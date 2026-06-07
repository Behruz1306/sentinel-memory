"""Live dashboard event bus — threads events from every Sentinel module to the UI.

Any core component (predictive pre-fetch, threat memory, trust engine, pipeline,
LiveKit agent, red team) calls `emit()` or `patch()`. The FastAPI server
registers a broadcast hook on startup and pushes snapshots to every WebSocket.
External workers (livekit_agent) can POST to /api/stream/push on the dashboard
server when they run out-of-process.
"""

from __future__ import annotations

import os
import threading
import time
import uuid
from copy import deepcopy
from typing import Any, Callable, Optional

_MAX_HISTORY = 60
_MAX_PREFETCH = 20
_MAX_THREAT_LOGS = 50
_MAX_ALERTS = 12

_lock = threading.Lock()
_broadcast_hook: Optional[Callable[[dict], None]] = None


def _now() -> float:
    return round(time.time(), 3)


def _empty_state() -> dict:
    return {
        "session_id": "",
        "transcript": "",
        "interim": "",
        "trust_score": 100,
        "trust_history": [],
        "voice_anomaly": 0.0,
        "deepfake_pct": 0,
        "cache_status": "cold",
        "prefetch_events": [],
        "prefetch_entity": "",
        "prefetch_latency_ms": None,
        "response_latency_ms": None,
        "threat_logs": [],
        "threat_match": "",
        "database_size": 0,
        "active_alerts": [],
        "immune_learned": None,
        "engines": [],
        "consensus": {},
        "verdict": "ALLOW",
        "se_risk": 0,
        "uncertainty": 0,
        "anticipatory_forecast": None,
        "transcript_lines": [],
        "last_event": None,
        "updated_at": _now(),
    }


_state = _empty_state()


def register_broadcast(hook: Callable[[dict], None]) -> None:
    global _broadcast_hook
    _broadcast_hook = hook


def snapshot() -> dict:
    with _lock:
        return deepcopy(_state)


def reset(**kwargs) -> None:
    with _lock:
        global _state
        _state = _empty_state()
        _state.update(kwargs)
        _state["updated_at"] = _now()
    _notify()


def patch(**fields) -> None:
    with _lock:
        _state.update(fields)
        _state["updated_at"] = _now()
    _notify()


def _notify() -> None:
    snap = snapshot()
    if _broadcast_hook:
        try:
            _broadcast_hook(snap)
        except Exception:
            pass
    _push_remote(snap)


def _push_remote(snap: dict) -> None:
    url = os.getenv("SENTINEL_DASHBOARD_URL", "http://127.0.0.1:8000/api/stream/push")
    if not url:
        return
    # Avoid echo loop when the server handles the event in-process.
    if os.getenv("SENTINEL_DASHBOARD_SERVER") == "1":
        return
    try:
        import json
        import urllib.request
        req = urllib.request.Request(
            url, data=json.dumps(snap).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=0.35)
    except Exception:
        pass


def _trust_point(score: int) -> None:
    hist = _state.setdefault("trust_history", [])
    hist.append({"t": _now(), "score": int(score)})
    if len(hist) > _MAX_HISTORY:
        del hist[: len(hist) - _MAX_HISTORY]


def emit(event: str, **data) -> None:
    """High-level event helper — updates state and notifies subscribers."""
    with _lock:
        _state["last_event"] = event
        _state["updated_at"] = _now()

        if event == "session_open":
            _state["session_id"] = data.get("session_id", "")
            _state["voice_anomaly"] = float(data.get("voice_anomaly", 0))
            _state["deepfake_pct"] = round(_state["voice_anomaly"] * 100, 1)
            _state["trust_score"] = int(data.get("trust_score", 100))
            _trust_point(_state["trust_score"])

        elif event == "interim_transcript":
            _state["interim"] = data.get("text", "")
            if data.get("session_id"):
                _state["session_id"] = data["session_id"]
            if "voice_anomaly" in data:
                _state["voice_anomaly"] = float(data["voice_anomaly"])
                _state["deepfake_pct"] = round(_state["voice_anomaly"] * 100, 1)
            if "trust_score" in data:
                _state["trust_score"] = int(data["trust_score"])
                _trust_point(_state["trust_score"])

        elif event == "final_transcript":
            _state["transcript"] = data.get("text", "")
            _state["interim"] = ""
            if "trust_score" in data:
                _state["trust_score"] = int(data["trust_score"])
                _trust_point(_state["trust_score"])

        elif event == "trust_update":
            _state["trust_score"] = int(data.get("score", _state["trust_score"]))
            _trust_point(_state["trust_score"])
            if "voice_anomaly" in data:
                _state["voice_anomaly"] = float(data["voice_anomaly"])
                _state["deepfake_pct"] = round(_state["voice_anomaly"] * 100, 1)
            if data.get("engines"):
                _state["engines"] = data["engines"]
            if data.get("consensus"):
                _state["consensus"] = data["consensus"]

        elif event == "prefetch_triggered":
            entity = data.get("entity", "")
            _state["cache_status"] = "warming"
            _state["prefetch_entity"] = entity
            row = {"event": "prefetch_triggered", "entity": entity,
                   "label": data.get("label", entity), "ts": _now()}
            evs = _state.setdefault("prefetch_events", [])
            evs.insert(0, row)
            del evs[_MAX_PREFETCH:]

        elif event == "cache_warmed":
            ms = data.get("latency_ms")
            entity = data.get("entity", _state.get("prefetch_entity", ""))
            _state["cache_status"] = "warmed"
            _state["prefetch_latency_ms"] = ms
            row = {"event": "cache_warmed", "entity": entity,
                   "latency_ms": ms, "ts": _now()}
            evs = _state.setdefault("prefetch_events", [])
            evs.insert(0, row)
            del evs[_MAX_PREFETCH:]

        elif event == "cache_hit":
            _state["cache_status"] = "warmed"
            _state["response_latency_ms"] = data.get("latency_ms", 0)
            row = {"event": "cache_hit", "entity": data.get("entity", ""),
                   "latency_ms": data.get("latency_ms"), "ts": _now()}
            evs = _state.setdefault("prefetch_events", [])
            evs.insert(0, row)
            del evs[_MAX_PREFETCH:]

        elif event == "cache_cold":
            _state["cache_status"] = "cold"
            _state["response_latency_ms"] = data.get("latency_ms")

        elif event == "threat_detected":
            row = {
                "id": data.get("id", uuid.uuid4().hex[:8]),
                "text": (data.get("text", ""))[:120],
                "signature": data.get("signature_id", ""),
                "signature_label": data.get("signature_label", ""),
                "similarity_pct": data.get("similarity_pct", 0),
                "attack_type": data.get("attack_type", "none"),
                "risk": data.get("risk", 0),
                "verdict": data.get("verdict", "ALLOW"),
                "backend": data.get("backend", "local"),
                "ts": _now(),
            }
            logs = _state.setdefault("threat_logs", [])
            logs.insert(0, row)
            del logs[_MAX_THREAT_LOGS:]
            if row["signature"]:
                sim = row["similarity_pct"]
                _state["threat_match"] = (
                    f"{row['signature_label'] or row['signature']} ({sim}% similarity)"
                )

        elif event == "immune_learned":
            size = int(data.get("database_size", _state.get("database_size", 0)))
            _state["database_size"] = size
            _state["immune_learned"] = {
                "signature_id": data.get("signature_id", ""),
                "text": (data.get("text", ""))[:80],
                "from_size": data.get("from_size", size - 1),
                "to_size": size,
                "ts": _now(),
            }

        elif event == "alert":
            msg = data.get("message", "")
            if msg:
                alerts = _state.setdefault("active_alerts", [])
                alerts.insert(0, {"message": msg, "level": data.get("level", "warn"), "ts": _now()})
                del alerts[_MAX_ALERTS:]

        elif event == "verdict":
            if data.get("decision"):
                _state["verdict"] = str(data["decision"]).upper()
            if data.get("decision") == "BLOCK":
                msg = data.get("alert") or "🚨 RED ALERT: Access Denied"
                alerts = _state.setdefault("active_alerts", [])
                alerts.insert(0, {"message": msg, "level": "critical", "ts": _now()})
                del alerts[_MAX_ALERTS:]
            if data.get("trust_score") is not None:
                _state["trust_score"] = int(data["trust_score"])
                _trust_point(_state["trust_score"])
            if data.get("response_latency_ms") is not None:
                _state["response_latency_ms"] = data["response_latency_ms"]
            if data.get("se_risk") is not None:
                _state["se_risk"] = int(data["se_risk"])
                _state["uncertainty"] = int(data.get("uncertainty", data["se_risk"]))

        elif event == "anticipatory_forecast":
            _state["anticipatory_forecast"] = {
                "phrase": data.get("phrase", "Keep this confidential"),
                "confidence": int(data.get("confidence", 91)),
                "status": "predicted",
                "trigger": data.get("trigger", ""),
                "ts": _now(),
            }

        elif event == "forecast_confirmed":
            fc = _state.get("anticipatory_forecast") or {}
            fc.update(
                phrase=data.get("phrase", fc.get("phrase", "Keep this confidential")),
                confidence=int(data.get("confidence", fc.get("confidence", 91))),
                status="confirmed",
                ts=_now(),
            )
            _state["anticipatory_forecast"] = fc

        elif event == "pipeline_complete":
            for key in ("verdict", "trust_score", "se_risk", "uncertainty",
                        "threat_match", "response_latency_ms", "cache_status",
                        "transcript", "interim", "session_id"):
                if data.get(key) is not None:
                    _state[key] = data[key]
            if data.get("trust_score") is not None:
                _trust_point(int(data["trust_score"]))
            line = (data.get("transcript") or data.get("query") or "").strip()
            if line:
                lines = _state.setdefault("transcript_lines", [])
                if not lines or lines[0].get("text") != line:
                    lines.insert(0, {"text": line, "ts": _now(),
                                     "verdict": data.get("verdict", "")})
                    del lines[30:]

        # merge any extra scalar fields
        for k, v in data.items():
            if k in ("engines", "consensus", "anticipatory_forecast") and v:
                _state[k] = v

    _notify()


def _fallback_log(metrics: dict, err: str) -> None:
    """Local log when the dashboard server is unreachable (offline CLI demos)."""
    try:
        import json
        row = {"ts": _now(), "metrics": metrics, "error": err}
        with open("dashboard_events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")
    except Exception:
        pass


def push_dashboard_update(metrics: dict) -> bool:
    """Pipe live pipeline variables to the dashboard (in-process or HTTP POST).

    When the FastAPI server is running in-process, state patches broadcast over
    WebSocket immediately. Otherwise POSTs to /api/dashboard-update and falls back
    to dashboard_events.jsonl if the server is down.
    """
    emit("pipeline_complete", **metrics)
    if metrics.get("decision") or metrics.get("verdict"):
        emit("verdict",
             decision=metrics.get("verdict") or metrics.get("decision"),
             trust_score=metrics.get("trust_score"),
             response_latency_ms=metrics.get("response_latency_ms"),
             se_risk=metrics.get("se_risk"),
             uncertainty=metrics.get("uncertainty"),
             alert=metrics.get("alert"))
    if os.getenv("SENTINEL_DASHBOARD_SERVER") == "1":
        return True
    url = os.getenv(
        "SENTINEL_DASHBOARD_URL",
        "http://127.0.0.1:8000/api/dashboard-update",
    )
    try:
        import json
        import urllib.request
        req = urllib.request.Request(
            url, data=json.dumps(metrics).encode(),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=0.5)
        return True
    except Exception as exc:
        _fallback_log(metrics, str(exc))
        return False


def init_database_size(n: int) -> None:
    patch(database_size=n)
