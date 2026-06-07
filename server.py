#!/usr/bin/env python3
"""Sentinel API + live dashboard.

    uvicorn server:app --port 8000
    open http://localhost:8000
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.core import llm
from src.core.cloudwatch import security_log
from src.core.dashboard_bus import init_database_size, patch, register_broadcast, snapshot
from src.core.graph_kb import KnowledgeGraph
from src.core.retrieval import SentinelRetriever
from src.core.session import SessionState
from src.core.threat_memory import threat_memory
from src.middleware.stream_simulator import CALLS, get_call, play
from src.middleware.pipeline import SentinelPipeline
from src.red_team.simulator import run_campaign

app = FastAPI(title="Sentinel Memory", version="0.2.0")

_kb = KnowledgeGraph()
_retriever = SentinelRetriever(_kb)
_pipeline = SentinelPipeline(_kb)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
_ws_clients: set[WebSocket] = set()


async def _broadcast_state(snap: dict) -> None:
    dead = []
    for ws in list(_ws_clients):
        try:
            await ws.send_json(snap)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.discard(ws)


@app.on_event("startup")
async def _dashboard_startup():
    os.environ["SENTINEL_DASHBOARD_SERVER"] = "1"
    init_database_size(threat_memory.stats().get("signatures", 0))
    loop = asyncio.get_event_loop()
    register_broadcast(lambda snap: asyncio.run_coroutine_threadsafe(_broadcast_state(snap), loop))


class EvalBody(BaseModel):
    query: str
    claimed_identity: str = "guest"
    verification: str = "claimed_only"
    origin: str = "unknown"
    origin_ip: str = "0.0.0.0"
    voice_anomaly: float = 0.0
    transcript: str = ""
    intent: str = "read"
    verified_user_id: Optional[str] = None


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"))


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "llm": llm.llm_info(),
        "retrieval": _retriever.backend,
        "breach_sink": security_log.sink,
        "kb": _kb.stats(),
        "threat_memory": threat_memory.stats(),
        "stream": snapshot(),
    }


@app.get("/api/stream/state")
def stream_state():
    return snapshot()


@app.get("/api/security/status")
def security_status():
    """Live security posture for the command-center dashboard."""
    snap = snapshot()
    tm = threat_memory.stats()
    return {
        **snap,
        "threat_memory": tm,
        "retrieval_backend": _retriever.backend,
    }


class StreamPushBody(BaseModel):
    """Partial or full dashboard snapshot (from external workers via HTTP)."""
    session_id: Optional[str] = None
    transcript: Optional[str] = None
    interim: Optional[str] = None
    trust_score: Optional[int] = None
    trust_history: Optional[list] = None
    voice_anomaly: Optional[float] = None
    deepfake_pct: Optional[float] = None
    cache_status: Optional[str] = None
    prefetch_events: Optional[list] = None
    prefetch_entity: Optional[str] = None
    prefetch_latency_ms: Optional[float] = None
    response_latency_ms: Optional[float] = None
    threat_logs: Optional[list] = None
    threat_match: Optional[str] = None
    database_size: Optional[int] = None
    active_alerts: Optional[list] = None
    immune_learned: Optional[Any] = None
    engines: Optional[list] = None
    consensus: Optional[dict] = None
    last_event: Optional[str] = None
    updated_at: Optional[float] = None


@app.post("/api/stream/push")
async def stream_push(body: StreamPushBody):
    patch(**body.model_dump(exclude_none=True))
    return {"ok": True}


@app.websocket("/api/ws/stream")
async def ws_stream(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        await websocket.send_json(snapshot())
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _ws_clients.discard(websocket)


@app.post("/api/evaluate")
def evaluate(body: EvalBody):
    s = SessionState(
        session_id="api", caller_id="api-caller",
        claimed_identity=body.claimed_identity, verification=body.verification,
        origin=body.origin, origin_ip=body.origin_ip,
        voice_anomaly=body.voice_anomaly, verified_user_id=body.verified_user_id,
    )
    if body.transcript:
        s.commit_final(body.transcript)
    result = _retriever.execute(s, body.query, intent=body.intent, raise_on_deny=False)
    return result.to_dict()


@app.post("/api/compare")
def compare(body: EvalBody):
    """Naive similarity-only RAG vs Sentinel — the core thesis, side by side.

    `naive` is what a vanilla RAG agent would feed its LLM: the top semantic
    hits in full, sensitivity ignored. `sentinel` is the trust-gated result.
    """
    s = SessionState(
        session_id="cmp", caller_id="api",
        claimed_identity=body.claimed_identity, verification=body.verification,
        origin=body.origin, origin_ip=body.origin_ip,
        voice_anomaly=body.voice_anomaly, verified_user_id=body.verified_user_id,
    )
    if body.transcript:
        s.commit_final(body.transcript)
    sentinel = _retriever.execute(s, body.query, intent=body.intent, raise_on_deny=False)
    naive_hits = _retriever._retrieve(body.query, 4) or []
    naive = [
        {"title": doc.title, "sensitivity": doc.sensitivity,
         "leaked": doc.sensitivity in ("CONFIDENTIAL", "RESTRICTED", "FINANCIAL"),
         "served": doc.content}
        for doc, _ in naive_hits
    ]
    return {"naive": naive, "sentinel": sentinel.to_dict()}


@app.post("/api/simulate/{call_id}")
def simulate(call_id: str):
    """Run a scripted call through the pipeline; return the play-by-play."""
    call = get_call(call_id)
    if not call:
        return {"error": f"unknown call '{call_id}'"}
    events = []
    play(call, SentinelPipeline(_kb), on_event=lambda k, p: events.append(_ev(k, p)))
    return {"call": call.id, "title": call.title, "events": events}


def _ev(kind, payload):
    if kind == "interim":
        return {"kind": "interim", "heard": payload["heard"],
                "prefetched": payload["prefetched"]}
    turn = payload["turn"]
    return {"kind": "final", "decision": turn.decision, "denied": turn.denied,
            "result": turn.result}


@app.post("/api/redteam")
def redteam():
    camp = run_campaign()
    return {
        "total": camp["total"], "defended": camp["defended"],
        "breached": camp["breached"], "defense_rate": camp["defense_rate"],
        "results": [
            {
                "id": r.attack.id, "name": r.attack.name,
                "attack_type": r.attack.attack_type,
                "target_sensitivity": r.attack.target_sensitivity,
                "status": r.status, "trust_score": r.trust_score,
                "se_risk": r.se_risk, "priority": r.priority, "detail": r.detail,
            }
            for r in camp["results"]
        ],
    }


class ThreatBody(BaseModel):
    text: str


class LearnBody(BaseModel):
    text: str
    attack_type: str = "social engineering"
    tactic: str = "learned"
    severity: int = 80


@app.get("/api/threat/memory")
def threat_memory_stats():
    """The immune system's current state — how many attacks Moss remembers."""
    return {
        **threat_memory.stats(),
        "signatures": [
            {"id": s.id, "attack_type": s.attack_type, "tactic": s.tactic,
             "severity": s.severity, "text": s.text}
            for s in threat_memory.signatures()
        ],
    }


@app.post("/api/threat/detect")
def threat_detect(body: ThreatBody):
    """Semantically match arbitrary text against the Moss attack memory."""
    return threat_memory.detect(body.text).to_dict()


@app.post("/api/threat/learn")
def threat_learn(body: LearnBody):
    """Teach the firewall a new attack at runtime (writes back into Moss)."""
    return threat_memory.learn(
        body.text, attack_type=body.attack_type, tactic=body.tactic,
        severity=body.severity,
    )


# Persona presets stamp the trust metadata the agent reads from dispatch.
VOICE_PERSONAS = {
    "deepfake_ceo": {"label": "Deepfake “CEO” (spoofed)", "claimed_identity": "ceo",
                     "verification": "claimed_only", "origin": "spoofed", "voice_anomaly": 0.85},
    "verified_ceo": {"label": "Verified CEO (SSO)", "claimed_identity": "ceo",
                     "verification": "cryptographic", "origin": "corporate_sso",
                     "voice_anomaly": 0.03, "verified_user_id": "user:mark"},
    "guest": {"label": "Unknown caller", "claimed_identity": "guest",
              "verification": "claimed_only", "origin": "unknown", "voice_anomaly": 0.0},
}


class TokenBody(BaseModel):
    persona: str = "guest"


@app.get("/api/voice/personas")
def voice_personas():
    return {"personas": [{"id": k, **v} for k, v in VOICE_PERSONAS.items()],
            "configured": bool(os.getenv("LIVEKIT_URL"))}


@app.post("/api/voice/token")
def voice_token(body: TokenBody):
    url, key, secret = (os.getenv("LIVEKIT_URL"), os.getenv("LIVEKIT_API_KEY"),
                        os.getenv("LIVEKIT_API_SECRET"))
    if not all([url, key, secret]):
        return {"error": "LiveKit not configured (set LIVEKIT_* in .env)"}
    persona = VOICE_PERSONAS.get(body.persona, VOICE_PERSONAS["guest"])
    meta = {k: persona[k] for k in
            ("claimed_identity", "verification", "origin", "voice_anomaly", "verified_user_id")
            if k in persona}
    room = f"sentinel-{body.persona}-{uuid.uuid4().hex[:8]}"
    from livekit import api as lk
    token = (
        lk.AccessToken(key, secret)
        .with_identity(f"caller-{uuid.uuid4().hex[:6]}")
        .with_name(persona["label"])
        .with_grants(lk.VideoGrants(room_join=True, room=room))
        .with_room_config(lk.RoomConfiguration(
            agents=[lk.RoomAgentDispatch(agent_name="sentinel", metadata=json.dumps(meta))]))
        .to_jwt()
    )
    return {"token": token, "url": url, "room": room, "persona": persona}


@app.get("/api/scenarios")
def scenarios():
    return {"scenarios": [
        {"id": c.id, "name": c.title, "claimed_identity": c.claimed_identity,
         "verification": c.verification, "origin": c.origin,
         "voice_anomaly": c.voice_anomaly, "transcript": c.final,
         "query": c.final, "intent": c.intent, "notes": c.notes}
        for c in CALLS
    ]}


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
