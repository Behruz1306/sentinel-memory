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

from fastapi import FastAPI, File, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.core import llm
from src.core import persistence as db
from src.core.cloudwatch import security_log
from src.core.company_pack import get_pack, list_packs, resolve_company
from src.core.reports import report_pdf_bytes
from src.core.dashboard_bus import emit, init_database_size, patch, register_broadcast, snapshot
from src.core.graph_kb import KnowledgeGraph
from src.core.retrieval import SentinelRetriever
from src.core.session import SessionState
from src.core.threat_memory import threat_memory
from src.core.workspace import Workspace, ingest_pdf, upload_company
from src.middleware import twilio_voice
from src.middleware.stream_simulator import CALLS, get_call, play
from src.middleware.pipeline import SentinelPipeline
from src.red_team.simulator import run_campaign

app = FastAPI(title="Sentinel Memory", version="0.2.0")

_kb = KnowledgeGraph()
_retriever = SentinelRetriever(_kb)
_pipeline = SentinelPipeline(_kb)
_workspace = Workspace(_retriever)

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
    return FileResponse(os.path.join(STATIC_DIR, "workspace.html"))


@app.get("/legacy")
def legacy_dashboard():
    """Original live command-center (advanced telemetry)."""
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"))


@app.get("/favicon.ico")
def favicon():
    """Avoid noisy 404s in the browser console."""
    from fastapi.responses import Response
    return Response(status_code=204)


def _cloud_deploy() -> bool:
    """Render and similar PaaS set RENDER=true; small instances can't run 8× dual-LLM."""
    return os.getenv("RENDER") == "true" or os.getenv("SENTINEL_CLOUD_DEPLOY") == "1"


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "llm": llm.llm_info(),
        "retrieval": _retriever.backend,
        "breach_sink": security_log.sink,
        "kb": _kb.stats(),
        "threat_memory": threat_memory.stats(),
        "persistence": db.stats(),
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
    verdict: Optional[str] = None
    se_risk: Optional[int] = None
    uncertainty: Optional[int] = None
    anticipatory_forecast: Optional[Any] = None
    transcript_lines: Optional[list] = None
    last_event: Optional[str] = None
    updated_at: Optional[float] = None


class DashboardUpdateBody(BaseModel):
    """Live metrics from the runtime pipeline (retrieval, demo_call, red team)."""
    session_id: Optional[str] = None
    transcript: Optional[str] = None
    interim: Optional[str] = None
    query: Optional[str] = None
    trust_score: Optional[int] = None
    se_risk: Optional[int] = None
    uncertainty: Optional[int] = None
    verdict: Optional[str] = None
    decision: Optional[str] = None
    threat_match: Optional[str] = None
    response_latency_ms: Optional[float] = None
    cache_status: Optional[str] = None
    prefetch_entity: Optional[str] = None
    voice_anomaly: Optional[float] = None
    alert: Optional[str] = None


def _apply_dashboard_metrics(data: dict) -> dict:
    clean = {k: v for k, v in data.items() if v is not None}
    if clean.get("decision") and not clean.get("verdict"):
        clean["verdict"] = clean["decision"]
    emit("pipeline_complete", **clean)
    if clean.get("verdict") or clean.get("decision"):
        emit("verdict",
             decision=clean.get("verdict") or clean.get("decision"),
             trust_score=clean.get("trust_score"),
             response_latency_ms=clean.get("response_latency_ms"),
             se_risk=clean.get("se_risk"),
             uncertainty=clean.get("uncertainty"),
             alert=clean.get("alert"))
    patch(**{k: v for k, v in clean.items()
             if k in snapshot() or k in ("verdict", "se_risk", "uncertainty",
                                         "threat_match", "anticipatory_forecast")})
    return clean


@app.post("/api/stream/push")
async def stream_push(body: StreamPushBody):
    patch(**body.model_dump(exclude_none=True))
    return {"ok": True}


@app.post("/api/dashboard-update")
async def dashboard_update(body: DashboardUpdateBody):
    """Capture live pipeline metrics and broadcast to all dashboard clients."""
    applied = _apply_dashboard_metrics(body.model_dump(exclude_none=True))
    return {"ok": True, "applied": list(applied.keys())}


@app.websocket("/api/ws/stream")
async def ws_stream(websocket: WebSocket):
    await _ws_dashboard_handler(websocket)


@app.websocket("/api/ws/dashboard")
async def ws_dashboard(websocket: WebSocket):
    """Primary live dashboard WebSocket (alias of /api/ws/stream)."""
    await _ws_dashboard_handler(websocket)


async def _ws_dashboard_handler(websocket: WebSocket):
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
    # Cloud: sequential + heuristic/Moss only — avoids 502/OOM from 8 parallel LLM calls.
    cloud = _cloud_deploy()
    camp = run_campaign(use_llm=not cloud, max_workers=1 if cloud else 8)
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


# --- Sentinel Workspace (persistent multi-turn evaluation) -----------------

class WorkspaceSessionBody(BaseModel):
    company_id: str = "acme-logistics"
    channel: str = "chat"
    caller_name: str = ""
    claimed_identity: str = "guest"
    verification: str = "claimed_only"
    origin: str = "unknown"
    voice_anomaly: float = 0.0
    verified_user_id: Optional[str] = None


class WorkspaceMessageBody(BaseModel):
    message: str
    persona: Optional[dict] = None


class CompanyUploadBody(BaseModel):
    name: str
    payload: dict


@app.get("/api/workspace/company")
def workspace_company(pack_id: str = "acme-logistics"):
    active = resolve_company(pack_id)
    if not active and get_pack(pack_id):
        active = get_pack(pack_id).to_dict()
    return {
        "packs": list_packs(),
        "uploads": db.list_company_uploads(),
        "active": active or {},
        "pack_id": pack_id,
    }


@app.post("/api/workspace/company/upload")
def workspace_company_upload(body: CompanyUploadBody):
    return upload_company(body.name, body.payload)


@app.post("/api/workspace/sessions")
def workspace_create_session(body: WorkspaceSessionBody):
    return _workspace.create_session(**body.model_dump())


@app.get("/api/workspace/sessions")
def workspace_list_sessions(limit: int = 30):
    return {"sessions": db.list_sessions(limit)}


@app.get("/api/workspace/sessions/{session_id}")
def workspace_get_session(session_id: str):
    rec = db.get_session(session_id)
    if not rec:
        return {"error": "not found"}
    return rec


@app.post("/api/workspace/sessions/{session_id}/message")
def workspace_message(session_id: str, body: WorkspaceMessageBody):
    return _workspace.send_message(session_id, body.message, persona=body.persona)


@app.get("/api/workspace/sessions/{session_id}/report")
def workspace_report(session_id: str):
    return _workspace.report(session_id)


@app.get("/api/workspace/sessions/{session_id}/report.pdf")
def workspace_report_pdf(session_id: str):
    report = _workspace.report(session_id)
    if report.get("error"):
        return report
    try:
        pdf = report_pdf_bytes(report)
    except Exception as e:
        return {"error": str(e)}
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sentinel-{session_id}.pdf"'},
    )


@app.post("/api/workspace/company/{company_id}/ingest-pdf")
async def workspace_ingest_pdf(
    company_id: str,
    file: UploadFile = File(...),
    title: str = "Ingested PDF",
    sensitivity: str = "CONFIDENTIAL",
):
    import tempfile
    data = await file.read()
    suffix = ".pdf" if (file.filename or "").lower().endswith(".pdf") else ""
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return ingest_pdf(
            company_id, path,
            title=title or file.filename or "PDF",
            sensitivity=sensitivity,
        )
    except Exception as e:
        return {"error": str(e)}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


@app.get("/api/workspace/activity")
def workspace_activity(limit: int = 40):
    return {"items": db.activity_feed(limit)}


# --- Twilio voice (real phone calls) ---------------------------------------

@app.get("/api/twilio/status")
def twilio_status():
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    num = os.getenv("TWILIO_PHONE_NUMBER")
    base = (os.getenv("SENTINEL_PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL")
            or "http://localhost:8000").rstrip("/")
    return {
        "configured": bool(sid and os.getenv("TWILIO_AUTH_TOKEN")),
        "phone_number": num,
        "voice_url": f"{base}/api/twilio/voice",
        "gather_url": f"{base}/api/twilio/gather",
    }


@app.post("/api/twilio/voice")
async def twilio_voice_incoming(request: Request):
    form = await request.form()
    call_sid = form.get("CallSid", "")
    sess = _workspace.create_session(channel="phone", caller_name="Phone caller")
    sid = sess["session_id"]
    if call_sid:
        twilio_voice.bind_call(str(call_sid), sid)
    xml = twilio_voice.twiml_gather(sid)
    return Response(content=xml, media_type="application/xml")


@app.post("/api/twilio/gather")
async def twilio_gather(request: Request, session_id: str = ""):
    form = await request.form()
    speech = (form.get("SpeechResult") or "").strip()
    call_sid = str(form.get("CallSid", ""))
    sid = session_id or twilio_voice.session_for_call(call_sid) or ""
    if not sid:
        return Response(
            content='<?xml version="1.0"?><Response><Say>Session error. Goodbye.</Say></Response>',
            media_type="application/xml",
        )
    if not speech:
        xml = twilio_voice.twiml_gather(sid, "I didn't catch that. Please repeat your request.")
        return Response(content=xml, media_type="application/xml")
    result = _workspace.send_message(sid, speech)
    xml = twilio_voice.twiml_reply(sid, result.get("reply", ""), result.get("verdict", "ALLOW"))
    return Response(content=xml, media_type="application/xml")


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
