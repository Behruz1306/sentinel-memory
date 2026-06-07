#!/usr/bin/env python3
"""Sentinel API + live dashboard.

    uvicorn server:app --port 8000
    open http://localhost:8000
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.core import llm
from src.core.cloudwatch import security_log
from src.core.graph_kb import KnowledgeGraph
from src.core.retrieval import SentinelRetriever
from src.core.session import SessionState
from src.middleware.stream_simulator import CALLS, get_call, play
from src.middleware.pipeline import SentinelPipeline
from src.red_team.simulator import run_campaign

app = FastAPI(title="Sentinel Memory", version="0.2.0")

_kb = KnowledgeGraph()
_retriever = SentinelRetriever(_kb)
_pipeline = SentinelPipeline(_kb)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


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
    }


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
