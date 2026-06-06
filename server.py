#!/usr/bin/env python3
"""Sentinel API + live dashboard.

    uvicorn server:app --reload --port 8000
    open http://localhost:8000

Endpoints:
    GET  /                 -> the live Co-Pilot dashboard
    POST /api/evaluate     -> run one retrieval request through the firewall
    POST /api/redteam      -> run the full attack campaign
    GET  /api/scenarios    -> preset live-demo scenarios
"""

from __future__ import annotations

import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from sentinel.firewall import RetrievalFirewall, RetrievalRequest
from sentinel.llm import llm_available
from sentinel.redteam import ATTACKS, run_campaign

app = FastAPI(title="Sentinel", version="0.1.0")
fw = RetrievalFirewall()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class EvalBody(BaseModel):
    query: str
    claimed_identity: str = "unknown"
    verification: str = "claimed_only"
    transcript: str = ""
    intent: str = "read"


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"))


@app.get("/api/health")
def health():
    return {"ok": True, "llm": llm_available()}


@app.post("/api/evaluate")
def evaluate(body: EvalBody):
    decision = fw.evaluate(RetrievalRequest(**body.model_dump()))
    return decision.to_dict()


@app.post("/api/redteam")
def redteam():
    return run_campaign(fw)


@app.get("/api/scenarios")
def scenarios():
    return {
        "scenarios": [
            {
                "id": a.id,
                "name": a.name,
                "category": a.category,
                "query": a.request.query,
                "claimed_identity": a.request.claimed_identity,
                "verification": a.request.verification,
                "transcript": a.request.transcript,
                "intent": a.request.intent,
            }
            for a in ATTACKS
        ]
    }


if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
