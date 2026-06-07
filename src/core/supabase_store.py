"""Supabase (PostgreSQL) persistence — survives Render redeploys."""

from __future__ import annotations

import json
import os
import time
import uuid
from typing import Optional

_client = None


def _sb():
    global _client
    if _client is None:
        from supabase import create_client
        _client = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_SERVICE_ROLE_KEY"],
        )
    return _client


def backend_name() -> str:
    return "supabase"


def ensure_user(*, email: str, password_hash: str, name: str, role: str = "analyst",
                  org: str = "", title: str = "") -> str:
    existing = get_user_by_email(email)
    if existing:
        return existing["id"]
    return create_user(email=email, password_hash=password_hash, name=name,
                       role=role, org=org, title=title)


def create_user(*, email: str, password_hash: str, name: str, role: str = "analyst",
                org: str = "", title: str = "") -> str:
    uid = f"usr-{uuid.uuid4().hex[:10]}"
    now = time.time()
    _sb().table("users").insert({
        "id": uid, "email": email.lower(), "password_hash": password_hash,
        "name": name, "role": role, "org": org, "title": title,
        "onboarded": False, "created_at": now,
    }).execute()
    return uid


def get_user(user_id: str) -> Optional[dict]:
    r = _sb().table("users").select("*").eq("id", user_id).limit(1).execute()
    return _row_user(r.data[0]) if r.data else None


def get_user_by_email(email: str) -> Optional[dict]:
    r = _sb().table("users").select("*").eq("email", email.lower()).limit(1).execute()
    return _row_user(r.data[0]) if r.data else None


def set_user_onboarded(user_id: str) -> None:
    _sb().table("users").update({"onboarded": True}).eq("id", user_id).execute()


def save_token(token: str, user_id: str, expires_at: float) -> None:
    _sb().table("auth_tokens").insert({
        "token": token, "user_id": user_id, "expires_at": expires_at,
    }).execute()


def get_token(token: str) -> Optional[dict]:
    r = _sb().table("auth_tokens").select("*").eq("token", token).limit(1).execute()
    if not r.data:
        return None
    row = r.data[0]
    return {"token": row["token"], "user_id": row["user_id"], "expires_at": row["expires_at"]}


def create_session(*, company_id: str = "acme-logistics", channel: str = "chat",
                   user_id: str = "", caller_name: str = "", claimed_identity: str = "guest",
                   verification: str = "claimed_only", origin: str = "unknown",
                   voice_anomaly: float = 0.0, meta: Optional[dict] = None) -> str:
    sid = f"sess-{uuid.uuid4().hex[:12]}"
    now = time.time()
    _sb().table("sessions").insert({
        "id": sid, "company_id": company_id, "channel": channel,
        "user_id": user_id or None, "caller_name": caller_name,
        "claimed_identity": claimed_identity, "verification": verification,
        "origin": origin, "voice_anomaly": voice_anomaly, "trust_score": 100,
        "created_at": now, "updated_at": now, "meta": meta or {},
    }).execute()
    log_activity("session_open", f"New {channel} session — {caller_name or claimed_identity}",
                   session_id=sid, detail={"company_id": company_id})
    return sid


def add_turn(session_id: str, *, role: str, content: str, verdict: str = "",
             trust_score: int = 0, analysis: Optional[dict] = None) -> str:
    tid = f"turn-{uuid.uuid4().hex[:10]}"
    now = time.time()
    _sb().table("turns").insert({
        "id": tid, "session_id": session_id, "role": role, "content": content,
        "verdict": verdict, "trust_score": trust_score,
        "analysis": analysis or {}, "created_at": now,
    }).execute()
    _sb().table("sessions").update({
        "trust_score": trust_score, "updated_at": now,
    }).eq("id", session_id).execute()
    return tid


def log_activity(kind: str, summary: str, *, session_id: str = "",
                   detail: Optional[dict] = None) -> None:
    _sb().table("activity").insert({
        "kind": kind, "summary": summary, "detail": detail or {},
        "session_id": session_id or None, "created_at": time.time(),
    }).execute()


def list_sessions(limit: int = 30, user_id: str = "") -> list:
    q = _sb().table("sessions").select("*").order("updated_at", desc=True).limit(limit)
    if user_id:
        q = q.eq("user_id", user_id)
    return [_row_session(r) for r in q.execute().data or []]


def user_dashboard(user_id: str) -> dict:
    sess = _sb().table("sessions").select("id", count="exact").eq("user_id", user_id).execute()
    sessions = sess.count or 0
    recent = _sb().table("sessions").select("*").eq("user_id", user_id).order(
        "updated_at", desc=True).limit(8).execute().data or []
    # Count blocks/allows via turns join — fetch user session ids
    sids = [r["id"] for r in recent]
    blocks, allows = 0, 0
    if sids:
        turns = _sb().table("turns").select("verdict,session_id").in_("session_id", sids).execute().data or []
        blocks = sum(1 for t in turns if t.get("verdict") == "BLOCK")
        allows = sum(1 for t in turns if t.get("verdict") == "ALLOW")
    all_sess = _sb().table("sessions").select("id").eq("user_id", user_id).execute().data or []
    if all_sess:
        all_ids = [s["id"] for s in all_sess]
        all_turns = _sb().table("turns").select("verdict").in_("session_id", all_ids).execute().data or []
        blocks = sum(1 for t in all_turns if t.get("verdict") == "BLOCK")
        allows = sum(1 for t in all_turns if t.get("verdict") == "ALLOW")
    return {
        "sessions": sessions, "blocks": blocks, "allows": allows,
        "recent": [_row_session(r) for r in recent],
    }


def get_session(session_id: str) -> Optional[dict]:
    r = _sb().table("sessions").select("*").eq("id", session_id).limit(1).execute()
    if not r.data:
        return None
    out = _row_session(r.data[0])
    turns = _sb().table("turns").select("*").eq("session_id", session_id).order(
        "created_at").execute().data or []
    out["turns"] = [_row_turn(t) for t in turns]
    return out


def activity_feed(limit: int = 40) -> list:
    rows = _sb().table("activity").select("*").order(
        "created_at", desc=True).limit(limit).execute().data or []
    return [{
        "kind": r["kind"], "summary": r["summary"],
        "detail": r.get("detail") or {},
        "session_id": r.get("session_id") or "",
        "created_at": r["created_at"],
    } for r in rows]


def get_company_upload(upload_id: str) -> Optional[dict]:
    r = _sb().table("company_uploads").select("*").eq("id", upload_id).limit(1).execute()
    if not r.data:
        return None
    row = r.data[0]
    return {
        "id": row["id"], "name": row["name"],
        "payload": row.get("payload") or {},
        "created_at": row["created_at"],
    }


def list_company_uploads(limit: int = 20) -> list:
    rows = _sb().table("company_uploads").select("id,name,created_at").order(
        "created_at", desc=True).limit(limit).execute().data or []
    return rows


def save_company_upload(name: str, payload: dict) -> str:
    uid = f"co-{uuid.uuid4().hex[:8]}"
    _sb().table("company_uploads").insert({
        "id": uid, "name": name, "payload": payload, "created_at": time.time(),
    }).execute()
    log_activity("company_upload", f"Custom company pack uploaded: {name}",
                 detail={"upload_id": uid})
    return uid


def stats() -> dict:
    def _count(table: str) -> int:
        r = _sb().table(table).select("id", count="exact").limit(1).execute()
        return r.count or 0
    return {
        "sessions": _count("sessions"),
        "turns": _count("turns"),
        "events": _count("activity"),
        "uploads": _count("company_uploads"),
        "backend": "supabase",
    }


def _row_user(r: dict) -> dict:
    return {
        "id": r["id"], "email": r["email"], "password_hash": r["password_hash"],
        "name": r["name"], "role": r["role"], "org": r.get("org") or "",
        "title": r.get("title") or "", "onboarded": bool(r.get("onboarded")),
        "created_at": r["created_at"],
    }


def _row_session(r: dict) -> dict:
    meta = r.get("meta")
    if isinstance(meta, str):
        meta = json.loads(meta or "{}")
    return {
        "id": r["id"], "company_id": r["company_id"], "channel": r["channel"],
        "user_id": r.get("user_id") or "", "caller_name": r.get("caller_name") or "",
        "claimed_identity": r.get("claimed_identity") or "",
        "verification": r.get("verification") or "",
        "origin": r.get("origin") or "", "voice_anomaly": r.get("voice_anomaly") or 0,
        "trust_score": r.get("trust_score") or 0,
        "created_at": r["created_at"], "updated_at": r["updated_at"],
        "meta": meta or {},
    }


def _row_turn(r: dict) -> dict:
    analysis = r.get("analysis")
    if isinstance(analysis, str):
        analysis = json.loads(analysis or "{}")
    return {
        "id": r["id"], "role": r["role"], "content": r["content"],
        "verdict": r.get("verdict") or "", "trust_score": r.get("trust_score") or 0,
        "analysis": analysis or {}, "created_at": r["created_at"],
    }
