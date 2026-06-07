"""Persistence facade — Supabase (production) or SQLite (local/tests).

Set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY on Render for durable cloud storage.
Without them, falls back to SQLite under data/sentinel.db.
"""

from __future__ import annotations

import os


def _pick():
    if os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"):
        from . import supabase_store as store
        return store
    from . import sqlite_store as store
    return store


def _store():
    return _pick()


def backend_name() -> str:
    return _store().backend_name()


# Re-export all store operations through the active backend.
def ensure_user(**kw):
    return _store().ensure_user(**kw)


def create_user(**kw):
    return _store().create_user(**kw)


def get_user(user_id: str):
    return _store().get_user(user_id)


def get_user_by_email(email: str):
    return _store().get_user_by_email(email)


def save_token(token: str, user_id: str, expires_at: float):
    return _store().save_token(token, user_id, expires_at)


def get_token(token: str):
    return _store().get_token(token)


def set_user_onboarded(user_id: str):
    return _store().set_user_onboarded(user_id)


def create_session(**kw):
    return _store().create_session(**kw)


def add_turn(session_id: str, *, role: str, content: str, verdict: str = "",
             trust_score: int = 0, analysis=None):
    return _store().add_turn(session_id, role=role, content=content, verdict=verdict,
                             trust_score=trust_score, analysis=analysis)


def log_activity(kind: str, summary: str, *, session_id: str = "", detail=None):
    return _store().log_activity(kind, summary, session_id=session_id, detail=detail)


def list_sessions(limit: int = 30, user_id: str = ""):
    return _store().list_sessions(limit, user_id)


def user_dashboard(user_id: str):
    return _store().user_dashboard(user_id)


def get_session(session_id: str):
    return _store().get_session(session_id)


def activity_feed(limit: int = 40):
    return _store().activity_feed(limit)


def get_company_upload(upload_id: str):
    return _store().get_company_upload(upload_id)


def list_company_uploads(limit: int = 20):
    return _store().list_company_uploads(limit)


def save_company_upload(name: str, payload: dict):
    return _store().save_company_upload(name, payload)


def stats():
    return _store().stats()
