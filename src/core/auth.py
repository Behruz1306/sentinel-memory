"""Lightweight auth — demo accounts + token sessions for the Sentinel app."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
import uuid
from typing import Optional

from . import persistence as db

_SALT = os.getenv("SENTINEL_AUTH_SALT", "sentinel-memory-v1")
_TOKEN_TTL = 7 * 24 * 3600

DEMO_ACCOUNTS = [
    {
        "email": "analyst@sentinel.io",
        "password": "demo123",
        "name": "Alex Rivera",
        "role": "security_analyst",
        "org": "Acme Logistics",
        "title": "Security Analyst",
    },
    {
        "email": "judge@moss.io",
        "password": "moss2026",
        "name": "Hackathon Judge",
        "role": "evaluator",
        "org": "Moss / YC",
        "title": "Evaluator",
    },
    {
        "email": "ciso@acmelogistics.com",
        "password": "ciso2026",
        "name": "Sarah Chen",
        "role": "ciso",
        "org": "Acme Logistics",
        "title": "Chief Information Security Officer",
    },
]


def _hash_password(password: str) -> str:
    return hashlib.sha256(f"{_SALT}:{password}".encode()).hexdigest()


def ensure_demo_users() -> None:
    for acc in DEMO_ACCOUNTS:
        db.ensure_user(
            email=acc["email"],
            password_hash=_hash_password(acc["password"]),
            name=acc["name"],
            role=acc["role"],
            org=acc.get("org", ""),
            title=acc.get("title", ""),
        )


def register(email: str, password: str, name: str, *, org: str = "") -> dict:
    email = email.strip().lower()
    if not email or not password or len(password) < 6:
        return {"error": "Email and password (6+ chars) required"}
    if db.get_user_by_email(email):
        return {"error": "Email already registered"}
    uid = db.create_user(
        email=email,
        password_hash=_hash_password(password),
        name=name.strip() or email.split("@")[0],
        role="analyst",
        org=org,
        title="Analyst",
    )
    return _issue_token(uid)


def login(email: str, password: str) -> dict:
    email = email.strip().lower()
    user = db.get_user_by_email(email)
    if not user or user["password_hash"] != _hash_password(password):
        return {"error": "Invalid email or password"}
    return _issue_token(user["id"])


def _issue_token(user_id: str) -> dict:
    token = secrets.token_urlsafe(32)
    expires = time.time() + _TOKEN_TTL
    db.save_token(token, user_id, expires)
    user = db.get_user(user_id)
    return {"token": token, "expires_at": expires, "user": _public_user(user)}


def resolve_token(token: str) -> Optional[dict]:
    if not token:
        return None
    row = db.get_token(token)
    if not row or row["expires_at"] < time.time():
        return None
    user = db.get_user(row["user_id"])
    return _public_user(user) if user else None


def _public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "role": user["role"],
        "org": user.get("org", ""),
        "title": user.get("title", ""),
    }


def demo_accounts_public() -> list:
    """Credentials for login page — hackathon demo only."""
    return [
        {"email": a["email"], "password": a["password"], "name": a["name"],
         "title": a.get("title", ""), "org": a.get("org", "")}
        for a in DEMO_ACCOUNTS
    ]
