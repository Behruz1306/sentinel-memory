"""SQLite persistence backend (local dev + tests).

Everything the jury does (chat, calls, uploads, blocks, learns) is recorded so
the product visibly *remembers* and improves over time.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Optional

_DEFAULT_DB = os.path.join(os.path.dirname(__file__), "..", "..", "data", "sentinel.db")
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None
_current_path: Optional[str] = None


def _db_path() -> str:
    return os.getenv("SENTINEL_DB_PATH", _DEFAULT_DB)


def reset_connection() -> None:
    """Close pooled connection (tests / DB path changes)."""
    global _conn, _current_path
    if _conn is not None:
        try:
            _conn.close()
        except Exception:
            pass
    _conn = None
    _current_path = None


def _connect() -> sqlite3.Connection:
    global _conn, _current_path
    path = _db_path()
    if _conn is not None and _current_path != path:
        reset_connection()
    if _conn is None:
        _current_path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _conn = sqlite3.connect(path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _init_schema(_conn)
    return _conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            org TEXT DEFAULT '',
            title TEXT DEFAULT '',
            onboarded INTEGER DEFAULT 0,
            created_at REAL
        );
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            expires_at REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL DEFAULT 'acme-logistics',
            channel TEXT NOT NULL DEFAULT 'chat',
            user_id TEXT,
            caller_name TEXT,
            claimed_identity TEXT,
            verification TEXT,
            origin TEXT,
            voice_anomaly REAL DEFAULT 0,
            trust_score INTEGER DEFAULT 100,
            created_at REAL,
            updated_at REAL,
            meta TEXT
        );
        CREATE TABLE IF NOT EXISTS turns (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            verdict TEXT,
            trust_score INTEGER,
            analysis TEXT,
            created_at REAL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            summary TEXT NOT NULL,
            detail TEXT,
            session_id TEXT,
            created_at REAL
        );
        CREATE TABLE IF NOT EXISTS company_uploads (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at REAL
        );
        CREATE INDEX IF NOT EXISTS idx_turns_session ON turns(session_id);
        CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    """)
    _migrate(conn)
    conn.commit()


def _migrate(conn: sqlite3.Connection) -> None:
    sess_cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)").fetchall()}
    if "user_id" not in sess_cols:
        conn.execute("ALTER TABLE sessions ADD COLUMN user_id TEXT")
    user_cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "onboarded" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN onboarded INTEGER DEFAULT 0")


def set_user_onboarded(user_id: str) -> None:
    with _lock:
        _connect().execute("UPDATE users SET onboarded=1 WHERE id=?", (user_id,))
        _connect().commit()


def backend_name() -> str:
    return "sqlite"


# --- Users & auth tokens -----------------------------------------------------

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
    with _lock:
        _connect().execute(
            "INSERT INTO users (id, email, password_hash, name, role, org, title, created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (uid, email.lower(), password_hash, name, role, org, title, now),
        )
        _connect().commit()
    return uid


def get_user(user_id: str) -> Optional[dict]:
    with _lock:
        row = _connect().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return _row_user(row) if row else None


def get_user_by_email(email: str) -> Optional[dict]:
    with _lock:
        row = _connect().execute(
            "SELECT * FROM users WHERE email=?", (email.lower(),)
        ).fetchone()
    return _row_user(row) if row else None


def save_token(token: str, user_id: str, expires_at: float) -> None:
    with _lock:
        _connect().execute(
            "INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (?,?,?)",
            (token, user_id, expires_at),
        )
        _connect().commit()


def get_token(token: str) -> Optional[dict]:
    with _lock:
        row = _connect().execute(
            "SELECT * FROM auth_tokens WHERE token=?", (token,)
        ).fetchone()
    if not row:
        return None
    return {"token": row["token"], "user_id": row["user_id"], "expires_at": row["expires_at"]}


def _row_user(r) -> dict:
    keys = r.keys() if hasattr(r, "keys") else r
    onboarded = r["onboarded"] if "onboarded" in keys else 0
    return {
        "id": r["id"], "email": r["email"], "password_hash": r["password_hash"],
        "name": r["name"], "role": r["role"], "org": r["org"], "title": r["title"],
        "onboarded": bool(onboarded), "created_at": r["created_at"],
    }


def create_session(*, company_id: str = "acme-logistics", channel: str = "chat",
                   user_id: str = "", caller_name: str = "", claimed_identity: str = "guest",
                   verification: str = "claimed_only", origin: str = "unknown",
                   voice_anomaly: float = 0.0, meta: Optional[dict] = None) -> str:
    sid = f"sess-{uuid.uuid4().hex[:12]}"
    now = time.time()
    with _lock:
        _connect().execute(
            "INSERT INTO sessions (id, company_id, channel, user_id, caller_name, "
            "claimed_identity, verification, origin, voice_anomaly, "
            "trust_score, created_at, updated_at, meta) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, company_id, channel, user_id or None, caller_name, claimed_identity,
             verification, origin, voice_anomaly, 100, now, now,
             json.dumps(meta or {})),
        )
        _connect().commit()
    log_activity("session_open", f"New {channel} session — {caller_name or claimed_identity}",
                   session_id=sid, detail={"company_id": company_id})
    return sid


def add_turn(session_id: str, *, role: str, content: str, verdict: str = "",
             trust_score: int = 0, analysis: Optional[dict] = None) -> str:
    tid = f"turn-{uuid.uuid4().hex[:10]}"
    now = time.time()
    with _lock:
        c = _connect()
        c.execute(
            "INSERT INTO turns (id, session_id, role, content, verdict, "
            "trust_score, analysis, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (tid, session_id, role, content, verdict, trust_score,
             json.dumps(analysis or {}), now),
        )
        c.execute(
            "UPDATE sessions SET trust_score=?, updated_at=? WHERE id=?",
            (trust_score, now, session_id),
        )
        c.commit()
    return tid


def log_activity(kind: str, summary: str, *, session_id: str = "",
                   detail: Optional[dict] = None) -> None:
    with _lock:
        _connect().execute(
            "INSERT INTO activity (kind, summary, detail, session_id, created_at) "
            "VALUES (?,?,?,?,?)",
            (kind, summary, json.dumps(detail or {}), session_id, time.time()),
        )
        _connect().commit()


def list_sessions(limit: int = 30, user_id: str = "", channel: str = "") -> list:
    with _lock:
        q = "SELECT * FROM sessions WHERE 1=1"
        params: list = []
        if user_id:
            q += " AND user_id=?"
            params.append(user_id)
        if channel:
            q += " AND channel=?"
            params.append(channel)
        q += " ORDER BY updated_at DESC LIMIT ?"
        params.append(limit)
        rows = _connect().execute(q, params).fetchall()
    return [_row_session(r) for r in rows]


def user_dashboard(user_id: str) -> dict:
    with _lock:
        c = _connect()
        sessions = c.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id=?", (user_id,)
        ).fetchone()[0]
        blocks = c.execute(
            "SELECT COUNT(*) FROM turns t JOIN sessions s ON t.session_id=s.id "
            "WHERE s.user_id=? AND t.verdict='BLOCK'", (user_id,)
        ).fetchone()[0]
        allows = c.execute(
            "SELECT COUNT(*) FROM turns t JOIN sessions s ON t.session_id=s.id "
            "WHERE s.user_id=? AND t.verdict='ALLOW'", (user_id,)
        ).fetchone()[0]
        recent = c.execute(
            "SELECT * FROM sessions WHERE user_id=? ORDER BY updated_at DESC LIMIT 8",
            (user_id,),
        ).fetchall()
    return {
        "sessions": sessions,
        "blocks": blocks,
        "allows": allows,
        "recent": [_row_session(r) for r in recent],
    }


def get_session(session_id: str) -> Optional[dict]:
    with _lock:
        c = _connect()
        row = c.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if not row:
            return None
        turns = c.execute(
            "SELECT * FROM turns WHERE session_id=? ORDER BY created_at ASC",
            (session_id,),
        ).fetchall()
    out = _row_session(row)
    out["turns"] = [_row_turn(t) for t in turns]
    return out


def activity_feed(limit: int = 40) -> list:
    with _lock:
        rows = _connect().execute(
            "SELECT * FROM activity ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [{
        "kind": r["kind"], "summary": r["summary"],
        "detail": json.loads(r["detail"] or "{}"),
        "session_id": r["session_id"],
        "created_at": r["created_at"],
    } for r in rows]


def get_company_upload(upload_id: str) -> Optional[dict]:
    with _lock:
        row = _connect().execute(
            "SELECT * FROM company_uploads WHERE id=?", (upload_id,)
        ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"], "name": row["name"],
        "payload": json.loads(row["payload"] or "{}"),
        "created_at": row["created_at"],
    }


def list_company_uploads(limit: int = 20) -> list:
    with _lock:
        rows = _connect().execute(
            "SELECT id, name, created_at FROM company_uploads ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"id": r["id"], "name": r["name"], "created_at": r["created_at"]} for r in rows]


def save_company_upload(name: str, payload: dict) -> str:
    uid = f"co-{uuid.uuid4().hex[:8]}"
    with _lock:
        _connect().execute(
            "INSERT INTO company_uploads (id, name, payload, created_at) VALUES (?,?,?,?)",
            (uid, name, json.dumps(payload), time.time()),
        )
        _connect().commit()
    log_activity("company_upload", f"Custom company pack uploaded: {name}",
                 detail={"upload_id": uid})
    return uid


def stats() -> dict:
    with _lock:
        c = _connect()
        sessions = c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        turns = c.execute("SELECT COUNT(*) FROM turns").fetchone()[0]
        events = c.execute("SELECT COUNT(*) FROM activity").fetchone()[0]
        uploads = c.execute("SELECT COUNT(*) FROM company_uploads").fetchone()[0]
    return {"sessions": sessions, "turns": turns, "events": events,
            "uploads": uploads, "backend": "sqlite"}


def _row_session(r) -> dict:
    return {
        "id": r["id"], "company_id": r["company_id"], "channel": r["channel"],
        "user_id": r["user_id"] if "user_id" in r.keys() else "",
        "caller_name": r["caller_name"], "claimed_identity": r["claimed_identity"],
        "verification": r["verification"], "origin": r["origin"],
        "voice_anomaly": r["voice_anomaly"], "trust_score": r["trust_score"],
        "created_at": r["created_at"], "updated_at": r["updated_at"],
        "meta": json.loads(r["meta"] or "{}"),
    }


def _row_turn(r) -> dict:
    return {
        "id": r["id"], "role": r["role"], "content": r["content"],
        "verdict": r["verdict"], "trust_score": r["trust_score"],
        "analysis": json.loads(r["analysis"] or "{}"),
        "created_at": r["created_at"],
    }
