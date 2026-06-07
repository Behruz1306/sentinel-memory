"""SQLite persistence — sessions, turns, global activity, reports.

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


def _db_path() -> str:
    return os.getenv("SENTINEL_DB_PATH", _DEFAULT_DB)


def _connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        path = _db_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _conn = sqlite3.connect(path, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _init_schema(_conn)
    return _conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            company_id TEXT NOT NULL DEFAULT 'acme-logistics',
            channel TEXT NOT NULL DEFAULT 'chat',
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
    """)
    conn.commit()


def create_session(*, company_id: str = "acme-logistics", channel: str = "chat",
                   caller_name: str = "", claimed_identity: str = "guest",
                   verification: str = "claimed_only", origin: str = "unknown",
                   voice_anomaly: float = 0.0, meta: Optional[dict] = None) -> str:
    sid = f"sess-{uuid.uuid4().hex[:12]}"
    now = time.time()
    with _lock:
        _connect().execute(
            "INSERT INTO sessions (id, company_id, channel, caller_name, "
            "claimed_identity, verification, origin, voice_anomaly, "
            "trust_score, created_at, updated_at, meta) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (sid, company_id, channel, caller_name, claimed_identity,
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


def list_sessions(limit: int = 30) -> list:
    with _lock:
        rows = _connect().execute(
            "SELECT * FROM sessions ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_session(r) for r in rows]


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
    return {"sessions": sessions, "turns": turns, "events": events, "uploads": uploads}


def _row_session(r) -> dict:
    return {
        "id": r["id"], "company_id": r["company_id"], "channel": r["channel"],
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
