"""Live voice-session state tracker.

Every WebRTC voice session carries a mutable security context that Sentinel
updates turn-by-turn: who the caller claims to be, where the stream originates,
how it was verified, signs of synthetic/deepfake audio, and the running
transcript. The trust engine reads this state to score the session.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionState:
    session_id: str
    caller_id: str = "unknown"
    claimed_identity: str = "guest"          # role key: ceo/finance/ops/guest...
    verified_user_id: Optional[str] = None   # set only after real verification
    verification: str = "claimed_only"       # channel used to verify identity
    origin: str = "unknown"                   # WebRTC ip / SIP origin class
    origin_ip: str = "0.0.0.0"

    # voice/audio anomaly signals (0..1). 1.0 == almost certainly synthetic.
    voice_anomaly: float = 0.0
    emotion: str = "neutral"

    # rolling conversation context
    transcript: str = ""
    interim_text: str = ""
    turns: list = field(default_factory=list)

    # predictive prefetch cache: entity -> [(doc, relevance)]
    prefetch_cache: dict = field(default_factory=dict)
    prefetched_entities: list = field(default_factory=list)

    # last computed trust (filled by trust_engine)
    trust_score: int = 0
    created_at: float = field(default_factory=time.time)

    def add_interim(self, token: str):
        self.interim_text = (self.interim_text + " " + token).strip()

    def commit_final(self, text: str):
        self.turns.append(text)
        self.transcript = (self.transcript + "\n" + text).strip()
        self.interim_text = ""

    def full_context(self) -> str:
        return (self.transcript + "\n" + self.interim_text).strip()


class SessionManager:
    """In-memory registry of active sessions."""

    def __init__(self):
        self._sessions: dict = {}

    def open(self, session_id: str, **kwargs) -> SessionState:
        s = SessionState(session_id=session_id, **kwargs)
        self._sessions[session_id] = s
        return s

    def get(self, session_id: str) -> Optional[SessionState]:
        return self._sessions.get(session_id)

    def close(self, session_id: str):
        self._sessions.pop(session_id, None)

    def all(self) -> list:
        return list(self._sessions.values())


# module-level singleton
sessions = SessionManager()
