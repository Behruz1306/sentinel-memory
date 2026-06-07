"""Twilio voice webhook — real phone calls through Sentinel Workspace.

Configure your Twilio number voice URL to:
    POST https://<host>/api/twilio/voice

Speech is gathered turn-by-turn; each utterance runs the full workspace pipeline.
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Optional
from xml.sax.saxutils import escape

# CallSid -> session_id (in-memory; persisted turns live in SQLite)
_call_sessions: dict[str, str] = {}


def _public_url() -> str:
    return (os.getenv("SENTINEL_PUBLIC_URL") or os.getenv("RENDER_EXTERNAL_URL")
            or "http://localhost:8000").rstrip("/")


def twiml_gather(session_id: str, prompt: str = "") -> str:
    action = f"{_public_url()}/api/twilio/gather?session_id={urllib.parse.quote(session_id)}"
    say = prompt or (
        "Welcome to Sentinel Memory. You are connected through the trust firewall. "
        "Please state your request after the tone."
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna">{escape(say)}</Say>
  <Gather input="speech" action="{escape(action)}" method="POST" speechTimeout="auto" language="en-US">
    <Say voice="Polly.Joanna">I'm listening.</Say>
  </Gather>
  <Say voice="Polly.Joanna">We didn't receive speech. Goodbye.</Say>
</Response>"""


def twiml_reply(session_id: str, reply: str, verdict: str) -> str:
    prefix = {"BLOCK": "Access denied. ", "REDACT": "Partial access. ", "ALLOW": ""}.get(verdict, "")
    action = f"{_public_url()}/api/twilio/gather?session_id={urllib.parse.quote(session_id)}"
    text = escape((prefix + reply)[:500])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna">{text}</Say>
  <Gather input="speech" action="{escape(action)}" method="POST" speechTimeout="auto" language="en-US">
    <Say voice="Polly.Joanna">Anything else?</Say>
  </Gather>
  <Say voice="Polly.Joanna">Thank you. Goodbye.</Say>
</Response>"""


def bind_call(call_sid: str, session_id: str) -> None:
    _call_sessions[call_sid] = session_id


def session_for_call(call_sid: str) -> Optional[str]:
    return _call_sessions.get(call_sid)
