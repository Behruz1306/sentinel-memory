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


WELCOME_SCRIPT = (
    "Hello, and thank you for calling the Sentinel secure assistant. "
    "This line is protected by our trust firewall. "
    "I'm here to help with shipments, accounts, payroll questions, and internal requests. "
    "Let's have a natural conversation — first, who am I speaking with today?"
)


def twiml_gather(session_id: str, prompt: str = "") -> str:
    action = f"{_public_url()}/api/twilio/gather?session_id={urllib.parse.quote(session_id)}"
    say = prompt or WELCOME_SCRIPT
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna">{escape(say)}</Say>
  <Gather input="speech" action="{escape(action)}" method="POST"
          speechTimeout="auto" timeout="8" language="en-US" enhanced="true">
    <Say voice="Polly.Joanna">Go ahead, I'm listening.</Say>
  </Gather>
  <Say voice="Polly.Joanna">I didn't hear anything. Please call back when you're ready. Goodbye.</Say>
</Response>"""


def twiml_reply(session_id: str, reply: str, phone_verdict: str, *, final: bool = False) -> str:
    """phone_verdict: LISTENING | REVIEW | ALLOW | BLOCK | REDACT"""
    action = f"{_public_url()}/api/twilio/gather?session_id={urllib.parse.quote(session_id)}"
    text = escape((reply or "Thank you.")[:600])
    if final and phone_verdict == "BLOCK":
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna">{text}</Say>
  <Pause length="1"/>
  <Say voice="Polly.Joanna">This call has been logged for security review. Goodbye.</Say>
  <Hangup/>
</Response>"""
    if final and phone_verdict == "ALLOW":
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna">{text}</Say>
  <Gather input="speech" action="{escape(action)}" method="POST"
          speechTimeout="auto" timeout="6" language="en-US">
    <Say voice="Polly.Joanna">Is there anything else I can help you with?</Say>
  </Gather>
  <Say voice="Polly.Joanna">Thank you for calling. Have a great day. Goodbye.</Say>
  <Hangup/>
</Response>"""
    follow = "Please go on — I'm still with you." if phone_verdict in ("LISTENING", "REVIEW") else "Anything else?"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Response>
  <Say voice="Polly.Joanna">{text}</Say>
  <Gather input="speech" action="{escape(action)}" method="POST"
          speechTimeout="auto" timeout="8" language="en-US" enhanced="true">
    <Say voice="Polly.Joanna">{escape(follow)}</Say>
  </Gather>
  <Say voice="Polly.Joanna">Thank you for calling. Goodbye.</Say>
</Response>"""


def bind_call(call_sid: str, session_id: str) -> None:
    _call_sessions[call_sid] = session_id


def session_for_call(call_sid: str) -> Optional[str]:
    return _call_sessions.get(call_sid)
