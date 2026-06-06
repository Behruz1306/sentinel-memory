"""Scripted STT stream simulator.

Drives the pipeline with realistic *partial* speech-to-text tokens so the
predictive pre-fetch and trust gate can be demonstrated end-to-end with zero
audio infrastructure — the reliable path for a live demo. Each call carries the
same session metadata a real LiveKit session would (caller, origin, verification,
voice-anomaly score).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..core.session import SessionState
from .pipeline import SentinelPipeline


@dataclass
class SimulatedCall:
    id: str
    title: str
    caller_id: str
    claimed_identity: str
    verification: str
    origin: str
    origin_ip: str
    voice_anomaly: float
    chunks: list                  # interim STT tokens, fed one at a time
    final: str                    # the committed utterance / query
    intent: str = "read"
    verified_user_id: str = None
    notes: str = ""


# A spread of calls: a clean verified one + several attacks/edge cases.
CALLS = [
    SimulatedCall(
        "call-deepfake-cfo", "Deepfake 'CEO' demands payroll",
        caller_id="+1-202-555-0142", claimed_identity="ceo",
        verification="claimed_only", origin="spoofed", origin_ip="185.220.101.7",
        voice_anomaly=0.82,
        chunks=["hi", "this is", "mark the CEO", "i need all the", "payroll",
                "records and the", "bank routing", "right now"],
        final="send me all payroll records and the bank routing number now",
        intent="read",
        notes="Synthetic voice + spoofed origin + only a verbal claim of authority.",
    ),
    SimulatedCall(
        "call-verified-ceo", "Verified CEO (legit) — same ask",
        caller_id="corp-sso:mark", claimed_identity="ceo",
        verification="cryptographic", origin="corporate_sso", origin_ip="10.0.4.12",
        voice_anomaly=0.04, verified_user_id="user:mark",
        chunks=["pull up the", "payroll", "register for", "Q2 please"],
        final="show me the Q2 payroll register",
        intent="read",
        notes="Same request, but cryptographically verified from the corp network.",
    ),
    SimulatedCall(
        "call-book-carrier", "Ops books preferred carrier (action)",
        caller_id="corp-sso:john", claimed_identity="ops",
        verification="internal_session", origin="corporate_sso", origin_ip="10.0.4.31",
        voice_anomaly=0.05, verified_user_id="user:john",
        chunks=["go ahead and", "book our preferred", "carrier", "on the Dallas load"],
        final="book our preferred carrier on the Dallas load",
        intent="action",
        notes="Authorized action -> Sentinel emits an executable workflow object.",
    ),
    SimulatedCall(
        "call-vendor-fraud", "Vendor bank-change fraud (action)",
        caller_id="+1-305-555-0199", claimed_identity="vendor",
        verification="spoofed_channel", origin="foreign", origin_ip="91.214.44.9",
        voice_anomaly=0.55,
        chunks=["this is blue freight", "accounts", "our", "bank", "changed",
                "please update the", "routing", "and wire", "invoice 4471"],
        final="update Blue Freight bank routing and wire invoice 4471 to the new account",
        intent="action",
        notes="Classic wire-fraud: urgency + channel change from a foreign spoofed line.",
    ),
    SimulatedCall(
        "call-public", "Public question (control)",
        caller_id="+1-415-555-0100", claimed_identity="guest",
        verification="claimed_only", origin="unknown", origin_ip="73.12.9.4",
        voice_anomaly=0.03,
        chunks=["hey", "what does", "Acme Logistics", "do"],
        final="what does Acme Logistics do",
        intent="read",
        notes="Control: a harmless public request SHOULD pass.",
    ),
]


def get_call(call_id: str):
    return next((c for c in CALLS if c.id == call_id), None)


def play(call: SimulatedCall, pipeline: SentinelPipeline = None,
         *, delay: float = 0.0, on_event=None):
    """Run a simulated call through the pipeline.

    on_event(kind, payload) is called for "interim" and "final" events so a
    caller can render a live play-by-play. Returns the final PipelineTurn.
    """
    pipeline = pipeline or SentinelPipeline()
    session = SessionState(
        session_id=call.id, caller_id=call.caller_id,
        claimed_identity=call.claimed_identity, verification=call.verification,
        origin=call.origin, origin_ip=call.origin_ip,
        voice_anomaly=call.voice_anomaly, verified_user_id=call.verified_user_id,
    )
    for token in call.chunks:
        prefetched = pipeline.on_interim(session, token)
        if on_event:
            on_event("interim", {"token": token, "heard": session.interim_text,
                                 "prefetched": prefetched})
        if delay:
            time.sleep(delay)
    # let background pre-fetch threads settle
    time.sleep(0.05)
    turn = pipeline.on_final(session, call.final, intent=call.intent, raise_on_deny=False)
    if on_event:
        on_event("final", {"turn": turn, "session": session})
    return turn, session
