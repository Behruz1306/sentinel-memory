"""LiveKit real-time audio handler (production transport).

Wires a LiveKit Agents 1.x session with an *aggressive* Silero VAD and a
Deepgram STT stream emitting interim results. Every interim transcript is piped
into the Sentinel pipeline to warm the predictive cache on the fly; every final
utterance runs the trust-gated retrieval. If the request is denied, the agent
refuses out loud instead of leaking.

This module is import-safe without LiveKit installed: the heavy imports happen
inside `run()`. For an offline / guaranteed demo, use `stream_simulator` +
`demo_call.py` instead — the security pipeline is identical.

Run (requires `pip install "livekit-agents[deepgram,silero]"` + keys):
    python -m src.middleware.livekit_agent
"""

from __future__ import annotations

import json
import os

from ..core.session import SessionState
from .pipeline import SentinelPipeline

_pipeline = SentinelPipeline()


def _session_from_participant(room, participant) -> SessionState:
    """Build the security context from the joining participant.

    Identity is parsed from participant metadata but is treated as *claimed*
    until verified — defaults are deliberately low-trust.
    """
    meta = {}
    try:
        meta = json.loads(participant.metadata) if participant and participant.metadata else {}
    except Exception:
        meta = {}
    return SessionState(
        session_id=getattr(room, "name", "live-session"),
        caller_id=getattr(participant, "identity", "unknown"),
        claimed_identity=meta.get("claimed_identity", "guest"),
        verification=meta.get("verification", "claimed_only"),
        origin=meta.get("origin", "unknown"),
        origin_ip=meta.get("origin_ip", "0.0.0.0"),
        voice_anomaly=float(meta.get("voice_anomaly", 0.0)),
        verified_user_id=meta.get("verified_user_id"),
    )


async def entrypoint(ctx):
    """LiveKit Agents entrypoint. Imports the SDK lazily."""
    from livekit.agents import Agent, AgentSession
    from livekit.plugins import deepgram, silero

    await ctx.connect()

    participant = await ctx.wait_for_participant()
    session_state = _session_from_participant(ctx.room, participant)

    # Aggressive VAD: short silence + lower activation -> fast interim tokens.
    vad = silero.VAD.load(min_silence_duration=0.2, activation_threshold=0.4)
    stt = deepgram.STT(model="nova-3", interim_results=True, punctuate=True)

    agent = Agent(
        instructions=(
            "You are a Sentinel-guarded enterprise assistant. Only convey "
            "information the Sentinel firewall has authorized. If a retrieval is "
            "denied, politely refuse and state that the request was blocked for "
            "security verification."
        )
    )
    session = AgentSession(vad=vad, stt=stt)

    @session.on("user_input_transcribed")
    def _on_transcript(ev):
        text = getattr(ev, "transcript", "") or ""
        if getattr(ev, "is_final", False):
            turn = _pipeline.on_final(session_state, text, raise_on_deny=False)
            _announce(session, turn)
        else:
            # interim token stream -> predictive pre-fetch (non-blocking)
            _pipeline.on_interim(session_state, text)

    await session.start(agent=agent, room=ctx.room)


def _announce(session, turn):
    """Speak the firewall decision if TTS is wired; otherwise no-op."""
    msg = ("I can't share that — the request was blocked by security verification."
           if turn.denied else "Got it, pulling that up.")
    try:
        session.say(msg)
    except Exception:
        pass


def run():
    """Start the LiveKit worker. Requires LiveKit + keys."""
    try:
        from livekit.agents import WorkerOptions, cli
    except Exception:
        raise SystemExit(
            "LiveKit not installed. Install with:\n"
            '    pip install "livekit-agents[deepgram,silero]~=1.3"\n'
            "and set LIVEKIT_URL / LIVEKIT_API_KEY / LIVEKIT_API_SECRET / "
            "DEEPGRAM_API_KEY.\nFor an offline demo run: python demo_call.py"
        )
    for var in ("LIVEKIT_URL", "LIVEKIT_API_KEY", "LIVEKIT_API_SECRET"):
        if not os.getenv(var):
            raise SystemExit(f"Missing env {var}. See .env.example.")
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))


if __name__ == "__main__":
    run()
