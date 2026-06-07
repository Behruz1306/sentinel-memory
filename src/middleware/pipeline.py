"""SentinelPipeline — orchestrates a live voice turn.

Transport-agnostic: it consumes STT tokens (interim + final) from *any* source
(real LiveKit audio or the scripted simulator) and runs:

    interim token  -> predictive pre-fetch (warm the cache, never block)
    final utterance -> trust scoring -> gated, action-aware retrieval

This decoupling is deliberate: the security pipeline is identical whether the
audio came from a real phone call or a test harness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..core.exceptions import AccessDeniedException
from ..core.graph_kb import KnowledgeGraph
from ..core.retrieval import SentinelRetriever
from ..core.session import SessionState


@dataclass
class PipelineTurn:
    query: str
    decision: str
    denied: bool
    result: Optional[dict]      # RetrievalResult.to_dict(), or None if hard-denied
    breach: Optional[dict] = None


class SentinelPipeline:
    def __init__(self, kb: Optional[KnowledgeGraph] = None):
        self.kb = kb or KnowledgeGraph()
        self.retriever = SentinelRetriever(self.kb)

    # -- streaming hooks ----------------------------------------------------
    def on_interim(self, session: SessionState, token: str) -> list:
        """Feed an interim STT token; returns entities pre-fetched this tick."""
        session.add_interim(token)
        triggered = self.retriever.predictive.observe(session, session.interim_text)
        self._emit_interim(session)
        return [t.entity for t in triggered]

    def _emit_interim(self, session: SessionState) -> None:
        try:
            from ..core import trust_engine as te
            from ..core.dashboard_bus import emit
            tb = te.compute_trust_score(session, use_llm=False)
            emit(
                "interim_transcript",
                text=session.interim_text,
                session_id=session.session_id,
                trust_score=tb.score,
                voice_anomaly=session.voice_anomaly,
            )
        except Exception:
            pass

    def on_final(self, session: SessionState, text: str, *,
                 intent: str = "read", raise_on_deny: bool = True) -> PipelineTurn:
        """Commit a final utterance and run the trust-gated retrieval."""
        session.commit_final(text)
        # Look-ahead confirmation check on the committed utterance (dashboard only).
        self.retriever.predictive._lookahead(session, text)
        query = text
        try:
            result = self.retriever.execute(
                session, query, intent=intent, raise_on_deny=raise_on_deny
            )
            self._emit_final(session, text, result.to_dict())
            return PipelineTurn(
                query=query, decision=result.decision,
                denied=(result.decision == "BLOCK"), result=result.to_dict(),
            )
        except AccessDeniedException as e:
            self._emit_final(session, text, None, decision="BLOCK")
            return PipelineTurn(
                query=query, decision="BLOCK", denied=True,
                result=None, breach=e.breach,
            )

    def _emit_final(self, session: SessionState, text: str, result: Optional[dict],
                    *, decision: str = "ALLOW") -> None:
        try:
            from ..core.dashboard_bus import emit
            trust = (result or {}).get("trust", {})
            emit("final_transcript", text=text, session_id=session.session_id,
                 trust_score=trust.get("score", session.trust_score))
            if result:
                pred = result.get("predictive") or {}
                emit(
                    "verdict",
                    decision=result.get("decision", decision),
                    trust_score=trust.get("score"),
                    response_latency_ms=pred.get("lookup_ms", 0),
                    alert=(f"🚨 RED ALERT: Access Denied — {text[:60]}"
                           if result.get("decision") == "BLOCK" else None),
                )
                threat = trust.get("threat") or {}
                if threat.get("engines"):
                    emit("trust_update", score=trust.get("score"),
                         engines=threat["engines"],
                         consensus=threat.get("consensus", {}))
        except Exception:
            pass
