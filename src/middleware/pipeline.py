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
        return [t.entity for t in triggered]

    def on_final(self, session: SessionState, text: str, *,
                 intent: str = "read", raise_on_deny: bool = True) -> PipelineTurn:
        """Commit a final utterance and run the trust-gated retrieval."""
        session.commit_final(text)
        query = text
        try:
            result = self.retriever.execute(
                session, query, intent=intent, raise_on_deny=raise_on_deny
            )
            return PipelineTurn(
                query=query, decision=result.decision,
                denied=(result.decision == "BLOCK"), result=result.to_dict(),
            )
        except AccessDeniedException as e:
            return PipelineTurn(
                query=query, decision="BLOCK", denied=True,
                result=None, breach=e.breach,
            )
