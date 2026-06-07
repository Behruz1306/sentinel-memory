"""Predictive Retrieval Engine (Moss paradigm).

While the caller is still speaking, a background observer watches the interim
STT stream. The instant a known organizational entity appears
("contract", "invoice", "payroll"...), it fires a pre-fetch into the graph KB
and caches the result on the session — so by the time the sentence finishes,
the answer is already warm. Latency effectively disappears.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass, field

# Entity trigger -> a retrieval query seed for the KB.
ENTITY_MAP = {
    "payroll": "payroll register salaries bank routing",
    "salary": "payroll register salaries",
    "contract": "carrier agreement contract rate terms",
    "agreement": "carrier agreement contract terms",
    "invoice": "invoice amount remittance bank account",
    "carrier": "carrier profile MC DOT insurance",
    "rate": "carrier rate per mile market",
    "insurance": "carrier insurance cargo",
    "bank": "bank account routing remittance",
    "routing": "bank routing account payment",
    "handbook": "employee handbook policy",
    "pto": "employee handbook PTO policy",
}

_ENTITY_RE = re.compile(r"\b(" + "|".join(map(re.escape, ENTITY_MAP)) + r")\b", re.IGNORECASE)

# Lightweight look-ahead: financial trigger words predict a secrecy phrase the
# caller often follows with (BEC / wire-fraud pattern). Presentation-only —
# does not alter caching or trust scoring.
_LOOKAHEAD_RE = re.compile(r"\b(wire|payroll|transfer)\b", re.IGNORECASE)
_CONFIRM_RE = re.compile(
    r"keep\s+this\s+confidential|keep\s+it\s+quiet|don'?t\s+tell|quietly",
    re.IGNORECASE,
)
_FORECAST_PHRASE = "Keep this confidential"
_FORECAST_CONFIDENCE = 91


@dataclass
class Prefetch:
    entity: str
    query: str
    hits: list          # [(doc, relevance)]
    warm: bool = True   # already in cache before the utterance finished
    started_at: float = field(default_factory=time.time)


class PredictiveRetriever:
    """Observes interim transcript tokens and warms the cache ahead of time.

    Pre-fetch runs in a background thread so it never blocks the audio path —
    mirroring how a real worker would intercept the live STT stream. The
    retrieval backend is injected (`retrieve_fn`) so the same warm-cache logic
    works over Moss or the local index.
    """

    def __init__(self, retrieve_fn):
        self._retrieve = retrieve_fn

    def observe(self, session, interim_text: str) -> list:
        """Scan newly-heard text; pre-fetch any entity not already warmed.

        Returns the list of Prefetch objects triggered by *this* observation.
        """
        triggered = []
        for m in _ENTITY_RE.finditer(interim_text or ""):
            entity = m.group(1).lower()
            if entity in session.prefetch_cache:
                continue  # already warm
            query = ENTITY_MAP[entity]
            # placeholder so concurrent observations don't double-fire
            session.prefetch_cache[entity] = []
            pf = Prefetch(entity=entity, query=query, hits=[])
            triggered.append(pf)
            try:
                from .dashboard_bus import emit
                label = self._entity_label(entity)
                emit("prefetch_triggered", entity=entity, label=label)
            except Exception:
                pass
            threading.Thread(
                target=self._warm, args=(session, entity, query, pf), daemon=True
            ).start()
        self._lookahead(session, interim_text)
        return triggered

    def _lookahead(self, session, interim_text: str) -> None:
        """Predict the next utterance fragment for the live dashboard only."""
        text = interim_text or ""
        if not text.strip():
            return
        try:
            from .dashboard_bus import emit
            if _CONFIRM_RE.search(text):
                emit("forecast_confirmed", phrase=_FORECAST_PHRASE,
                     confidence=_FORECAST_CONFIDENCE)
                return
            if _LOOKAHEAD_RE.search(text) and not getattr(session, "_forecast_emitted", False):
                session._forecast_emitted = True
                m = _LOOKAHEAD_RE.search(text)
                emit("anticipatory_forecast", phrase=_FORECAST_PHRASE,
                     confidence=_FORECAST_CONFIDENCE, trigger=m.group(1).lower())
        except Exception:
            pass

    @staticmethod
    def _entity_label(entity: str) -> str:
        labels = {
            "payroll": "Q2 Payroll", "salary": "Payroll Register",
            "contract": "Carrier Contract", "agreement": "Carrier Agreement",
            "invoice": "Invoice / Remittance", "carrier": "Carrier Profile",
            "bank": "Bank Routing", "routing": "Bank Routing",
        }
        return labels.get(entity, entity.title())

    def _warm(self, session, entity: str, query: str, pf: Prefetch):
        hits = self._retrieve(query, 4) or []
        session.prefetch_cache[entity] = hits
        if entity not in session.prefetched_entities:
            session.prefetched_entities.append(entity)
        pf.hits = hits
        latency_ms = round((time.time() - pf.started_at) * 1000, 2)
        try:
            from .dashboard_bus import emit
            emit("cache_warmed", entity=entity, latency_ms=latency_ms)
        except Exception:
            pass

    def cached_for(self, session, query: str):
        """Return warmed hits if the final query maps to a prefetched entity."""
        ql = (query or "").lower()
        for entity, hits in session.prefetch_cache.items():
            if entity in ql and hits:
                return entity, hits
        return None, None
