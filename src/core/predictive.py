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
from dataclasses import dataclass

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


@dataclass
class Prefetch:
    entity: str
    query: str
    hits: list          # [(doc, relevance)]
    warm: bool = True   # already in cache before the utterance finished


class PredictiveRetriever:
    """Observes interim transcript tokens and warms the cache ahead of time.

    Pre-fetch runs in a background thread so it never blocks the audio path —
    mirroring how a real worker would intercept the live STT stream.
    """

    def __init__(self, kb):
        self.kb = kb

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
            threading.Thread(
                target=self._warm, args=(session, entity, query, pf), daemon=True
            ).start()
        return triggered

    def _warm(self, session, entity: str, query: str, pf: Prefetch):
        hits = self.kb.retrieve(query, k=4)
        session.prefetch_cache[entity] = hits
        if entity not in session.prefetched_entities:
            session.prefetched_entities.append(entity)
        pf.hits = hits

    def cached_for(self, session, query: str):
        """Return warmed hits if the final query maps to a prefetched entity."""
        ql = (query or "").lower()
        for entity, hits in session.prefetch_cache.items():
            if entity in ql and hits:
                return entity, hits
        return None, None
