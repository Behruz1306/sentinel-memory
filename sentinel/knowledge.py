"""Knowledge base + retrieval.

This is the layer Moss says is the real bottleneck. Sentinel's twist: every
document carries a *sensitivity* level, so retrieval can be gated by trust —
not just ranked by similarity.

Retrieval uses OpenAI embeddings when a key is present, and falls back to a
lexical (token-overlap) scorer otherwise, so the demo always returns results.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Optional

# Sensitivity ladder -> the trust score required to see it in full.
SENSITIVITY = {
    "PUBLIC": 0,
    "INTERNAL": 50,
    "CONFIDENTIAL": 80,
    "RESTRICTED": 90,
}


@dataclass
class Document:
    id: str
    title: str
    category: str
    sensitivity: str
    content: str
    # fields worth masking when we REDACT instead of BLOCK
    pii: list[str] = field(default_factory=list)
    _embedding: Optional[list[float]] = None

    @property
    def required_trust(self) -> int:
        return SENSITIVITY.get(self.sensitivity, 80)


# --- Seed corpus: a small fictional logistics company, "Acme Logistics" ------
# Mix of sensitivities so the firewall has interesting decisions to make.
SEED_DOCS: list[Document] = [
    Document(
        "doc-payroll-q2", "Q2 Payroll Register", "payroll", "RESTRICTED",
        "Full payroll for Q2. Sarah Chen (Finance Dir) $214,000/yr; John Reyes "
        "(Ops) $138,000; CEO Mark Diaz $410,000. Bank routing 021000021, "
        "account 5567829104. SSNs on file.",
        pii=["214,000", "138,000", "410,000", "021000021", "5567829104"],
    ),
    Document(
        "doc-contract-acme-001", "Master Carrier Agreement — Blue Freight",
        "contracts", "CONFIDENTIAL",
        "Signed by John Reyes on 2026-03-11. Negotiated rate $2.18/mi, 30-day "
        "payment terms, $1M cargo insurance. Amendment A raised detention to "
        "$75/hr. Approved by Sarah Chen.",
        pii=["2.18", "5567829104"],
    ),
    Document(
        "doc-carrier-bluefreight", "Carrier Profile — Blue Freight LLC",
        "carriers", "INTERNAL",
        "MC-884213, DOT 2910887. Preferred carrier. Insurance valid to "
        "2027-01. Credit limit $250k. 94% on-time over 311 loads.",
    ),
    Document(
        "doc-invoice-4471", "Invoice #4471 — Blue Freight", "finance", "CONFIDENTIAL",
        "Amount $48,200 due 2026-06-20. Remit to Blue Freight, account "
        "5567829104, routing 021000021. PO #BG-7781.",
        pii=["48,200", "5567829104", "021000021"],
    ),
    Document(
        "doc-handbook", "Employee Handbook (2026)", "hr", "INTERNAL",
        "PTO policy, expense limits ($75/day meals), code of conduct, security "
        "awareness training schedule.",
    ),
    Document(
        "doc-about", "About Acme Logistics", "marketing", "PUBLIC",
        "Acme Logistics is a third-party freight brokerage founded 2019, HQ in "
        "Dallas TX. We move dry van, reefer and flatbed nationwide.",
    ),
    Document(
        "doc-vendor-bank-change", "Vendor Banking — Change Procedure", "finance",
        "RESTRICTED",
        "Bank-detail changes for any vendor require: written request, callback "
        "to the number ON FILE (not one provided in the request), and dual "
        "approval by Finance Dir + CEO. Never change on a single phone call.",
    ),
]


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def _lexical_score(query: str, doc: Document) -> float:
    q = set(_tokenize(query))
    if not q:
        return 0.0
    d = _tokenize(doc.title + " " + doc.category + " " + doc.content)
    if not d:
        return 0.0
    dset = set(d)
    overlap = len(q & dset)
    # light idf-ish boost for title/category hits
    title_hits = len(q & set(_tokenize(doc.title + " " + doc.category)))
    return overlap / len(q) + 0.5 * title_hits


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class KnowledgeBase:
    def __init__(self, docs: Optional[list[Document]] = None):
        self.docs = docs if docs is not None else list(SEED_DOCS)
        self._embed_ready = False

    # -- optional embedding index ------------------------------------------
    def _ensure_embeddings(self):
        if self._embed_ready or not os.getenv("OPENAI_API_KEY"):
            return
        try:
            from openai import OpenAI

            client = OpenAI()
            texts = [f"{d.title}. {d.content}" for d in self.docs]
            resp = client.embeddings.create(
                model="text-embedding-3-small", input=texts
            )
            for d, item in zip(self.docs, resp.data):
                d._embedding = item.embedding
            self._embed_ready = True
        except Exception:
            self._embed_ready = False

    def _embed_query(self, query: str) -> Optional[list[float]]:
        if not self._embed_ready:
            return None
        try:
            from openai import OpenAI

            client = OpenAI()
            resp = client.embeddings.create(
                model="text-embedding-3-small", input=[query]
            )
            return resp.data[0].embedding
        except Exception:
            return None

    def retrieve(self, query: str, k: int = 4) -> list[tuple[Document, float]]:
        """Return up to k (document, relevance) pairs, best first.

        NOTE: this is pure relevance — it does NOT consider trust. The firewall
        applies trust on top. That separation is the whole point.
        """
        self._ensure_embeddings()
        qv = self._embed_query(query) if self._embed_ready else None
        scored: list[tuple[Document, float]] = []
        for d in self.docs:
            if qv is not None and d._embedding is not None:
                s = _cosine(qv, d._embedding)
            else:
                s = _lexical_score(query, d)
            if s > 0:
                scored.append((d, s))
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:k]
