"""Mock Graph Knowledge Base — the high-speed local memory layer.

Most RAG stores isolated chunks. Sentinel stores *relationships*:

    User ──HAS_ROLE──▶ Role ──GRANTS──▶ Permission ──ALLOWS──▶ Document

Retrieval can therefore reason over the graph (who may see what, and *why*)
instead of only ranking by similarity. Documents are sensitivity-tagged so the
trust engine can gate them.

Embeddings are used when an LLM key is present; otherwise a lexical scorer
keeps retrieval fully functional offline.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from typing import Optional

# Sensitivity -> minimum SessionTrustScore required (the permission matrix is
# the authoritative copy in trust_engine; this mirror keeps docs self-describing).
SENSITIVITY_ORDER = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "FINANCIAL"]


@dataclass
class Document:
    id: str
    title: str
    category: str
    sensitivity: str
    content: str
    required_permission: str
    pii: list = field(default_factory=list)
    embedding: Optional[list] = None


@dataclass
class Node:
    id: str
    kind: str           # user | role | permission | document
    label: str
    attrs: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Seed graph: fictional "Acme Logistics"
# ---------------------------------------------------------------------------
_USERS = [
    Node("user:mark", "user", "Mark Diaz", {"role": "role:ceo"}),
    Node("user:sarah", "user", "Sarah Chen", {"role": "role:finance"}),
    Node("user:john", "user", "John Reyes", {"role": "role:ops"}),
    Node("user:guest", "user", "Unknown Caller", {"role": "role:guest"}),
]
_ROLES = [
    Node("role:ceo", "role", "CEO", {"grants": ["perm:financial", "perm:confidential", "perm:internal", "perm:public"]}),
    Node("role:finance", "role", "Finance Director", {"grants": ["perm:financial", "perm:confidential", "perm:internal", "perm:public"]}),
    Node("role:ops", "role", "Operations", {"grants": ["perm:confidential", "perm:internal", "perm:public"]}),
    Node("role:guest", "role", "Guest", {"grants": ["perm:public"]}),
]
_PERMS = [
    Node("perm:public", "permission", "PUBLIC"),
    Node("perm:internal", "permission", "INTERNAL"),
    Node("perm:confidential", "permission", "CONFIDENTIAL"),
    Node("perm:financial", "permission", "FINANCIAL"),
]

SEED_DOCS = [
    Document(
        "doc:payroll-q2", "Q2 Payroll Register", "payroll", "FINANCIAL",
        "Full payroll for Q2. Sarah Chen $214,000/yr; John Reyes $138,000; "
        "CEO Mark Diaz $410,000. Bank routing 021000021, account 5567829104. "
        "SSNs on file.",
        required_permission="perm:financial",
        pii=["214,000", "138,000", "410,000", "021000021", "5567829104"],
    ),
    Document(
        "doc:contract-blue", "Master Carrier Agreement — Blue Freight",
        "contracts", "CONFIDENTIAL",
        "Signed by John Reyes 2026-03-11. Rate $2.18/mi, 30-day terms, $1M "
        "cargo insurance. Amendment A: detention $75/hr. Approved by Sarah Chen.",
        required_permission="perm:confidential",
        pii=["2.18"],
    ),
    Document(
        "doc:invoice-4471", "Invoice #4471 — Blue Freight", "finance", "FINANCIAL",
        "Amount $48,200 due 2026-06-20. Remit to Blue Freight, account "
        "5567829104, routing 021000021. PO #BG-7781.",
        required_permission="perm:financial",
        pii=["48,200", "5567829104", "021000021"],
    ),
    Document(
        "doc:carrier-blue", "Carrier Profile — Blue Freight LLC", "carriers", "INTERNAL",
        "MC-884213, DOT 2910887. Preferred carrier. Insurance valid to 2027-01. "
        "Credit limit $250k. 94% on-time over 311 loads.",
        required_permission="perm:internal",
    ),
    Document(
        "doc:handbook", "Employee Handbook (2026)", "hr", "INTERNAL",
        "PTO policy, expense limits ($75/day meals), code of conduct, security "
        "awareness training schedule.",
        required_permission="perm:internal",
    ),
    Document(
        "doc:bank-change", "Vendor Banking — Change Procedure", "finance", "FINANCIAL",
        "Bank-detail changes require: written request, callback to the number "
        "ON FILE (never one provided in the request), and dual approval by "
        "Finance Dir + CEO. Never change on a single phone call.",
        required_permission="perm:financial",
    ),
    Document(
        "doc:about", "About Acme Logistics", "marketing", "PUBLIC",
        "Acme Logistics is a 3PL freight brokerage founded 2019, HQ Dallas TX. "
        "We move dry van, reefer and flatbed nationwide.",
        required_permission="perm:public",
    ),
]


def _tok(text: str) -> list:
    return re.findall(r"[a-z0-9]+", text.lower())


def _lexical(query: str, doc: Document) -> float:
    q = set(_tok(query))
    if not q:
        return 0.0
    body = set(_tok(doc.title + " " + doc.category + " " + doc.content))
    title = set(_tok(doc.title + " " + doc.category))
    if not body:
        return 0.0
    return len(q & body) / len(q) + 0.5 * len(q & title)


def _cosine(a: list, b: list) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class KnowledgeGraph:
    def __init__(self, docs: Optional[list] = None):
        self.docs = {d.id: d for d in (docs if docs is not None else list(SEED_DOCS))}
        self.nodes: dict = {}
        for n in _USERS + _ROLES + _PERMS:
            self.nodes[n.id] = n
        for d in self.docs.values():
            self.nodes[d.id] = Node(d.id, "document", d.title,
                                    {"permission": d.required_permission, "sensitivity": d.sensitivity})
        self._embed_ready = False

    # -- graph traversal ----------------------------------------------------
    def permissions_for_user(self, user_id: str) -> list:
        u = self.nodes.get(user_id)
        if not u:
            return ["perm:public"]
        role = self.nodes.get(u.attrs.get("role", ""))
        return list(role.attrs.get("grants", ["perm:public"])) if role else ["perm:public"]

    def documents_for_user(self, user_id: str) -> list:
        """Traverse User -> Role -> Permission -> Document."""
        allowed = set(self.permissions_for_user(user_id))
        return [d for d in self.docs.values() if d.required_permission in allowed]

    def relationship_path(self, user_id: str, doc_id: str) -> list:
        """Human-readable path explaining *why* a user can reach a document."""
        u = self.nodes.get(user_id)
        d = self.docs.get(doc_id)
        if not u or not d:
            return []
        role = self.nodes.get(u.attrs.get("role", ""))
        if not role or d.required_permission not in role.attrs.get("grants", []):
            return [u.label, "→ (no permission path) →", d.title]
        perm = self.nodes.get(d.required_permission)
        return [u.label, "HAS_ROLE", role.label, "GRANTS",
                perm.label if perm else d.required_permission, "ALLOWS", d.title]

    # -- retrieval ----------------------------------------------------------
    def _ensure_embeddings(self):
        if self._embed_ready or not os.getenv("OPENAI_API_KEY"):
            return
        try:
            from openai import OpenAI

            client = OpenAI()
            texts = [f"{d.title}. {d.content}" for d in self.docs.values()]
            resp = client.embeddings.create(model="text-embedding-3-small", input=texts)
            for d, item in zip(self.docs.values(), resp.data):
                d.embedding = item.embedding
            self._embed_ready = True
        except Exception:
            self._embed_ready = False

    def _embed_query(self, query: str):
        if not self._embed_ready:
            return None
        try:
            from openai import OpenAI

            client = OpenAI()
            return client.embeddings.create(model="text-embedding-3-small", input=[query]).data[0].embedding
        except Exception:
            return None

    def retrieve(self, query: str, k: int = 4) -> list:
        """Pure relevance ranking (trust is applied later by the firewall)."""
        self._ensure_embeddings()
        qv = self._embed_query(query) if self._embed_ready else None
        scored = []
        for d in self.docs.values():
            if qv is not None and d.embedding is not None:
                s = _cosine(qv, d.embedding)
            else:
                s = _lexical(query, d)
            if s > 0:
                scored.append((d, round(s, 3)))
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored[:k]

    def stats(self) -> dict:
        return {
            "users": sum(1 for n in self.nodes.values() if n.kind == "user"),
            "roles": sum(1 for n in self.nodes.values() if n.kind == "role"),
            "permissions": sum(1 for n in self.nodes.values() if n.kind == "permission"),
            "documents": len(self.docs),
        }
