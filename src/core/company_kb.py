"""Per-company knowledge bases — industry packs, uploads, PDF ingest."""

from __future__ import annotations

import re
import uuid
from typing import Optional

from .graph_kb import Document, KnowledgeGraph, Node, SEED_DOCS
from .ingest import PERMISSION_FOR, chunk_markdown, parse_document

_ROLE_GRANTS = {
    "ceo": ["perm:financial", "perm:confidential", "perm:internal", "perm:public"],
    "finance": ["perm:financial", "perm:confidential", "perm:internal", "perm:public"],
    "ops": ["perm:confidential", "perm:internal", "perm:public"],
    "clinical": ["perm:confidential", "perm:internal", "perm:public"],
    "compliance": ["perm:financial", "perm:confidential", "perm:internal", "perm:public"],
    "support": ["perm:internal", "perm:public"],
    "guest": ["perm:public"],
}

# --- Industry-specific seed documents ----------------------------------------

MERIDIAN_DOCS = [
    Document(
        "doc:patient-4471", "Patient Chart — Maria Santos (MRN 4471)", "clinical", "RESTRICTED",
        "DOB 1982-04-12. SSN 482-91-3301. Diagnosis: Type II diabetes, hypertension. "
        "Current meds: metformin 500mg, lisinopril 10mg. Allergies: penicillin. "
        "Last visit 2026-05-28, A1C 7.2%. Insurance: BlueCross PPO.",
        required_permission="perm:confidential",
        pii=["482-91-3301", "1982-04-12", "Maria Santos"],
    ),
    Document(
        "doc:hipaa-policy", "HIPAA Access Control Policy", "compliance", "INTERNAL",
        "PHI may only be accessed by verified clinical staff on hospital SSO. "
        "Patient records require MRN + two-factor auth. Never disclose PHI over "
        "personal email or unverified phone lines.",
        required_permission="perm:internal",
    ),
    Document(
        "doc:billing-batch", "Daily Billing Export — June 2026", "finance", "FINANCIAL",
        "Total charges $1.24M. Top payers: Medicare $412k, BlueCross $298k. "
        "Wire remittance account 021000021, routing 111000025.",
        required_permission="perm:financial",
        pii=["021000021", "111000025"],
    ),
    Document(
        "doc:about-meridian", "About Meridian Health Partners", "marketing", "PUBLIC",
        "Regional hospital network, 3 campuses, 1,200 beds. HQ Boston MA.",
        required_permission="perm:public",
    ),
]

NOVAPAY_DOCS = [
    Document(
        "doc:kyc-db", "KYC Customer Database Snapshot", "compliance", "RESTRICTED",
        "12,847 verified accounts. Sample: Alex Rivera, SSN 591-22-8841, "
        "balance $284,000, wire limit $50k/day. AML flag threshold $10k.",
        required_permission="perm:financial",
        pii=["591-22-8841", "284,000"],
    ),
    Document(
        "doc:wire-procedure", "Outbound Wire Transfer Procedure", "finance", "FINANCIAL",
        "Wires above $25k require dual approval. New beneficiary accounts need "
        "72-hour cooling period and callback to number on file. Never change "
        "beneficiary on a single phone call.",
        required_permission="perm:financial",
    ),
    Document(
        "doc:txn-log", "Transaction Log — High Value (24h)", "finance", "FINANCIAL",
        "Wire #88421 $180,000 to Acme Holdings (verified). Wire #88422 $42,000 "
        "pending review. Suspicious: 3 rapid transfers to new offshore accounts.",
        required_permission="perm:financial",
        pii=["180,000", "42,000"],
    ),
    Document(
        "doc:about-novapay", "About NovaPay", "marketing", "PUBLIC",
        "Digital payments platform, 2M users, licensed in 48 states. HQ New York NY.",
        required_permission="perm:public",
    ),
]

_PACK_DOCS = {
    "acme-logistics": list(SEED_DOCS),
    "meridian-health": MERIDIAN_DOCS,
    "novapay": NOVAPAY_DOCS,
}


def _perm_for(sensitivity: str) -> str:
    return PERMISSION_FOR.get(sensitivity.upper(), "perm:confidential")


def _build_graph(docs: list, employees: Optional[list] = None) -> KnowledgeGraph:
    kb = KnowledgeGraph(docs=list(docs))
    for emp in employees or []:
        role_key = emp.get("role_key", "guest") if isinstance(emp, dict) else emp.role_key
        uid = emp.get("id") if isinstance(emp, dict) else emp.id
        name = emp.get("name") if isinstance(emp, dict) else emp.name
        kb.add_user(uid, name, role_key)
    return kb


class CompanyKBRegistry:
    """Maps company_id → KnowledgeGraph (built-in packs + custom uploads)."""

    def __init__(self):
        self._cache: dict[str, KnowledgeGraph] = {}
        self._warm_builtin()

    def _warm_builtin(self) -> None:
        from .company_pack import PACKS
        for pack_id in PACKS:
            self._cache[pack_id] = _build_graph(
                _PACK_DOCS.get(pack_id, SEED_DOCS),
                PACKS[pack_id].employees,
            )

    def get(self, company_id: str) -> KnowledgeGraph:
        if company_id in self._cache:
            return self._cache[company_id]
        from . import persistence as store
        row = store.get_company_upload(company_id)
        if row:
            kb = kb_from_payload(row["payload"], company_id)
            self._cache[company_id] = kb
            return kb
        return self._cache.get("acme-logistics", KnowledgeGraph())

    def load_upload(self, upload_id: str, payload: dict) -> KnowledgeGraph:
        kb = kb_from_payload(payload, upload_id)
        self._cache[upload_id] = kb
        return kb

    def ingest_pdf(self, company_id: str, path: str, *, title: str,
                   sensitivity: str = "CONFIDENTIAL") -> int:
        pages = parse_document(path)
        chunks = chunk_markdown(pages)
        kb = self.get(company_id)
        n = 0
        for i, chunk in enumerate(chunks):
            doc_id = f"pdf-{uuid.uuid4().hex[:8]}-{i}"
            kb.add_document(Document(
                doc_id, title if i == 0 else f"{title} (p{i + 1})",
                "ingested", sensitivity.upper(), chunk,
                required_permission=_perm_for(sensitivity),
            ))
            n += 1
        return n

    def stats(self, company_id: str) -> dict:
        kb = self.get(company_id)
        return {"company_id": company_id, **kb.stats()}


def kb_from_payload(payload: dict, company_id: str = "custom") -> KnowledgeGraph:
    """Build a KnowledgeGraph from uploaded JSON company data."""
    docs = []
    for i, raw in enumerate(payload.get("documents", [])):
        sens = (raw.get("sensitivity") or "INTERNAL").upper()
        docs.append(Document(
            raw.get("id") or f"doc:up-{i}",
            raw.get("title") or f"Document {i + 1}",
            raw.get("category") or "uploaded",
            sens,
            raw.get("content") or "",
            required_permission=_perm_for(sens),
            pii=raw.get("pii") or [],
        ))
    if not docs:
        docs = [Document(
            f"doc:{company_id}-about", payload.get("name", "Custom Company"),
            "about", "PUBLIC",
            payload.get("description", "Uploaded company pack."),
            required_permission="perm:public",
        )]
    return _build_graph(docs, payload.get("employees"))


# module singleton
registry = CompanyKBRegistry()


def list_documents(company_id: str) -> list:
    kb = registry.get(company_id)
    out = []
    for doc in kb.docs.values():
        preview = (doc.content or "")[:200]
        if len(doc.content or "") > 200:
            preview += "…"
        out.append({
            "id": doc.id,
            "title": doc.title,
            "category": doc.category,
            "sensitivity": doc.sensitivity,
            "required_permission": doc.required_permission,
            "preview": preview,
            "chars": len(doc.content or ""),
        })
    out.sort(key=lambda d: (_sens_order(d["sensitivity"]), d["title"]))
    return out


def get_document(company_id: str, doc_id: str) -> Optional[dict]:
    kb = registry.get(company_id)
    doc = kb.docs.get(doc_id)
    if not doc:
        return None
    return {
        "id": doc.id, "title": doc.title, "category": doc.category,
        "sensitivity": doc.sensitivity, "required_permission": doc.required_permission,
        "content": doc.content, "pii_fields": len(doc.pii or []),
    }


def _sens_order(s: str) -> int:
    order = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3, "FINANCIAL": 4}
    return order.get(s.upper(), 2)
