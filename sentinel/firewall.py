"""The Retrieval Firewall.

Pipeline for every retrieval request an agent makes:

    query + caller context
        -> semantic retrieval        (what's relevant)
        -> trust resolution          (what trust did the requester earn)
        -> social-engineering scan   (does the conversation smell like an attack)
        -> decision                  (ALLOW / REDACT / BLOCK, with reasons)

Retrieval informed by security, not just similarity.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional

from . import llm
from .knowledge import KnowledgeBase, Document
from .trust import effective_trust


# --- social-engineering detection -------------------------------------------

_SE_PATTERNS = {
    "urgency": r"\b(urgent|immediately|right now|asap|emergency|before .* close|in the next)\b",
    "authority": r"\b(this is the (ceo|cfo|director)|i'?m the (ceo|cfo)|on behalf of|board)\b",
    "secrecy": r"\b(don'?t tell|keep this (quiet|between us)|confidential.*don'?t|no one (else|needs))\b",
    "bypass": r"\b(skip|bypass|override|no time for|forget the (process|policy|verification))\b",
    "channel_change": r"\b(new (bank|account|routing)|change.*(bank|payment|account)|send.*gift card|wire to)\b",
    "payload": r"(ignore (all|previous) instructions|system prompt|you are now|disregard)",
}


def _heuristic_se_score(transcript: str) -> tuple[int, list[str]]:
    t = (transcript or "").lower()
    hits: list[str] = []
    for name, pat in _SE_PATTERNS.items():
        if re.search(pat, t):
            hits.append(name)
    # each distinct manipulation tactic adds risk; payload/channel weigh more
    weight = {"payload": 35, "channel_change": 30, "bypass": 25}
    score = sum(weight.get(h, 18) for h in hits)
    return min(score, 100), hits


def social_engineering_scan(transcript: str) -> tuple[int, list[str]]:
    """Return (risk 0-100, signals[]). LLM-backed, heuristic fallback."""
    base, hits = _heuristic_se_score(transcript)
    out = llm.complete_json(
        system=(
            "You are a security analyst detecting social engineering in a "
            "conversation where someone is asking an AI agent to retrieve data "
            "or take an action. Score manipulation risk 0-100 and list the "
            "specific tactics you see (e.g. urgency, authority_pressure, "
            "secrecy, verification_bypass, channel_change, prompt_injection, "
            "vendor_fraud). Respond as JSON: "
            '{"risk": int, "signals": [str], "rationale": str}'
        ),
        user=f"Conversation:\n{transcript or '(no transcript)'}",
        max_tokens=300,
    )
    if not out:
        return base, hits
    try:
        risk = int(out.get("risk", base))
        signals = [str(s) for s in out.get("signals", [])] or hits
        # never let the LLM talk us *below* a strong heuristic signal
        return max(risk, base if hits else 0), signals
    except Exception:
        return base, hits


# --- decision model ----------------------------------------------------------

@dataclass
class RetrievalRequest:
    query: str
    claimed_identity: str = "unknown"
    verification: str = "claimed_only"
    transcript: str = ""
    intent: str = "read"  # "read" or "action"


@dataclass
class DocVerdict:
    doc_id: str
    title: str
    sensitivity: str
    relevance: float
    required_trust: int
    decision: str          # ALLOW / REDACT / BLOCK
    served: str            # content actually returned to the agent


@dataclass
class FirewallDecision:
    query: str
    decision: str                 # overall: ALLOW / REDACT / BLOCK
    risk_score: int               # 0-100
    effective_trust: int
    actor_name: str
    actor_role: str
    verification: str
    se_risk: int
    se_signals: list[str]
    reasons: list[str]
    docs: list[DocVerdict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


def _redact(content: str, pii: list[str]) -> str:
    out = content
    for token in pii:
        out = out.replace(token, "█" * max(4, len(token)))
    return out


class RetrievalFirewall:
    def __init__(self, kb: Optional[KnowledgeBase] = None):
        self.kb = kb or KnowledgeBase()

    def evaluate(self, req: RetrievalRequest) -> FirewallDecision:
        eff_trust, actor, factor = effective_trust(req.claimed_identity, req.verification)
        se_risk, se_signals = social_engineering_scan(req.transcript or req.query)

        reasons: list[str] = []
        if factor <= 0.15:
            reasons.append(
                f"Identity '{actor.role}' is only CLAIMED ({req.verification}); "
                f"unverified authority is discounted to {eff_trust}/100."
            )
        if se_risk >= 40:
            reasons.append(
                f"Social-engineering risk {se_risk}/100 — signals: "
                f"{', '.join(se_signals) or 'pattern match'}."
            )

        hits = self.kb.retrieve(req.query, k=4)
        doc_verdicts: list[DocVerdict] = []
        worst = "ALLOW"
        order = {"ALLOW": 0, "REDACT": 1, "BLOCK": 2}

        for doc, rel in hits:
            need = doc.required_trust
            # trust gate, hardened by social-engineering risk
            trust_after_risk = eff_trust - int(se_risk * 0.6)
            if trust_after_risk >= need:
                decision, served = "ALLOW", doc.content
            elif trust_after_risk >= need - 25 and doc.pii:
                decision, served = "REDACT", _redact(doc.content, doc.pii)
            else:
                decision, served = "BLOCK", "[withheld by Sentinel]"

            # action requests on sensitive data demand high trust regardless
            if req.intent == "action" and need >= 80 and trust_after_risk < 90:
                decision, served = "BLOCK", "[action blocked by Sentinel]"

            doc_verdicts.append(DocVerdict(
                doc.id, doc.title, doc.sensitivity, round(rel, 3),
                need, decision, served,
            ))
            if order[decision] > order[worst]:
                worst = decision

        if worst == "BLOCK" and not any(r.startswith("Identity") or r.startswith("Social") for r in reasons):
            reasons.append("Requested data sensitivity exceeds the requester's verified trust.")
        if worst == "ALLOW" and not reasons:
            reasons.append("Requester is verified and trusted for this sensitivity level.")

        risk_score = max(se_risk, max((order[d.decision] * 40 for d in doc_verdicts), default=0))

        return FirewallDecision(
            query=req.query,
            decision=worst,
            risk_score=min(risk_score, 100),
            effective_trust=eff_trust,
            actor_name=actor.name,
            actor_role=actor.role,
            verification=req.verification,
            se_risk=se_risk,
            se_signals=se_signals,
            reasons=reasons,
            docs=doc_verdicts,
        )
