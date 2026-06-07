"""Action-aware retrieval orchestrator — the firewall in one call.

    execute(session, query, intent)
        1. score the session (trust_engine)
        2. use the predictive warm-cache if the query was pre-fetched
        3. rank candidate documents (graph KB)
        4. gate each document against the permission matrix -> ALLOW/REDACT/BLOCK
        5. if an action is implied, emit an executable function-call plan
           (only authorized when trust clears the action's threshold)
        6. on a financial/restricted violation: log a CloudWatch red alert and,
           if raise_on_deny, throw AccessDeniedException
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from .actions import detect_action
from .cloudwatch import security_log
from .exceptions import AccessDeniedException
from .graph_kb import KnowledgeGraph
from .moss_retriever import MossRetriever
from .predictive import PredictiveRetriever
from . import trust_engine as te


@dataclass
class DocVerdict:
    doc_id: str
    title: str
    sensitivity: str
    relevance: float
    required_trust: int
    decision: str
    served: str
    relationship: list = field(default_factory=list)


@dataclass
class RetrievalResult:
    query: str
    intent: str
    decision: str          # overall ALLOW / REDACT / BLOCK
    trust: dict
    docs: list = field(default_factory=list)
    action: Optional[dict] = None
    predictive: Optional[dict] = None
    reasons: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


_ORDER = {"ALLOW": 0, "REDACT": 1, "BLOCK": 2}


def _redact(content: str, pii: list) -> str:
    out = content
    for token in pii:
        out = out.replace(token, "█" * max(4, len(token)))
    return out


class SentinelRetriever:
    def __init__(self, kb: Optional[KnowledgeGraph] = None):
        self.kb = kb or KnowledgeGraph()
        self.moss = MossRetriever(self.kb)
        self.predictive = PredictiveRetriever(self._retrieve)

    @property
    def backend(self) -> str:
        return "moss" if self.moss.available else "local"

    def _retrieve(self, query: str, k: int = 4):
        """Relevance ranking via Moss when available, else the local index."""
        if self.moss.available:
            hits = self.moss.retrieve(query, k)
            if hits:
                return hits
        return self.kb.retrieve(query, k)

    def execute(self, session, query: str, intent: str = "read",
                *, raise_on_deny: bool = False, use_llm: bool = True) -> RetrievalResult:
        trust = te.compute_trust_score(session, use_llm=use_llm)
        reasons = list(trust.factors)

        # 1. predictive warm-cache (Moss paradigm) ------------------------
        t0 = time.time()
        entity, cached = self.predictive.cached_for(session, query)
        if cached:
            hits = cached
            predictive = {"entity": entity, "warm": True,
                          "note": f"Pre-fetched on '{entity}' before utterance finished."}
        else:
            hits = self._retrieve(query, 4)
            predictive = {"entity": None, "warm": False,
                          "note": "Cold retrieval (no entity pre-fetched)."}
        predictive["backend"] = self.backend
        predictive["lookup_ms"] = round((time.time() - t0) * 1000, 2)
        try:
            from .dashboard_bus import emit
            if predictive["warm"]:
                emit("cache_hit", entity=entity or "",
                     latency_ms=predictive["lookup_ms"])
            else:
                emit("cache_cold", latency_ms=predictive["lookup_ms"])
        except Exception:
            pass

        # 2. gate each candidate against the permission matrix ------------
        docs = []
        for doc, rel in hits:
            need = te.required_trust(doc.sensitivity)
            if trust.score > need:
                decision, served = "ALLOW", doc.content
            elif trust.score > need - 25 and doc.pii:
                decision, served = "REDACT", _redact(doc.content, doc.pii)
            else:
                decision, served = "BLOCK", "[withheld by Sentinel]"

            rel_path = (self.kb.relationship_path(session.verified_user_id, doc.id)
                        if session.verified_user_id else [])
            docs.append(DocVerdict(doc.id, doc.title, doc.sensitivity, rel,
                                   need, decision, served, rel_path))

        # Headline tracks the MOST RELEVANT document — what the agent actually
        # asked for. Lower-ranked incidental hits are still gated individually
        # in their own verdicts (a blocked financial doc stays withheld even if
        # the headline is ALLOW).
        overall = docs[0].decision if docs else "ALLOW"
        primary_block = None
        if docs and docs[0].decision == "BLOCK":
            top = hits[0][0]
            primary_block = (top, te.required_trust(top.sensitivity))

        # 3. action-aware workflow ---------------------------------------
        action = None
        plan = detect_action(session.full_context() or query) if intent in ("read", "action") else None
        if plan:
            authorized = trust.score >= plan.min_trust
            action = plan.to_dict()
            action["authorized"] = authorized
            if authorized:
                reasons.append(
                    f"Action '{plan.name}' AUTHORIZED (trust {trust.score} ≥ {plan.min_trust}); "
                    f"executable workflow emitted."
                )
            else:
                reasons.append(
                    f"Action '{plan.name}' BLOCKED (trust {trust.score} < {plan.min_trust})."
                )
                if _ORDER["BLOCK"] > _ORDER[overall]:
                    overall = "BLOCK"

        # 4. breach logging + optional exception --------------------------
        if overall == "BLOCK":
            target, need = primary_block if primary_block else (None, 90)
            if (target and target.sensitivity in ("FINANCIAL", "RESTRICTED")) or \
               (plan and not action.get("authorized") and plan.min_trust >= 90):
                breach = {
                    "session_id": session.session_id, "caller_id": session.caller_id,
                    "claimed_identity": session.claimed_identity, "origin": session.origin,
                    "origin_ip": session.origin_ip, "session_trust": trust.score,
                    "se_risk": trust.se_risk, "se_signals": trust.se_signals,
                    "voice_anomaly": session.voice_anomaly,
                    "target": target.id if target else (plan.name if plan else "unknown"),
                }
                security_log.breach(
                    f"Blocked sensitive request — trust {trust.score} insufficient "
                    f"(caller claimed '{session.claimed_identity}' via {session.origin}).",
                    **breach,
                )
                if raise_on_deny:
                    raise AccessDeniedException(
                        f"Access denied: session trust {trust.score} insufficient for request.",
                        breach=breach,
                    )

        result = RetrievalResult(
            query=query, intent=intent, decision=overall,
            trust=asdict(trust), docs=[asdict(d) for d in docs],
            action=action, predictive=predictive, reasons=reasons,
        )
        self._push_dashboard(session, query, trust, overall, predictive)
        return result

    def _push_dashboard(self, session, query: str, trust, decision: str,
                        predictive: dict) -> None:
        """Pipe live trust / threat / latency / verdict to the dashboard server."""
        try:
            from .dashboard_bus import push_dashboard_update
            threat = trust.threat or {}
            sem = threat.get("semantic") or {}
            threat_match = ""
            if sem.get("signature_id"):
                sim = round(float(sem.get("score", 0)) * 100, 1)
                threat_match = f"{sem.get('signature_id')} ({sim}% similarity)"
            elif threat.get("attack_type") and threat.get("attack_type") != "none":
                threat_match = str(threat.get("attack_type"))
            uncertainty = min(100, int(trust.se_risk + session.voice_anomaly * 20))
            push_dashboard_update({
                "session_id": session.session_id,
                "transcript": session.full_context() or query,
                "query": query,
                "trust_score": trust.score,
                "se_risk": trust.se_risk,
                "uncertainty": uncertainty,
                "verdict": decision,
                "decision": decision,
                "threat_match": threat_match or None,
                "response_latency_ms": predictive.get("lookup_ms"),
                "cache_status": "warmed" if predictive.get("warm") else "cold",
                "prefetch_entity": predictive.get("entity"),
                "alert": (f"🚨 RED ALERT: Access Denied — {query[:72]}"
                          if decision == "BLOCK" else None),
            })
        except Exception:
            pass
