"""Sentinel Workspace — multi-turn real conversations with full persistence."""

from __future__ import annotations

import os
import re
import time
from typing import Optional

from . import persistence as store
from .company_kb import registry as kb_registry
from .company_pack import get_pack, resolve_company, list_packs, ACME_LOGISTICS
from .session import SessionState, sessions
from .threat_memory import threat_memory


def _cloud_deploy() -> bool:
    return os.getenv("RENDER") == "true" or os.getenv("SENTINEL_CLOUD_DEPLOY") == "1"


def _company_meta(company_id: str) -> dict:
    return resolve_company(company_id) or (get_pack(company_id) or ACME_LOGISTICS).to_dict()


def _infer_identity(message: str, company_id: str) -> dict:
    meta = _company_meta(company_id)
    employees = meta.get("employees") or []
    text = message.lower()
    out = {
        "caller_name": "", "claimed_identity": "guest",
        "verification": "claimed_only", "origin": "unknown",
        "voice_anomaly": 0.0, "verified_user_id": None,
    }
    for emp in employees:
        name = emp.get("name", "") if isinstance(emp, dict) else emp.name
        email = emp.get("email", "") if isinstance(emp, dict) else emp.email
        role_key = emp.get("role_key", "guest") if isinstance(emp, dict) else emp.role_key
        eid = emp.get("id", "") if isinstance(emp, dict) else emp.id
        if name.lower() in text or email.lower() in text:
            out["caller_name"] = name
            out["claimed_identity"] = role_key
            break
    if re.search(r"\b(sso|corporate login|authenticated|verified|hospital sso)\b", text):
        out["verification"] = "cryptographic"
        out["origin"] = "corporate_sso"
        for emp in employees:
            name = emp.get("name", "") if isinstance(emp, dict) else emp.name
            eid = emp.get("id", "") if isinstance(emp, dict) else emp.id
            if name.lower() in text:
                out["verified_user_id"] = eid
    if re.search(r"\b(board|urgent|immediately|personal gmail|wire|routing|gmail\.com)\b", text):
        if out["verification"] == "claimed_only":
            out["origin"] = "spoofed" if "gmail" in text or "personal" in text else "foreign"
    if re.search(r"\b(deepfake|synthetic|cloned voice)\b", text):
        out["voice_anomaly"] = 0.9
    return out


_SENSITIVE_RE = re.compile(
    r"\b(payroll|salary|bank|routing|wire|ssn|social security|patient record|"
    r"chart|diagnosis|financial|confidential|password|account number)\b", re.I,
)


def _sensitive_request(message: str) -> bool:
    return bool(_SENSITIVE_RE.search(message or ""))


def _user_turn_count(rec: dict) -> int:
    return sum(1 for t in (rec.get("turns") or []) if t.get("role") == "user")


def _phone_dialogue(verdict: str, turn_num: int, trust: dict, analysis: dict,
                    message: str) -> tuple[str, str, bool]:
    """Natural phone conversation — defer hard reject/accept until enough dialogue."""
    trust_score = int(trust.get("score") or 0)
    ctx = {
        "docs": analysis.get("docs"),
        "action": analysis.get("action"),
        "trust_score": trust_score,
        "threat_match": analysis.get("threat_match"),
    }
    sensitive = _sensitive_request(message)
    threat = bool(analysis.get("threat_match"))

    final = (
        turn_num >= 4
        or (turn_num >= 3 and sensitive and verdict in ("BLOCK", "ALLOW", "REDACT"))
        or (turn_num >= 3 and verdict == "BLOCK" and trust_score < 30)
        or (turn_num >= 2 and verdict == "BLOCK" and threat and trust_score < 40)
        or (verdict == "ALLOW" and trust_score >= 75 and sensitive)
    )

    if not final:
        if turn_num <= 1:
            return (
                "Thank you for calling. I'd be happy to help. "
                "Could you tell me your full name and which department you're calling from?",
                "LISTENING", False,
            )
        if turn_num == 2:
            return (
                "I appreciate that. I can help with shipments, vendor accounts, "
                "and internal documents. What would you like to look up today? "
                "If this involves payroll or financial records, I may need extra verification.",
                "LISTENING", False,
            )
        if verdict == "BLOCK":
            return (
                "I understand. Before I can share anything sensitive, "
                "I need to build a clearer picture of your request and verify your identity. "
                "Can you explain why this is urgent, and whether you can use our standard approval process?",
                "REVIEW", False,
            )
        if verdict == "REDACT":
            return (
                "I may be able to share a summary with some details withheld. "
                "Could you be more specific about exactly what you need?",
                "REVIEW", False,
            )
        return (
            _agent_reply(verdict, ctx, message) + " What else can I help you with?",
            "LISTENING", False,
        )

    if verdict == "BLOCK":
        return (
            "I've now completed my full security review. "
            "Unfortunately I cannot approve access to the sensitive information you requested — "
            f"your session trust score is {trust_score} out of 100, which is below our threshold. "
            "Please contact IT security or use the verified channel on file.",
            "BLOCK", True,
        )
    if verdict == "REDACT":
        base = _agent_reply(verdict, ctx, message)
        return (
            f"After review, I can share a limited version. {base}",
            "REDACT", True,
        )
    base = _agent_reply(verdict, ctx, message)
    return (
        f"Good news — after our conversation I've verified enough trust to proceed. {base}",
        "ALLOW", True,
    )


def _agent_reply(verdict: str, analysis: dict, message: str) -> str:
    action = (analysis.get("action") or {})
    if verdict == "BLOCK":
        parts = ["I can't help with that request without proper verification."]
        if analysis.get("threat_match"):
            parts.append(f"Our security layer flagged this pattern ({analysis['threat_match']}).")
        if action and not action.get("authorized"):
            parts.append(
                f"The requested action '{action.get('name', 'workflow')}' is not authorized "
                f"at your current trust level."
            )
        parts.append("Please use the official verification channel on file.")
        return " ".join(parts)
    if verdict == "REDACT":
        docs = analysis.get("docs") or []
        titles = ", ".join(d.get("title", "") for d in docs[:2] if d.get("decision") != "BLOCK")
        return (
            f"I can share a redacted summary{f' on {titles}' if titles else ''}. "
            "Some fields are withheld until your identity is fully verified."
        )
    docs = [d for d in (analysis.get("docs") or []) if d.get("decision") == "ALLOW"]
    if docs:
        return (
            f"I've retrieved {docs[0].get('title', 'the requested document')} "
            f"under your current trust level ({analysis.get('trust_score', 0)}). "
            "How would you like me to proceed?"
        )
    return "I understand. Could you clarify what specific information you need?"


class Workspace:
    def __init__(self, retriever):
        self.retriever = retriever

    def create_session(self, *, company_id: str = "acme-logistics", channel: str = "chat",
                       user_id: str = "", caller_name: str = "", claimed_identity: str = "guest",
                       verification: str = "claimed_only", origin: str = "unknown",
                       voice_anomaly: float = 0.0, verified_user_id: Optional[str] = None,
                       meta: Optional[dict] = None) -> dict:
        sid = store.create_session(
            company_id=company_id, channel=channel, user_id=user_id,
            caller_name=caller_name, claimed_identity=claimed_identity,
            verification=verification, origin=origin, voice_anomaly=voice_anomaly, meta=meta,
        )
        sessions.open(
            sid, caller_id=sid, claimed_identity=claimed_identity,
            verified_user_id=verified_user_id, verification=verification,
            origin=origin, voice_anomaly=voice_anomaly,
        )
        return {
            "session_id": sid,
            "company": _company_meta(company_id),
            "kb": kb_registry.stats(company_id),
        }

    def send_message(self, session_id: str, message: str, *,
                     persona: Optional[dict] = None) -> dict:
        rec = store.get_session(session_id)
        if not rec:
            return {"error": "session not found"}

        company_id = rec["company_id"]
        kb = kb_registry.get(company_id)

        state = sessions.get(session_id) or sessions.open(
            session_id, caller_id=session_id,
            claimed_identity=rec["claimed_identity"],
            verification=rec["verification"], origin=rec["origin"],
            voice_anomaly=rec["voice_anomaly"],
        )

        inferred = _infer_identity(message, company_id)
        if persona:
            for k in ("caller_name", "claimed_identity", "verification",
                      "origin", "voice_anomaly", "verified_user_id"):
                if k in persona and persona[k] is not None:
                    inferred[k] = persona[k]

        state.claimed_identity = inferred["claimed_identity"]
        state.verification = inferred["verification"]
        state.origin = inferred["origin"]
        state.voice_anomaly = float(inferred.get("voice_anomaly") or 0)
        if inferred.get("verified_user_id"):
            state.verified_user_id = inferred["verified_user_id"]
        if inferred.get("caller_name"):
            state.caller_id = inferred["caller_name"]

        state.commit_final(message)
        store.add_turn(session_id, role="user", content=message)
        turn_num = _user_turn_count(store.get_session(session_id) or rec)
        is_phone = rec.get("channel") == "phone"

        use_llm = not _cloud_deploy()
        result = self.retriever.execute(
            state, message, intent="action", raise_on_deny=False,
            use_llm=use_llm, kb=kb,
        )
        analysis = result.to_dict()
        verdict = result.decision
        trust = result.trust

        threat_match = ""
        sem = (trust.get("threat") or {}).get("semantic") or {}
        if sem.get("signature_id"):
            sim = round(float(sem.get("score", 0)) * 100, 1)
            threat_match = f"{sem.get('signature_id')} ({sim}%)"
        elif trust.get("threat", {}).get("attack_type", "none") != "none":
            threat_match = str(trust["threat"].get("attack_type"))

        if verdict == "BLOCK" and trust.get("se_risk", 0) >= 50:
            learned = threat_memory.learn(
                message,
                attack_type=trust.get("threat", {}).get("attack_type", "social engineering"),
                tactic="workspace_conversation",
                severity=min(95, int(trust.get("se_risk", 70))),
            )
            store.log_activity(
                "immune_learn", "Immune system learned attack signature (+1)",
                session_id=session_id,
                detail={"signature_id": learned.get("signature_id"), "text_preview": message[:80]},
            )

        phone_final = False
        phone_verdict = verdict
        if is_phone:
            reply, phone_verdict, phone_final = _phone_dialogue(
                verdict, turn_num, trust, {
                    "docs": analysis.get("docs"),
                    "action": analysis.get("action"),
                    "threat_match": threat_match,
                }, message,
            )
        else:
            reply = _agent_reply(verdict, {
                "docs": analysis.get("docs"),
                "action": analysis.get("action"),
                "trust_score": trust.get("score"),
                "threat_match": threat_match,
            }, message)

        turn_analysis = {
            "verdict": verdict, "trust": trust, "docs": analysis.get("docs"),
            "action": analysis.get("action"), "predictive": analysis.get("predictive"),
            "reasons": analysis.get("reasons"), "threat_match": threat_match,
            "naive_leak": _naive_preview(message, kb),
            "phone_verdict": phone_verdict if is_phone else None,
            "phone_final": phone_final if is_phone else None,
            "phone_turn": turn_num if is_phone else None,
        }
        store.add_turn(
            session_id, role="assistant", content=reply,
            verdict=verdict if (not is_phone or phone_final) else phone_verdict,
            trust_score=trust.get("score", 0),
            analysis=turn_analysis,
        )
        act_kind = f"verdict_{verdict.lower()}"
        act_summary = f"{verdict} — trust {trust.get('score')} — {message[:60]}…"
        if is_phone and not phone_final:
            act_kind = "phone_dialogue"
            act_summary = f"Phone turn {turn_num} ({phone_verdict}) — trust {trust.get('score')} — {message[:50]}…"
        store.log_activity(
            act_kind, act_summary,
            session_id=session_id,
            detail={
                "verdict": verdict, "phone_verdict": phone_verdict,
                "phone_final": phone_final, "trust": trust.get("score"),
                "threat": threat_match,
            },
        )

        try:
            from .dashboard_bus import push_dashboard_update
            push_dashboard_update({
                "session_id": session_id,
                "transcript": state.full_context(),
                "query": message,
                "trust_score": trust.get("score"),
                "se_risk": trust.get("se_risk"),
                "verdict": phone_verdict if is_phone else verdict,
                "decision": verdict,
                "threat_match": threat_match or None,
                "channel": rec.get("channel"),
                "phone_final": phone_final,
            })
        except Exception:
            pass

        return {
            "session_id": session_id,
            "message": message,
            "reply": reply,
            "verdict": verdict,
            "trust_score": trust.get("score"),
            "phone_verdict": phone_verdict if is_phone else None,
            "phone_final": phone_final if is_phone else None,
            "phone_turn": turn_num if is_phone else None,
            "analysis": turn_analysis,
            "transcript": state.full_context(),
            "timeline": _build_timeline(store.get_session(session_id) or rec),
        }

    def report(self, session_id: str) -> dict:
        rec = store.get_session(session_id)
        if not rec:
            return {"error": "session not found"}
        blocks = sum(1 for t in rec["turns"] if t.get("verdict") == "BLOCK")
        allows = sum(1 for t in rec["turns"] if t.get("verdict") == "ALLOW")
        return {
            "session": rec,
            "company": _company_meta(rec["company_id"]),
            "summary": {
                "turns": len(rec["turns"]),
                "blocks": blocks,
                "allows": allows,
                "final_trust": rec["trust_score"],
                "generated_at": time.time(),
            },
        }


def _naive_preview(query: str, kb) -> list:
    hits = kb.retrieve(query, 3) or []
    return [
        {"title": d.title, "sensitivity": d.sensitivity,
         "would_leak": d.sensitivity in ("FINANCIAL", "RESTRICTED", "CONFIDENTIAL")}
        for d, _ in hits
    ]


def _build_timeline(rec: dict) -> list:
    timeline = []
    for t in rec.get("turns") or []:
        timeline.append({
            "role": t.get("role"),
            "content": (t.get("content") or "")[:120],
            "verdict": t.get("verdict"),
            "trust_score": t.get("trust_score"),
            "created_at": t.get("created_at"),
        })
    return timeline


def upload_company(name: str, payload: dict) -> dict:
    uid = store.save_company_upload(name, payload)
    kb = kb_registry.load_upload(uid, payload)
    return {
        "upload_id": uid, "company_id": uid, "name": name,
        "employees": len(payload.get("employees", [])),
        "documents": len(kb.docs),
        "kb": kb.stats(),
    }


def ingest_pdf(company_id: str, path: str, *, title: str, sensitivity: str) -> dict:
    n = kb_registry.ingest_pdf(company_id, path, title=title, sensitivity=sensitivity)
    store.log_activity(
        "pdf_ingest", f"Ingested PDF '{title}' ({n} chunks) into {company_id}",
        detail={"company_id": company_id, "chunks": n},
    )
    return {"chunks": n, "company_id": company_id, "kb": kb_registry.stats(company_id)}
