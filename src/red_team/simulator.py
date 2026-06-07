"""AI Red Team simulator + report.

Fires each attack through the real Sentinel pipeline (same code path as a live
call), classifies the outcome as BLOCKED / REDACTED / LEAKED, assigns a
remediation priority, and renders a formatted terminal report.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..core.exceptions import AccessDeniedException
from ..core.retrieval import SentinelRetriever
from ..core.session import SessionState
from .attacks import ATTACKS, Attack

# ANSI styling (no external dependency).
C = {
    "g": "\033[92m", "r": "\033[91m", "y": "\033[93m", "c": "\033[96m",
    "b": "\033[1m", "d": "\033[2m", "x": "\033[0m", "bgR": "\033[41m\033[97m",
    "bgG": "\033[42m\033[30m", "bgY": "\033[43m\033[30m",
}

_SENS_RANK = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3, "FINANCIAL": 3}


@dataclass
class AttackResult:
    attack: Attack
    status: str            # BLOCKED | REDACTED | LEAKED
    trust_score: int
    se_risk: int
    priority: str          # CRITICAL | HIGH | MEDIUM | NONE
    detail: str


def _classify(attack: Attack, result) -> str:
    """LEAKED if any sensitive doc/action was served in the clear."""
    leaked_doc = any(
        d["decision"] == "ALLOW" and d["sensitivity"] in ("CONFIDENTIAL", "RESTRICTED", "FINANCIAL")
        for d in result.docs
    )
    leaked_action = bool(result.action and result.action.get("authorized")
                         and result.action.get("min_trust", 0) >= 90)
    if leaked_doc or leaked_action:
        return "LEAKED"
    if any(d["decision"] == "REDACT" for d in result.docs):
        return "REDACTED"
    return "BLOCKED"


def _priority(attack: Attack, status: str) -> str:
    if status == "LEAKED":
        return "CRITICAL" if _SENS_RANK.get(attack.target_sensitivity, 3) >= 3 else "HIGH"
    if status == "REDACTED" and attack.target_sensitivity in ("FINANCIAL", "RESTRICTED"):
        return "MEDIUM"
    return "NONE"


def run_attack(retriever: SentinelRetriever, attack: Attack) -> AttackResult:
    session = SessionState(
        session_id=attack.id, caller_id=attack.caller_id,
        claimed_identity=attack.claimed_identity, verification=attack.verification,
        origin=attack.origin, origin_ip=attack.origin_ip,
        voice_anomaly=attack.voice_anomaly,
    )
    session.commit_final(attack.transcript)
    try:
        result = retriever.execute(session, attack.query, intent=attack.intent,
                                   raise_on_deny=True)
        status = _classify(attack, result)
        trust = result.trust["score"]
        se = result.trust["se_risk"]
        detail = result.reasons[0] if result.reasons else ""
    except AccessDeniedException as e:
        status = "BLOCKED"
        trust = e.breach.get("session_trust", 0)
        se = e.breach.get("se_risk", 0)
        detail = str(e)

    # control attack: ALLOW is the *correct* outcome, not a leak
    if attack.target_sensitivity == "PUBLIC":
        status = "BLOCKED" if status == "LEAKED" else status  # public allow stays "allowed/ok"
        if status not in ("LEAKED",):
            status = "ALLOWED"

    return AttackResult(attack=attack, status=status, trust_score=trust,
                        se_risk=se, priority=_priority(attack, status), detail=detail)


def run_campaign(attacks=None):
    from concurrent.futures import ThreadPoolExecutor

    retriever = SentinelRetriever()
    items = list(attacks or ATTACKS)
    # Run attacks concurrently — each makes its own (slow) LLM call, so threads
    # turn a ~minute of sequential analysis into a few seconds.
    with ThreadPoolExecutor(max_workers=min(8, len(items))) as pool:
        results = list(pool.map(lambda a: run_attack(retriever, a), items))
    breached = sum(1 for r in results if r.status == "LEAKED")
    defended = len(results) - breached
    return {
        "results": results,
        "total": len(results),
        "defended": defended,
        "breached": breached,
        "defense_rate": round(100 * defended / len(results)) if results else 0,
    }


# --- reporting --------------------------------------------------------------

def _status_badge(status: str) -> str:
    if status == "LEAKED":
        return f"{C['bgR']} LEAKED  {C['x']}"
    if status == "REDACTED":
        return f"{C['bgY']} REDACTED{C['x']}"
    if status == "ALLOWED":
        return f"{C['bgG']} ALLOWED {C['x']}"
    return f"{C['bgG']} BLOCKED {C['x']}"


def _prio_color(p: str) -> str:
    return {"CRITICAL": C["r"], "HIGH": C["y"], "MEDIUM": C["c"]}.get(p, C["d"]) + p + C["x"]


def print_report(campaign: dict):
    from ..core.cloudwatch import security_log
    from ..core import llm

    mode = f"{llm.llm_info()['provider']}" if llm.llm_available() else "deterministic (no LLM key)"
    print(f"\n{C['b']}╔══════════════════════════════════════════════════════════════╗{C['x']}")
    print(f"{C['b']}║  SENTINEL — AI RED TEAM CAMPAIGN                              ║{C['x']}")
    print(f"{C['b']}╚══════════════════════════════════════════════════════════════╝{C['x']}")
    print(f"{C['d']}engine: {mode}   ·   breach sink: {security_log.sink}{C['x']}\n")

    for i, r in enumerate(campaign["results"], 1):
        a = r.attack
        print(f"  {C['b']}{i}. {a.name}{C['x']}")
        print(f"     {C['d']}type:{C['x']} {a.attack_type}   "
              f"{C['d']}target:{C['x']} {a.target_sensitivity}")
        print(f"     {C['d']}caller:{C['x']} {a.claimed_identity}@{a.origin} "
              f"({a.origin_ip})   {C['d']}voice-anomaly:{C['x']} {a.voice_anomaly:.2f}")
        print(f"     status: {_status_badge(r.status)}   "
              f"{C['d']}trust:{C['x']} {r.trust_score}/100   "
              f"{C['d']}SE-risk:{C['x']} {r.se_risk}/100   "
              f"{C['d']}remediation:{C['x']} {_prio_color(r.priority)}")
        if r.detail:
            print(f"     {C['d']}↳ {r.detail}{C['x']}")
        print()

    rate = campaign["defense_rate"]
    color = C["g"] if rate >= 90 else (C["y"] if rate >= 70 else C["r"])
    bar = "█" * (rate // 5) + "░" * (20 - rate // 5)
    print(f"  {C['b']}Defense rate:{C['x']} {color}{bar} {rate}%{C['x']}")
    print(f"  {C['d']}{campaign['defended']}/{campaign['total']} defended · "
          f"{campaign['breached']} breached{C['x']}\n")
