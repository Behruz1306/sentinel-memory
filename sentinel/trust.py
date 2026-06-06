"""The Semantic Trust Graph.

Every actor (person, role, caller) has a trust score. Crucially, trust is a
function of *verification*, not just claimed identity — that gap is exactly
how impersonation attacks are caught: claiming to be the CEO over an
unverified channel does NOT grant you the CEO's trust.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Actor:
    id: str
    name: str
    role: str
    base_trust: int  # trust IF fully verified (0-100)


# Known organizational identities and their *verified* trust ceilings.
KNOWN_ACTORS: dict[str, Actor] = {
    "ceo": Actor("ceo", "Mark Diaz", "CEO", 95),
    "finance_director": Actor("finance_director", "Sarah Chen", "Finance Director", 92),
    "ops": Actor("ops", "John Reyes", "Operations", 78),
    "employee": Actor("employee", "Generic Employee", "Employee", 65),
    "vendor": Actor("vendor", "Known Vendor", "Vendor", 45),
    "unknown": Actor("unknown", "Unknown Caller", "Unknown", 8),
}


# How much of an actor's base trust survives, given the verification channel.
# This is where impersonation dies: a *claim* over an unverified phone line
# keeps almost none of the authority it asserts.
VERIFICATION_FACTOR = {
    "cryptographic": 1.00,   # signed token / SSO session
    "callback_on_file": 0.95,  # we called the number on file back
    "internal_session": 0.9,   # authenticated app session
    "voice_known": 0.6,        # recognized voice, no second factor
    "claimed_only": 0.15,      # "this is the CEO" — just words on a call
    "spoofed_channel": 0.05,   # caller-ID/email that fails auth checks
}


def resolve_actor(claimed_identity: str) -> Actor:
    key = (claimed_identity or "").strip().lower().replace(" ", "_")
    return KNOWN_ACTORS.get(key, KNOWN_ACTORS["unknown"])


def effective_trust(claimed_identity: str, verification: str) -> tuple[int, Actor, float]:
    """Trust the requester actually earns = base_trust * verification_factor."""
    actor = resolve_actor(claimed_identity)
    factor = VERIFICATION_FACTOR.get(verification, 0.15)
    return round(actor.base_trust * factor), actor, factor
