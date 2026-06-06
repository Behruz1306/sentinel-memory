"""Action-Aware Workflows.

Beyond facts, Sentinel retrieves *intent + executable workflow*. When an
authorized request implies an action ("book our preferred carrier"), the
retriever returns a function-call metadata object the agent can execute —
turning retrieval into the foundation for autonomous execution.

Actions inherit the same trust gate as data: high-impact actions require high
SessionTrustScore, enforced by the retriever before the call object is emitted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ActionPlan:
    name: str
    description: str
    arguments: dict
    endpoint: str
    method: str = "POST"
    min_trust: int = 90            # default: high-impact actions need high trust
    context_docs: list = field(default_factory=list)  # supporting doc ids

    def to_dict(self) -> dict:
        return {
            "type": "function_call",
            "name": self.name,
            "description": self.description,
            "arguments": self.arguments,
            "endpoint": self.endpoint,
            "method": self.method,
            "min_trust": self.min_trust,
            "context_docs": self.context_docs,
        }


# Intent patterns -> action templates.
_ACTIONS = [
    {
        "pattern": r"\b(book|dispatch|assign)\b.*\b(carrier|load|truck)\b",
        "name": "book_carrier",
        "description": "Book the preferred carrier on a load and update the TMS.",
        "endpoint": "/tms/bookings",
        "min_trust": 70,
        "args": lambda t: {
            "carrier": "Blue Freight LLC",
            "mc": "MC-884213",
            "rate_per_mile": 2.18,
            "insurance_verified": True,
        },
        "context": ["doc:carrier-blue", "doc:contract-blue"],
    },
    {
        "pattern": r"\b(pay|wire|remit|send (the )?payment)\b.*\b(invoice|vendor|carrier)\b",
        "name": "issue_payment",
        "description": "Issue payment against an invoice. High-impact financial action.",
        "endpoint": "/finance/payments",
        "min_trust": 95,
        "args": lambda t: {"invoice": "4471", "amount": 48200, "currency": "USD"},
        "context": ["doc:invoice-4471", "doc:bank-change"],
    },
    {
        "pattern": r"\b(change|update)\b.*\b(bank|routing|account)\b",
        "name": "change_vendor_bank",
        "description": "Change a vendor's banking details. Requires dual approval.",
        "endpoint": "/finance/vendors/bank",
        "min_trust": 99,  # effectively requires verified CEO+Finance; demo blocks this
        "args": lambda t: {"vendor": "Blue Freight LLC", "requires_dual_approval": True},
        "context": ["doc:bank-change"],
    },
]


def detect_action(text: str):
    """Return an ActionPlan if the utterance implies an executable workflow."""
    t = (text or "").lower()
    for spec in _ACTIONS:
        if re.search(spec["pattern"], t):
            return ActionPlan(
                name=spec["name"],
                description=spec["description"],
                arguments=spec["args"](t),
                endpoint=spec["endpoint"],
                min_trust=spec["min_trust"],
                context_docs=spec["context"],
            )
    return None
