"""Sentinel exceptions."""

from __future__ import annotations


class SentinelError(Exception):
    """Base class for all Sentinel errors."""


class AccessDeniedException(SentinelError):
    """Raised when a retrieval/action request violates the trust policy.

    Carries the structured breach context so the middleware can log a red alert
    to CloudWatch and surface a clean denial to the agent.
    """

    def __init__(self, message: str, *, breach: dict | None = None):
        super().__init__(message)
        self.breach = breach or {}
