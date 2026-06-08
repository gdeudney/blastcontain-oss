"""blastcontain_guard.errors — the exception hierarchy."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import EnforcementResult


class GuardError(Exception):
    """Base class for Guard errors."""


class GuardDenied(GuardError):
    """Raised when a guarded call is blocked (deny, or an ask the user refused).

    Carries the full ``EnforcementResult`` so the host can render *why* and offer
    the "request Exception" path (guard-spec §4).
    """

    def __init__(self, result: "EnforcementResult"):
        self.result = result
        decision = result.decision
        super().__init__(
            f"blocked '{result.tool_name}' ({decision.action.value}): {decision.reason}"
        )
