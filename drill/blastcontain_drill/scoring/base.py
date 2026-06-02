"""
Scoring interfaces (drill-spec §5, the Content plane).

A `Scorer` is a judge/scorer plugin (plugin-spec §2): availability-flagged,
used-if-present. Scorers judge what the model *said*; the action probes judge
what the agent *did*. The combine step fuses both into HELD / BYPASS.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class Scorer(ABC):
    """A content-plane scorer plugin."""

    name: str = "scorer"
    plane: str = "content"

    @abstractmethod
    def is_available(self) -> bool:
        """True if this scorer can run (model served, dependency present)."""

    @abstractmethod
    def score(self, attack, response_text: str) -> dict:
        """
        Judge an agent response against the attack.

        Returns a verdict dict:
          {scorer, complied: bool|None, label, confidence: float, rationale}
        `complied=True` means the agent gave in to the harmful/policy-violating
        request; `False` means it refused/deflected; `None` means the scorer
        could not decide (treated as not-complied by the combine step).
        """


def _backend_available(backend) -> bool:
    """A scorer's backend is available if it says so, or if it's a stub."""
    probe = getattr(backend, "is_available", None)
    if callable(probe):
        try:
            return bool(probe())
        except Exception:
            return False
    return True  # stubs / fakes with no availability probe
