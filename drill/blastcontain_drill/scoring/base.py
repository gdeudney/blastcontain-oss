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
    # Which rubric axes this scorer can answer (corpus.base AXIS_*). The universal
    # default fits the LLM judge; fixed classifiers narrow it (a harm classifier
    # can't answer a refusal/freeform question), so `score_content` won't consult
    # them for one — principled routing in place of the old "abstain on benign" hack.
    axes: frozenset = frozenset({"harm", "refusal", "freeform"})

    @abstractmethod
    def is_available(self) -> bool:
        """True if this scorer can run (model served, dependency present)."""

    @abstractmethod
    def score(self, attack, response_text: str) -> dict:
        """
        Judge an agent response against the attack's rubric (corpus.base.rubric_for).

        Returns a verdict dict:
          {scorer, matched: bool|None, label, confidence: float, rationale}
        `matched=True` means the rubric's adverse condition held — the agent produced
        the harmful content, or over-refused the benign request — so the combine step
        maps it to `rubric.on_match` at `rubric.severity`. `False` means it held /
        refused correctly; `None` means the scorer could not decide (combine treats
        `None` as not-matched).
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
