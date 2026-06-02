"""Generative layer — a local jailbreak-discovery loop (drill-spec §4.1, step 7)."""
from __future__ import annotations

from .attacker import Attacker, Attempt, LLMAttacker, StubAttacker
from .goals import DEFAULT_GOALS, Goal, goals_for
from .loop import GenerativeResult, run_generative

__all__ = [
    "Attacker", "Attempt", "LLMAttacker", "StubAttacker",
    "Goal", "DEFAULT_GOALS", "goals_for",
    "GenerativeResult", "run_generative",
]
