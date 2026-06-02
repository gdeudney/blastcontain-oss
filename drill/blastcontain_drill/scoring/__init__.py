"""Scoring — content scorers (plugins) + the content/action combine."""
from __future__ import annotations

from .base import Scorer
from .combine import combine
from .granite import GraniteGuardianScorer
from .guard import Qwen3GuardScorer
from .heuristic import HeuristicContentScorer
from .judge import LLMJudge

__all__ = [
    "Scorer", "HeuristicContentScorer", "LLMJudge",
    "Qwen3GuardScorer", "GraniteGuardianScorer", "make_guard_scorer",
    "combine", "score_content",
]


def make_guard_scorer(backend, model_id: str) -> Scorer:
    """
    Pick the guard scorer for a guard model id. New guard families register here
    (the guard layer is pluggable per drill-spec / data-trust). Defaults to
    Qwen3Guard for unrecognised ids.
    """
    low = (model_id or "").lower()
    if "granite" in low and "guardian" in low:
        return GraniteGuardianScorer(backend, model_id)
    return Qwen3GuardScorer(backend, model_id)


def score_content(scorers: list[Scorer], attack, response_text: str):
    """
    Run the available content scorers and pick the primary verdict.

    `scorers` is in **authority order** (e.g. [judge, guard, heuristic]). The
    primary is the highest-authority scorer that returns a *definite* comply/
    refuse verdict; a weak fallback (the heuristic) decides only when no stronger
    scorer did. This stops a lenient or contaminated scorer from overriding a more
    reliable one. Returns (primary_verdict, all_verdicts).
    """
    verdicts = []
    for s in scorers:
        try:
            if not s.is_available():
                continue
            verdicts.append(s.score(attack, response_text))
        except Exception:
            continue
    if not verdicts:
        return None, []
    for verdict in verdicts:
        if verdict.get("complied") is not None:
            return verdict, verdicts
    return verdicts[0], verdicts
