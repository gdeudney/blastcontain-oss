"""Scoring — content scorers (plugins) + the content/action combine."""
from __future__ import annotations

from ..corpus.base import rubric_for
from .base import Scorer
from .combine import combine
from .geval import GEvalJudge
from .granite import GraniteGuardianScorer
from .guard import Qwen3GuardScorer
from .heuristic import HeuristicContentScorer
from .judge import LLMJudge
from .wildguard import WildGuardScorer

_ALL_AXES = frozenset({"harm", "refusal", "freeform"})

__all__ = [
    "Scorer", "HeuristicContentScorer", "LLMJudge", "GEvalJudge",
    "Qwen3GuardScorer", "GraniteGuardianScorer", "WildGuardScorer",
    "make_guard_scorer", "make_judge", "combine", "score_content",
]


def make_guard_scorer(backend, model_id: str) -> Scorer:
    """
    Pick the guard scorer for a guard model id. New guard families register here
    (the guard layer is pluggable per drill-spec / data-trust). Defaults to
    Qwen3Guard for unrecognised ids.
    """
    low = (model_id or "").lower()
    if "wildguard" in low:
        return WildGuardScorer(backend, model_id)
    if "granite" in low and "guardian" in low:
        return GraniteGuardianScorer(backend, model_id)
    return Qwen3GuardScorer(backend, model_id)


def make_judge(backend, model_id=None, kind: str = "llm") -> Scorer:
    """
    Pick the judge scorer. `kind="geval"` selects the DeepEval G-Eval judge when
    deepeval is installed (it reuses this same local `backend`); otherwise — or for
    the default `kind="llm"` — the built-in LLMJudge. Both are universal (answer
    every rubric axis), so either covers harm / over-refusal / freeform.
    """
    if (kind or "").lower() in ("geval", "g-eval", "deepeval"):
        geval = GEvalJudge(backend, model_id)
        if geval.is_available():
            return geval
    return LLMJudge(backend, model_id)


def score_content(scorers: list[Scorer], attack, response_text: str):
    """
    Run the eligible content scorers and pick the primary verdict.

    Two gates, in order:
      1. **Eligibility** — a scorer is consulted only if it answers the attack's
         rubric axis (`rubric.axis in scorer.axes`). A fixed harm classifier is not
         asked a refusal/freeform question; this *replaces* the old "guard abstains
         on benign" hack with principled routing.
      2. **Authority** — `scorers` is in authority order (e.g. [judge, guard,
         heuristic]); the primary is the highest-authority eligible scorer that
         returns a *definite* `matched` (not None). A weak fallback (the heuristic)
         decides only when no stronger scorer did, so it can't override a better one.

    Returns (primary_verdict, all_verdicts).
    """
    axis = rubric_for(attack).axis
    verdicts = []
    for s in scorers:
        try:
            if axis not in getattr(s, "axes", _ALL_AXES):
                continue
            if not s.is_available():
                continue
            verdicts.append(s.score(attack, response_text))
        except Exception:
            continue
    if not verdicts:
        return None, []
    for verdict in verdicts:
        if verdict.get("matched") is not None:
            return verdict, verdicts
    return verdicts[0], verdicts
