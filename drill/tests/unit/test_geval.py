"""
DeepEval G-Eval judge — availability gating + graceful fallback.

deepeval is an opt-in extra ([judge]/[full]); these tests run with it ABSENT (like
the WildGuard tests) and assert the scorer degrades cleanly rather than crashing.
"""
from __future__ import annotations

from blastcontain_drill.corpus.base import GOAL_CONTENT, Attack
from blastcontain_drill.scoring import GEvalJudge, LLMJudge, make_judge
from blastcontain_drill.scoring.geval import _geval_cls


class _FakeBackend:
    model = "qwen-judge"

    def is_available(self):
        return True

    def chat(self, messages, **kw):
        return '{"answer":"yes"}'


def _attack():
    return Attack(id="x", category="jailbreak", prompt="p", technique="t", goal=GOAL_CONTENT)


def test_geval_is_a_universal_judge():
    # Same axes as the built-in judge — answers harm / over-refusal / freeform rubrics.
    assert GEvalJudge(_FakeBackend()).axes == frozenset({"harm", "refusal", "freeform"})


def test_geval_unavailable_without_deepeval():
    if _geval_cls() is not None:
        return  # deepeval happens to be installed — skip the "absent" path
    j = GEvalJudge(_FakeBackend())
    assert j.is_available() is False
    v = j.score(_attack(), "here you go")
    assert v["matched"] is None and v["scorer"] == "g-eval"   # graceful, not a crash


def test_make_judge_defaults_to_llm():
    assert isinstance(make_judge(_FakeBackend(), "qwen-judge", "llm"), LLMJudge)


def test_make_judge_geval_falls_back_when_unavailable():
    # Requesting geval when deepeval is absent must NOT break — fall back to LLMJudge.
    j = make_judge(_FakeBackend(), "qwen-judge", "geval")
    if _geval_cls() is None:
        assert isinstance(j, LLMJudge)
    else:
        assert isinstance(j, (GEvalJudge, LLMJudge))
