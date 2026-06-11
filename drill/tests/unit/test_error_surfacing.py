"""Error surfacing — broken sources + crashing scorers become visible, not silently dropped (#2)."""
from __future__ import annotations

from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.corpus.base import GOAL_CONTENT, Attack, AttackSource
from blastcontain_drill.scoring import score_content


class _BrokenSource(AttackSource):
    name = "broken-source"
    layer = "replay"

    def is_available(self):
        return True

    def dataset(self, categories=None, limit=None):
        raise RuntimeError("misconfigured endpoint")


class _CrashingScorer:
    name = "boom"
    axes = frozenset({"harm", "refusal", "freeform"})

    def is_available(self):
        return True

    def score(self, attack, resp):
        raise ValueError("backend down")


def _attack():
    return Attack(id="x", category="jailbreak", prompt="p", technique="t", goal=GOAL_CONTENT)


def test_broken_source_surfaces_as_a_warning_not_silent():
    corpus = load_corpus(extra_sources=[_BrokenSource()])
    assert any("broken-source" in w for w in corpus.warnings)
    assert len(corpus.attacks) > 0           # one broken source doesn't kill the corpus


def test_crashing_scorer_becomes_an_error_verdict_not_dropped():
    _primary, all_v = score_content([_CrashingScorer()], _attack(), "resp")
    assert "error" in [v.get("label") for v in all_v]          # surfaced, not swallowed
    assert any("backend down" in (v.get("rationale") or "") for v in all_v)


def test_eligibility_skip_is_not_an_error():
    # a harm-only scorer on a refusal-axis (benign) attack is SKIPPED, not an error verdict.
    benign = Attack(id="b", category="benign", prompt="p", technique="t",
                    goal=GOAL_CONTENT, expected_refusal=False)

    class _HarmOnly:
        name = "harm-guard"
        axes = frozenset({"harm"})

        def is_available(self):
            return True

        def score(self, attack, resp):
            return {"scorer": "harm-guard", "matched": True}

    _primary, all_v = score_content([_HarmOnly()], benign, "resp")
    assert all_v == []                       # routed out by axis, no error verdict
