"""Jailbreak-study leaderboard helpers (model-free)."""
from __future__ import annotations

from blastcontain_drill.jailbreak_study import (
    build_leaderboard,
    render_leaderboard_md,
    summarize_study,
)


class _Status:
    def __init__(self, value):
        self.value = value


class _Finding:
    def __init__(self, layer="replay"):
        self.layer = layer


class _Report:
    """Minimal stand-in exposing the DrillReport surface summarize_study reads."""

    def __init__(self, held=0, bypass_layers=(), critical=0, over_refusals=0,
                 errors=0, status="PASSED"):
        self.held = [object()] * held
        self.bypasses = [_Finding(layer) for layer in bypass_layers]
        self.critical_bypasses = [object()] * critical
        self.over_refusals = [object()] * over_refusals
        self.errors = [object()] * errors
        self.status = _Status(status)
        self.findings = self.held + self.bypasses + self.over_refusals + self.errors


def test_summarize_resistance_and_generative_count():
    r = _Report(held=8, bypass_layers=("replay", "generative", "generative"), critical=1,
                over_refusals=2, status="PARTIAL")
    s = summarize_study("qwen/qwen3.6-27b", r)
    assert s["held"] == 8 and s["bypasses"] == 3 and s["critical"] == 1
    assert s["generative_bypasses"] == 2          # only the layer=="generative" bypasses
    assert s["over_refusals"] == 2
    assert s["resistance"] == round(8 / 11, 3)    # held / (held + bypass)


def test_summarize_perfect_resistance_when_nothing_bypasses():
    s = summarize_study("m", _Report(held=10, bypass_layers=()))
    assert s["resistance"] == 1.0 and s["generative_bypasses"] == 0


def test_summarize_handles_failed_run():
    s = summarize_study("m", None)
    assert s["status"] == "ERROR" and s["resistance"] == 0.0


def test_build_leaderboard_ranks_most_robust_first():
    weak = _Report(held=2, bypass_layers=("replay",) * 8, critical=3)    # resistance 0.2
    strong = _Report(held=9, bypass_layers=("generative",))             # resistance 0.9
    rows = build_leaderboard([("weak", weak), ("strong", strong), ("broke", None)])
    assert [r["model"] for r in rows] == ["strong", "weak", "broke"]
    assert rows[0]["rank"] == 1 and rows[-1]["status"] == "ERROR"


def test_render_leaderboard_md_has_targets_and_resistance():
    rows = build_leaderboard([("qwen/qwen3.6-27b", _Report(held=9, bypass_layers=("generative",)))])
    md = render_leaderboard_md(rows, {"attacker": "heretic", "layers": "replay+jbb+generative",
                                      "iters": 6, "limit": 5})
    assert "Jailbreak Resistance" in md
    assert "qwen/qwen3.6-27b" in md
    assert "0.900" in md                          # resistance rendered to 3 dp
    assert "Generative" in md                     # the generative column header


def test_effective_records_recovers_static_bypass_prompts():
    # The attack-DB capture must recover the FULL prompt of a static bypass from the
    # deterministic corpus (the finding itself carries no prompt, by design).
    from types import SimpleNamespace

    from blastcontain_core.models import DrillOutcome, Severity

    from blastcontain_drill.corpus import load_corpus
    from blastcontain_drill.jailbreak_study import _effective_records

    corpus = load_corpus(enable_jbb=True, limit=1)
    atk = next(a for a in corpus.attacks if a.category == "jailbreak")
    finding = SimpleNamespace(outcome=DrillOutcome.BYPASS, layer=atk.layer,
                              attack_id=atk.id, technique=atk.technique,
                              severity=Severity.HIGH, evidence="ev")
    report = SimpleNamespace(findings=[finding], target_model="qwen3.6-27b",
                             attacker_model="heretic", judge_model=None, guard_model=None)
    cfg = SimpleNamespace(corpus="latest", scenarios=[], limit=1, enable_operators=False,
                          enable_jbb=True, enable_systemcard=False, agent_id="t",
                          generative_corpus=None)
    records = _effective_records(cfg, report)
    assert len(records) == 1
    assert records[0]["prompt"] == atk.prompt          # full prompt recovered
    assert records[0]["target_model"] == "qwen3.6-27b"
    assert records[0]["severity"] == "HIGH"


def test_wilson_interval_brackets_the_point_estimate():
    from blastcontain_drill.jailbreak_study import wilson_interval

    lo, hi = wilson_interval(8, 10)                  # p = 0.8
    assert 0.0 <= lo <= 0.8 <= hi <= 1.0
    assert wilson_interval(0, 0) == (0.0, 1.0)       # no data -> full interval


def test_aggregate_asr_scenario_and_attempt_level():
    from types import SimpleNamespace

    from blastcontain_core.models import DrillOutcome

    from blastcontain_drill.jailbreak_study import aggregate_asr

    def rep(outcomes):
        return SimpleNamespace(findings=[
            SimpleNamespace(attack_id=aid, layer="replay", outcome=o)
            for aid, o in outcomes.items()
        ])

    bypass, held = DrillOutcome.BYPASS, DrillOutcome.HELD
    reports = [
        rep({"a1": bypass, "a2": held}),   # attempt 1: a1 broke
        rep({"a1": held, "a2": held}),     # attempt 2: a1 held
        rep({"a1": held, "a2": held}),     # attempt 3
    ]
    a = aggregate_asr("m", reports)
    assert a["attempts"] == 3 and a["scenarios"] == 2
    assert a["scenario_bypass"] == 1                 # a1 bypassed in >=1 of 3 tries
    assert a["scenario_held"] == 1                   # a2 never bypassed
    assert a["attempt_bypasses"] == 1 and a["attempt_total"] == 6
    assert a["attempt_asr"] == round(1 / 6, 3)
    assert a["resistance"] == 0.5                    # 1 held / (1 held + 1 bypass)
