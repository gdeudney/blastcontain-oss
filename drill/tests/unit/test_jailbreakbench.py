"""JailbreakBench vendored dataset + over-refusal corpus wiring."""
from __future__ import annotations

from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.corpus.base import GOAL_CONTENT
from blastcontain_drill.corpus.jailbreakbench import JailbreakBenchSource
from blastcontain_core.models import (
    DrillFinding,
    DrillOutcome,
    DrillReport,
    Severity,
)


def test_source_loads_both_splits():
    src = JailbreakBenchSource()
    assert src.is_available()
    attacks = src.dataset()
    harm = [a for a in attacks if a.id.startswith("jbb-harm-")]
    benign = [a for a in attacks if a.id.startswith("jbb-benign-")]
    assert len(harm) == 100
    assert len(benign) == 100


def test_split_sets_expected_refusal_and_category():
    by_id = {a.id: a for a in JailbreakBenchSource().dataset()}
    h, b = by_id["jbb-harm-0"], by_id["jbb-benign-0"]
    # Harmful behaviors are scored as jailbreaks (refusal expected); benign ones
    # are over-refusal probes (compliance expected, no attack taxonomy).
    assert h.expected_refusal is True and h.category == "jailbreak"
    assert b.expected_refusal is False and b.category == "benign"
    assert h.goal == GOAL_CONTENT and h.source == "jailbreakbench"
    assert h.prompt and b.prompt


def test_limit_caps_per_split():
    attacks = JailbreakBenchSource().dataset(limit=5)
    assert len([a for a in attacks if a.category == "jailbreak"]) == 5
    assert len([a for a in attacks if a.category == "benign"]) == 5


def test_category_filter_selects_one_split():
    benign_only = JailbreakBenchSource().dataset(categories=["benign"])
    assert benign_only and all(a.category == "benign" for a in benign_only)


def test_load_corpus_opt_in():
    base = load_corpus()
    assert not any(s.startswith("jailbreakbench") for s in base.sources)
    with_jbb = load_corpus(enable_jbb=True)
    # opt-in AND version-tagged: recorded as jailbreakbench@<pinned-revision>
    assert "jailbreakbench@886acc3" in with_jbb.sources
    assert len(with_jbb) >= len(base) + 200


def test_drillreport_tracks_over_refusals_without_failing():
    # Over-refusals are usability false-positives, not security bypasses: they are
    # counted, but on their own they leave the drill PASSED.
    report = DrillReport(
        agent_id="a",
        environment="staging",
        corpus_version="v",
        findings=[
            DrillFinding("s1", "benign-1", DrillOutcome.OVER_REFUSAL, Severity.LOW),
            DrillFinding("s2", "benign-2", DrillOutcome.HELD),
        ],
    )
    assert len(report.over_refusals) == 1
    assert report.as_dict()["summary"]["over_refusals"] == 1
    assert report.derive_status() == report.status.PASSED


def test_critical_bypass_still_fails_despite_over_refusals():
    report = DrillReport(
        agent_id="a",
        environment="staging",
        corpus_version="v",
        findings=[
            DrillFinding("s1", "benign-1", DrillOutcome.OVER_REFUSAL, Severity.LOW),
            DrillFinding("s2", "harm-1", DrillOutcome.BYPASS, Severity.CRITICAL),
        ],
    )
    assert report.derive_status().value == "FAILED"
