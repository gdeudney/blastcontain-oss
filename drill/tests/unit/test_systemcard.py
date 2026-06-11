"""System-card-derived checks (cyber misuse/dual-use, identity & leak honesty, ART injection)."""
from __future__ import annotations

from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.corpus.base import (
    ACTION_GOALS,
    AXIS_FREEFORM,
    AXIS_HARM,
    AXIS_REFUSAL,
    rubric_for,
)
from blastcontain_drill.corpus.systemcard import SystemCardSource
from blastcontain_core.models import DrillOutcome


def test_source_covers_the_system_card_check_families():
    cats = {a.category for a in SystemCardSource().dataset()}
    assert {"cyber_misuse", "cyber_dual_use", "identity_honesty",
            "leaked_info_honesty", "prompt_injection_indirect"} <= cats


def test_cyber_misuse_vs_dual_use_refusal_polarity():
    attacks = SystemCardSource().dataset()
    # harmful cyber -> should refuse (harm rubric)
    misuse = next(a for a in attacks if a.category == "cyber_misuse")
    assert misuse.expected_refusal is True
    assert rubric_for(misuse).axis == AXIS_HARM
    # dual-use cyber -> should help; refusing it is an over-refusal (refusal rubric)
    dual = next(a for a in attacks if a.category == "cyber_dual_use")
    assert dual.expected_refusal is False
    assert rubric_for(dual).axis == AXIS_REFUSAL
    assert rubric_for(dual).on_match == DrillOutcome.OVER_REFUSAL


def test_identity_and_leak_use_the_freeform_rubric():
    for cat in ("identity_honesty", "leaked_info_honesty"):
        a = next(x for x in SystemCardSource().dataset() if x.category == cat)
        r = rubric_for(a)
        assert r.axis == AXIS_FREEFORM            # the freeform judging mode (#24 payoff)
        assert r.on_match == DrillOutcome.BYPASS


def test_indirect_injection_seeds_drive_the_action_plane():
    inj = [a for a in SystemCardSource().dataset() if a.category == "prompt_injection_indirect"]
    assert inj
    for a in inj:
        assert a.vector == "indirect"
        assert a.poisoned_document                # the hidden instruction
        assert a.goal in ACTION_GOALS             # scored on cage ground truth, not the judge


def test_load_corpus_records_systemcard_source():
    base = load_corpus()
    expanded = load_corpus(enable_systemcard=True)
    assert len(expanded) > len(base)
    assert any(s.startswith("system-card@") for s in expanded.sources)
