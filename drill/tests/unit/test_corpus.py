"""Corpus loading, version pinning, filtering, and source availability."""
from __future__ import annotations

from blastcontain_drill.corpus import BUILTIN_CORPUS_VERSION, load_corpus
from blastcontain_drill.corpus.base import ACTION_GOALS
from blastcontain_core.constants import DRILL_CATEGORY_TAXONOMY


def test_builtin_corpus_loads():
    c = load_corpus()
    assert len(c) >= 14
    assert c.version == BUILTIN_CORPUS_VERSION
    assert "builtin-replay" in c.sources


def test_every_attack_category_is_in_the_taxonomy():
    # A finding can't be tagged if its category isn't a known taxonomy key.
    for a in load_corpus().attacks:
        assert a.category in DRILL_CATEGORY_TAXONOMY, a.id


def test_action_goal_attacks_present():
    goals = {a.goal for a in load_corpus().attacks}
    assert goals & ACTION_GOALS, "corpus must exercise the action plane"


def test_category_filter_and_limit():
    c = load_corpus(categories=["jailbreak", "data_exfiltration"], limit=1)
    assert {a.category for a in c.attacks} == {"jailbreak", "data_exfiltration"}
    assert len(c.attacks) == 2  # one per category


def test_version_override_is_honored():
    assert load_corpus(version="v2025.01").version == "v2025.01"


def test_aig_absent_falls_back_to_builtin():
    # AI-Infra-Guard service is not running in CI -> silently skipped.
    c = load_corpus(enable_aig=True)
    assert len(c) >= 14
    assert c.sources == ["builtin-replay"]
