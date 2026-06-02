"""Operators layer — technique transforms expand the corpus (no model)."""
from __future__ import annotations

import base64

from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.corpus.builtin import _SEED
from blastcontain_drill.corpus.operators import DEFAULT_OPERATORS, OperatorsSource


def test_operators_expand_each_seed():
    src = OperatorsSource()
    variants = src.dataset()
    assert len(variants) == len(_SEED) * len(DEFAULT_OPERATORS)


def test_variants_preserve_category_goal_and_target():
    seed = next(s for s in _SEED if s.id == "tm-01")  # forbidden_tool goal
    src = OperatorsSource(seeds=[seed])
    for v in src.dataset():
        assert v.category == seed.category
        assert v.goal == seed.goal
        assert v.forbidden_tool == seed.forbidden_tool
        assert v.layer == "operators"
        assert v.source == "operators"
        assert v.id.startswith("tm-01+")


def test_base64_operator_round_trips_to_the_seed_prompt():
    seed = _SEED[0]
    variant = OperatorsSource().generate(seed, "base64")[0]
    encoded = variant.prompt.splitlines()[-1]
    assert base64.b64decode(encoded).decode() == seed.prompt


def test_generate_unknown_operator_returns_empty():
    assert OperatorsSource().generate(_SEED[0], "does-not-exist") == []


def test_load_corpus_with_operators_grows_and_records_source():
    base = load_corpus()
    expanded = load_corpus(enable_operators=True)
    assert len(expanded) > len(base)
    assert "operators" in expanded.sources
    assert "builtin-replay" in expanded.sources


def test_operators_respect_category_filter_and_limit():
    c = load_corpus(categories=["jailbreak"], limit=2, enable_operators=True)
    assert {a.category for a in c.attacks} == {"jailbreak"}
    # built-in (<=2) + operator variants (<=2) for the one category
    assert len(c.attacks) <= 4
