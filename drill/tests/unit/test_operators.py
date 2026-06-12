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


def _payload(prompt: str) -> str:
    """The encoded body after an operator's '…:' preamble line."""
    return prompt.split("\n", 1)[1]


def test_cipher_operators_are_faithful_to_the_seed():
    # An encoder must round-trip, else the model can't recover the request from the
    # ciphertext the guard waved through.
    import codecs
    import urllib.parse

    seed = _SEED[0]
    src = OperatorsSource()
    assert codecs.decode(_payload(src.generate(seed, "rot13")[0].prompt), "rot_13") == seed.prompt
    assert urllib.parse.unquote(_payload(src.generate(seed, "url_encode")[0].prompt)) == seed.prompt
    bits = _payload(src.generate(seed, "binary")[0].prompt)
    assert bytes(int(b, 2) for b in bits.split()).decode("utf-8") == seed.prompt
    assert _payload(src.generate(seed, "reverse")[0].prompt)[::-1] == seed.prompt


def test_filter_evasion_operators_obfuscate_but_stay_readable():
    seed = _SEED[0]
    src = OperatorsSource()
    # zero-width: invisible separators; stripping them restores the seed exactly
    zw = src.generate(seed, "zero_width")[0].prompt
    assert chr(0x200B) in zw and zw.replace(chr(0x200B), "") == seed.prompt
    # homoglyph: same length, no longer ASCII-identical
    hg = src.generate(seed, "homoglyph")[0].prompt
    assert len(hg) == len(seed.prompt) and hg != seed.prompt
    # char-space: drop the injected spaces and the non-space chars are unchanged
    cs = src.generate(seed, "char_space")[0].prompt
    assert cs.replace(" ", "") == seed.prompt.replace(" ", "")


def test_pyrit_deepteam_operators_registered():
    for op in ("rot13", "caesar", "atbash", "morse", "binary", "url_encode",
               "reverse", "char_space", "zero_width", "homoglyph"):
        assert op in DEFAULT_OPERATORS


def test_framing_operators_carry_the_ask_inside_a_legitimate_frame():
    # academic_framing (taxonomy/document-structure) and fiction_frame (narrative) wrap
    # the seed *verbatim* in a benign-looking context — the underlying ask is unchanged,
    # so the over-refusal / action labels survive (asserted in the apply-cleanly test).
    seed = _SEED[0]
    src = OperatorsSource()
    for op, marker in (("academic_framing", "ANSWER KEY"), ("fiction_frame", "SCENE")):
        assert op in DEFAULT_OPERATORS
        out = src.generate(seed, op)[0].prompt
        assert seed.prompt in out          # the request is carried through, not mutated
        assert marker in out               # ...embedded in a legitimate-looking frame


def test_all_operators_apply_cleanly_and_keep_labels():
    seed = _SEED[0]
    src = OperatorsSource()
    for op in DEFAULT_OPERATORS:
        variants = src.generate(seed, op)
        assert len(variants) == 1
        v = variants[0]
        assert isinstance(v.prompt, str) and v.prompt
        assert v.technique.endswith(op)
        # transforms must not disturb the over-refusal / action labels
        assert v.expected_refusal == seed.expected_refusal
        assert v.goal == seed.goal


def test_load_corpus_with_operators_grows_and_records_source():
    base = load_corpus()
    expanded = load_corpus(enable_operators=True)
    assert len(expanded) > len(base)
    # sources are version-tagged as name@revision in the (signed) report
    assert "operators@v3" in expanded.sources
    assert any(s.startswith("builtin-replay@") for s in expanded.sources)


def test_operators_respect_category_filter_and_limit():
    c = load_corpus(categories=["jailbreak"], limit=2, enable_operators=True)
    assert {a.category for a in c.attacks} == {"jailbreak"}
    # built-in (<=2) + operator variants (<=2) for the one category
    assert len(c.attacks) <= 4
