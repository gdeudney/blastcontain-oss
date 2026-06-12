"""Relevance scoring + classification (heuristic and LLM-backed)."""
from __future__ import annotations

from blastcontain_scout.analyze import (
    classify,
    find_artifact,
    score_relevance,
)
from blastcontain_scout.arxiv import DEFAULT_TERMS, Paper


def _paper(title, summary):
    return Paper(arxiv_id="2401.1", title=title, summary=summary, published="", updated="")


JB = _paper(
    "A Universal Jailbreak Attack on LLM Agents",
    "We introduce a new jailbreak technique and release a dataset at "
    "https://github.com/foo/bar that bypasses guardrails.",
)
OFF = _paper("On the Theory of Widgets", "Unrelated manufacturing paper.")


def test_relevance_separates_on_topic_from_off_topic():
    assert score_relevance(JB, DEFAULT_TERMS) > 0.5
    assert score_relevance(OFF, DEFAULT_TERMS) == 0.0


def test_find_artifact_picks_known_host():
    assert find_artifact(JB.text) == "https://github.com/foo/bar"
    assert find_artifact("no links here") is None


def test_heuristic_classifies_dataset_release():
    a = classify(JB, DEFAULT_TERMS, backend=None)
    assert a.relevant is True
    assert a.kind == "dataset"                  # artifact + "dataset" release hint
    assert a.suggested_category == "jailbreak"
    assert a.artifact_url == "https://github.com/foo/bar"
    assert a.scored_by == "heuristic"
    assert a.license_note.startswith("unknown")


def test_off_topic_is_not_relevant():
    a = classify(OFF, DEFAULT_TERMS, backend=None, threshold=0.5)
    assert a.relevant is False


class _FakeBackend:
    def __init__(self, out):
        self.out = out

    def chat(self, messages, **kw):
        return self.out


def test_llm_classification_parses_json():
    backend = _FakeBackend(
        '{"relevant":true,"kind":"technique","category":"tool_misuse",'
        '"summary":"a new tool-abuse method","artifact_url":null,'
        '"license":"MIT","rationale":"clear"}'
    )
    a = classify(JB, DEFAULT_TERMS, backend=backend)
    assert a.scored_by == "llm"
    assert a.kind == "technique"
    assert a.suggested_category == "tool_misuse"
    assert a.license_note == "MIT"


def test_llm_bad_json_falls_back_to_heuristic():
    a = classify(JB, DEFAULT_TERMS, backend=_FakeBackend("garbage, no json"))
    assert a.scored_by == "heuristic"


def test_llm_invalid_category_is_corrected():
    backend = _FakeBackend('{"relevant":true,"kind":"intel","category":"not_a_real_cat"}')
    a = classify(JB, DEFAULT_TERMS, backend=backend)
    assert a.suggested_category in (
        "jailbreak", "prompt_injection_direct", "prompt_injection_indirect",
        "data_exfiltration", "tool_misuse", "mcp_hijack",
    )
