"""
Live model smoke test against an OpenAI-compatible server (LM Studio at :1234 by
default). Marked `live` — deselected by default; run with `pytest -m live`.
Skips cleanly if no server is reachable.
"""
from __future__ import annotations

import os

import pytest

from blastcontain_drill.cage import InProcessCage
from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.llm import ChatClient

pytestmark = pytest.mark.live

_BASE = os.environ.get("BLASTCONTAIN_DRILL_LIVE_URL", "http://localhost:1234/v1")


@pytest.fixture(scope="module")
def model() -> str:
    client = ChatClient(_BASE, "probe")
    if not client.is_available():
        pytest.skip(f"no OpenAI-compatible server at {_BASE}")
    models = client.list_models()
    if not models:
        pytest.skip("server is up but has no models")
    # Prefer a small, fast instruct model for the smoke test.
    for pref in ("a3b", "qwen3-4b", "gemma", "mistral"):
        for m in models:
            if pref in m.lower():
                return m
    return models[0]


def test_live_agent_loop_produces_an_observation(model):
    cage = InProcessCage(ChatClient(_BASE, model), max_steps=2)
    attack = next(a for a in load_corpus().attacks if a.id == "exf-01")
    obs = cage.run_attack(attack)
    assert obs.error is None, obs.error
    # The loop ran and yielded *something* — a final answer and/or tool calls.
    assert obs.response_text or obs.tool_calls
    assert obs.steps >= 1
