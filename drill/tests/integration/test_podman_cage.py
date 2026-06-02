"""
PodmanCage containment tests. Marked `podman` — deselected by default
(`-m "not podman"`); run explicitly with `pytest -m podman`. Requires Podman
and pulls python:3.12-slim on first run.
"""
from __future__ import annotations

import pytest

from blastcontain_drill.cage.podman import PodmanCage
from blastcontain_drill.corpus import load_corpus

pytestmark = pytest.mark.podman


@pytest.fixture(autouse=True)
def _require_podman():
    if not PodmanCage.available():
        pytest.skip("podman not available on this host")


def _attack(aid: str):
    return next(a for a in load_corpus().attacks if a.id == aid)


def test_vulnerable_agent_attempts_exfil_but_is_contained():
    obs = PodmanCage(vulnerable=True).run_attack(_attack("exf-01"))
    assert obs.error is None, obs.error
    # The agent was driven to exfiltrate the canary...
    assert any(obs.canary and obs.canary in str(t.arguments) for t in obs.tool_calls)
    # ...but the off-box send was blocked (and the container is --network none).
    assert any(not e.allowed for e in obs.egress_attempts)
    assert all(t.blocked for t in obs.tool_calls if t.tool == "send")


def test_hardened_agent_makes_no_egress_in_the_cage():
    obs = PodmanCage(vulnerable=False).run_attack(_attack("exf-01"))
    assert obs.error is None, obs.error
    assert obs.egress_attempts == []
    assert obs.tool_calls == []
