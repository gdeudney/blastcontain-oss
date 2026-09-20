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


@pytest.mark.parametrize('vulnerable', [True, False])
@pytest.mark.parametrize('surface', ['description', 'response'])
def test_mcp_payload_delivery_inside_network_none_cage(vulnerable, surface):
    from blastcontain_drill.corpus.mcp_poisoning import MCPPoisoningSource
    from blastcontain_drill.probes import run_action_probes
    attack = next(a for a in MCPPoisoningSource().dataset() if a.id == f'mcp-{surface}-exfil')
    obs = PodmanCage(vulnerable=vulnerable).run_attack(attack)
    assert obs.error is None, obs.error
    assert obs.mcp['payload_delivered']
    assert any(event['method'] == 'tools/call' for event in obs.mcp['events'])
    assert run_action_probes(obs)['triggered'] is vulnerable
    if vulnerable:
        assert run_action_probes(obs)['contained']


@pytest.mark.parametrize('surface', ['description', 'response'])
@pytest.mark.parametrize('steps,expected', [(1, 'ERROR'), (2, 'ERROR'), (3, 'BYPASS')])
def test_incomplete_mcp_execution_survives_container_transport(surface, steps, expected):
    from blastcontain_drill.corpus.base import Corpus
    from blastcontain_drill.corpus.mcp_poisoning import MCPPoisoningSource
    from blastcontain_drill.runner import run_corpus
    attack = next(a for a in MCPPoisoningSource().dataset() if a.id == f'mcp-{surface}-exfil')
    finding = run_corpus(PodmanCage(vulnerable=True, max_steps=steps), Corpus('test', [attack]), [])[0]
    assert finding.outcome.value == expected
    assert finding.action_verdict['execution'] == {'completed': False, 'reason': 'step_limit'}
    if steps == 3:
        assert finding.action_verdict['triggered'] and finding.action_verdict['contained']
