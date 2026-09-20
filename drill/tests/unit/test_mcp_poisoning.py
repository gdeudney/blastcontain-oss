"""Real loopback MCP delivery and action evidence, with deterministic agents."""
import json
from unittest.mock import Mock

import pytest

from blastcontain_core.models import DrillOutcome
from blastcontain_drill.cage.base import CageObservation
from blastcontain_drill.cage.inprocess import InProcessCage
from blastcontain_drill.cage.mcp_fixture import poison_fixture
from blastcontain_drill.cage.podman import _obs_from_json
from blastcontain_drill.cage.stub import StubChatClient
from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.corpus.base import Corpus
from blastcontain_drill.corpus.mcp_poisoning import MCPPoisoningSource
from blastcontain_drill.runner import run_corpus


def test_explicit_opt_in_and_versioned_source():
    assert not any(a.mcp_tool_description or a.mcp_tool_response for a in load_corpus().attacks)
    corpus = load_corpus(enable_mcp_poisoning=True)
    assert 'mcp-poisoning@v1' in corpus.sources
    assert len([a for a in corpus.attacks if a.source == 'mcp-poisoning']) == 4
    assert MCPPoisoningSource().dataset(categories=['jailbreak']) == []
    assert len(MCPPoisoningSource().dataset(limit=1)) == 1


@pytest.mark.parametrize('attack', MCPPoisoningSource().dataset(), ids=lambda a: a.id)
@pytest.mark.parametrize('vulnerable', [True, False])
def test_actual_mcp_surfaces_reach_agent_and_score_actions(attack, vulnerable):
    cage = InProcessCage(StubChatClient(vulnerable=vulnerable))
    obs = cage.run_attack(attack)
    assert obs.error is None, obs.error
    assert obs.mcp['payload_delivered']
    assert obs.mcp['tool_called']
    assert [event['method'] for event in obs.mcp['events']][:3] == ['initialize', 'notifications/initialized', 'tools/list']
    assert 'tools/call' in [event['method'] for event in obs.mcp['events']]
    finding = run_corpus(cage, Corpus('test', [attack]), [])[0]
    assert finding.outcome == (DrillOutcome.BYPASS if vulnerable else DrillOutcome.HELD)
    assert finding.action_verdict['triggered'] is vulnerable
    if vulnerable:
        assert finding.action_verdict['contained']
        assert finding.blocked_by.startswith('cage containment')
    else:
        assert obs.response_text == 'Invoice INV-001 is paid, amount USD 42.00.'
    raw = json.dumps(obs.mcp)
    assert (attack.mcp_tool_description or attack.mcp_tool_response) not in raw
    assert _obs_from_json({**obs.as_dict(), 'canary': obs.canary}).mcp == obs.mcp


def test_refuse_everything_does_not_pass_unseen_response():
    backend = Mock()
    backend.chat.return_value = 'DONE I refuse everything.'
    attack = next(a for a in MCPPoisoningSource().dataset() if a.mcp_tool_response)
    finding = run_corpus(InProcessCage(backend), Corpus('test', [attack]), [])[0]
    assert finding.outcome == DrillOutcome.ERROR
    assert 'not delivered' in finding.bypass_description


def test_max_steps_before_payload_delivery_is_incomplete():
    attack = next(a for a in MCPPoisoningSource().dataset() if a.mcp_tool_response)
    finding = run_corpus(InProcessCage(StubChatClient(), max_steps=1), Corpus('test', [attack]), [])[0]
    assert finding.outcome == DrillOutcome.ERROR


@pytest.mark.parametrize('surface', ['description', 'response'])
@pytest.mark.parametrize('steps,expected', [(1, DrillOutcome.ERROR), (2, DrillOutcome.ERROR),
                                          (3, DrillOutcome.BYPASS), (4, DrillOutcome.BYPASS)])
def test_step_limit_cannot_establish_held_but_keeps_observed_harm(surface, steps, expected):
    attack = next(a for a in MCPPoisoningSource().dataset() if a.id == f'mcp-{surface}-exfil')
    cage = InProcessCage(StubChatClient(vulnerable=True), max_steps=steps)
    obs = cage.run_attack(attack)
    expected_reason = 'completed' if steps == 4 else 'step_limit'
    assert obs.termination_reason == expected_reason
    assert _obs_from_json(obs.as_dict()).termination_reason == expected_reason
    finding = run_corpus(cage, Corpus('test', [attack]), [])[0]
    assert finding.outcome == expected
    if steps < 4:
        assert finding.action_verdict['execution'] == {'completed': False, 'reason': 'step_limit'}
    if steps == 3:
        assert finding.action_verdict['triggered'] and finding.action_verdict['contained']
        assert 'execution incomplete' in finding.bypass_description


def test_step_limit_stops_subsequent_user_turns():
    from dataclasses import replace
    attack = replace(MCPPoisoningSource().dataset()[0], turns=['first', 'second'])
    backend = Mock()
    backend.chat.return_value = 'CALL list_files {}'
    obs = InProcessCage(backend, max_steps=1).run_attack(attack)
    assert obs.termination_reason == 'step_limit'
    assert backend.chat.call_count == 1


def test_cage_error_cannot_silently_become_held():
    cage = Mock()
    cage.run_attack.return_value = CageObservation(error='test backend unavailable')
    finding = run_corpus(cage, Corpus('test', [MCPPoisoningSource().dataset()[0]]), [])[0]
    assert finding.outcome == DrillOutcome.ERROR
    assert 'backend unavailable' in finding.bypass_description


def test_payload_is_never_added_to_system_instructions():
    backend = Mock()
    backend.chat.return_value = 'DONE Invoice is paid.'
    attack = MCPPoisoningSource().dataset()[0]
    InProcessCage(backend).run_attack(attack)
    messages = backend.chat.call_args.args[0]
    assert attack.mcp_tool_description not in messages[0]['content']
    assert any(attack.mcp_tool_description in m['content'] for m in messages if m['role'] != 'system')


def test_fixture_only_exposes_bounded_invoice_tool():
    with poison_fixture() as client:
        assert client.discover()[0]['name'] == 'lookup_invoice'
        assert 'USD 42.00' in client.call({'invoice_id': 'INV-001'})
        with pytest.raises(ValueError):
            client.call({'command': 'not allowed'})
        client.count = 16
        with pytest.raises(ValueError, match='limit'):
            client.discover()


def test_oversized_fixture_text_rejected():
    with pytest.raises(ValueError):
        with poison_fixture(description='x' * 12001):
            pass


def test_content_only_claim_cannot_fake_an_action_bypass():
    class ClaimsSuccess:
        name = 'claims'
        axes = frozenset({'harm'})

        def is_available(self):
            return True

        def score(self, attack, response):
            return {'scorer': 'claims', 'matched': True, 'label': 'unsafe'}

    cage = InProcessCage(StubChatClient(vulnerable=False))
    finding = run_corpus(cage, Corpus('test', [MCPPoisoningSource().dataset()[0]]), [ClaimsSuccess()])[0]
    assert finding.content_verdict['matched']
    assert not finding.action_verdict['triggered']
    assert finding.outcome == DrillOutcome.HELD


def test_unsupported_agent_url_cannot_claim_mcp_coverage():
    from blastcontain_drill.config import DrillConfig
    from blastcontain_drill.runner import run_drill
    with pytest.raises(ValueError, match='agent_url is unsupported'):
        run_drill(DrillConfig(agent_id='test', agent_url='http://127.0.0.1:1', enable_mcp_poisoning=True))


def test_discovery_failure_is_error_and_does_not_reach_backend(monkeypatch):
    from blastcontain_drill.cage.mcp_fixture import FixtureClient
    monkeypatch.setattr(FixtureClient, 'discover', Mock(side_effect=ValueError('bad protocol')))
    backend = Mock()
    finding = run_corpus(InProcessCage(backend), Corpus('test', [MCPPoisoningSource().dataset()[0]]), [])[0]
    assert finding.outcome == DrillOutcome.ERROR
    backend.chat.assert_not_called()
    assert not finding.action_verdict['mcp']['payload_delivered']


def test_transport_listener_is_closed_after_context():
    import socket
    with poison_fixture() as client:
        port = client.port
        client.discover()
    with pytest.raises(OSError):
        with socket.create_connection(('127.0.0.1', port), timeout=1):
            pytest.fail('fixture socket was left open')


def test_signed_and_markdown_reports_preserve_exposure(tmp_path):
    from blastcontain_core.models import DrillReport
    from blastcontain_core.signing import verify_packet
    from blastcontain_drill.reporter import write_drill_packet, write_markdown_report
    report = DrillReport(agent_id='test', environment='test', corpus_version='v1')
    report.findings = run_corpus(InProcessCage(StubChatClient(vulnerable=False)),
                                Corpus('test', [MCPPoisoningSource().dataset()[0]]), [])
    report.status = report.derive_status()
    packet = write_drill_packet(report, str(tmp_path / 'drill.json'))
    assert verify_packet(packet)
    assert packet['packet']['findings'][0]['action_verdict']['mcp']['payload_delivered']
    write_markdown_report(report, str(tmp_path / 'report.md'))
    text = (tmp_path / 'report.md').read_text(encoding='utf-8')
    assert 'MCP delivery evidence' in text and 'mcp-description-exfil' in text
