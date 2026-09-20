"""Passive MCP assessments: attribution, coverage, secret handling and no execution."""
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner
from blastcontain_core.signing import verify_packet
from blastcontain_verify.cli import main
from blastcontain_verify.config import VerifyConfig
from blastcontain_verify.mcp_target import run_mcp_scan
from blastcontain_verify.models import ScanStatus
from blastcontain_verify.reporter import write_audit_packet, write_markdown_report
from blastcontain_verify.reporter_sarif import write_sarif
from blastcontain_verify.scanner import run_scan


def inputs(tmp_path, server=None):
    config, policy = tmp_path / 'mcp.json', tmp_path / 'policy.json'
    config.write_text(json.dumps({'mcpServers': {'billing': server or {
        'command': 'never-execute-me', 'tools': ['get_invoice'],
    }}}))
    policy.write_text(json.dumps({'target_id': 'billing-mcp', 'permitted_tools': ['get_invoice']}))
    return VerifyConfig(target_type='mcp', target_id='billing-mcp',
                        mcp_config=str(config), policy=str(policy))


def test_no_execution_network_or_plugins(tmp_path, monkeypatch):
    forbidden = Mock(side_effect=AssertionError('unexpected execution'))
    for target in ('subprocess.run', 'subprocess.Popen', 'socket.create_connection', 'httpx.post',
                   'blastcontain_verify.scanner.load_plugin_groups',
                   'blastcontain_verify.checks.mcp.get_mcp_scanner'):
        monkeypatch.setattr(target, forbidden)
    result = run_scan(inputs(tmp_path))
    assert result.status == ScanStatus.APPROVED
    assert not result.coverage['runtime_observed']
    forbidden.assert_not_called()


@pytest.mark.parametrize('server', [
    {'url': 'https://example.invalid/mcp', 'headers': {'Authorization': 'Bearer ${TOKEN}'}, 'tools': ['get_invoice']},
    {'command': 'python', 'args': ['server.py'], 'tools': ['get_invoice']},
])
def test_target_attribution_in_all_outputs(tmp_path, server):
    result = run_mcp_scan(inputs(tmp_path, server))
    assert result.status == ScanStatus.APPROVED
    packet = write_audit_packet(result, str(tmp_path / 'audit.json'))
    assert packet['schema_version'] == '1.2'
    assert verify_packet(packet)
    assert 'agent_id' not in packet['packet']
    assert packet['packet']['target']['id'] == 'billing-mcp'
    write_markdown_report(result, str(tmp_path / 'report.md'))
    assert 'MCP Assessment' in (tmp_path / 'report.md').read_text()
    sarif = write_sarif(result, str(tmp_path / 'scan.sarif'))
    assert sarif['runs'][0]['invocations'][0]['properties']['target']['type'] == 'mcp'


@pytest.mark.parametrize('server', [
    {'url': 'http://example.invalid', 'tools': ['get_invoice']},
    {'url': 'https://example.invalid', 'auth': {'type': 'none'}, 'tools': ['get_invoice']},
])
def test_auth_configuration_risk(tmp_path, server):
    result = run_mcp_scan(inputs(tmp_path, server))
    assert 'MCP-02' in {f.check_id for f in result.findings}
    assert not result.coverage['authentication_validated']


def test_secret_values_not_serialized(tmp_path):
    secret = 'sentinel-do-not-serialize'
    result = run_mcp_scan(inputs(tmp_path, {
        'url': f'https://user:{secret}@example.invalid?token={secret}',
        'headers': {'Authorization': f'Bearer {secret}'}, 'env': {'API_KEY': secret},
        'tools': ['get_invoice'],
    }))
    assert 'MCP-05' in {f.check_id for f in result.findings}
    assert secret not in json.dumps(result.as_dict())


@pytest.mark.parametrize('change', ['missing-tools', 'missing-policy', 'skip-required', 'wrong-policy'])
def test_incomplete_cannot_approve(tmp_path, change):
    cfg = inputs(tmp_path)
    if change == 'missing-tools':
        cfg = inputs(tmp_path, {'command': 'python'})
    elif change == 'missing-policy':
        cfg.policy = None
    elif change == 'skip-required':
        cfg.skip_checks = ['MCP-05']
    else:
        Path(cfg.policy).write_text('{"target_id":"other","permitted_tools":[]}')
    result = run_mcp_scan(cfg)
    assert result.status == ScanStatus.ERROR
    assert not result.coverage['complete']


@pytest.mark.parametrize('server', [
    {'command': 'x', 'url': 'https://example.invalid'}, {'command': 'x', 'args': 'secret'},
    {'url': 'file:///secret'}, {'url': 'https://host:bad'}, {'command': 'x', 'transport': 'sse'},
    {'command': 'x', 'tools': [{'name': 'bad\nname'}]}, {'command': 'x', 'env': ['secret']},
    {'command': 'x', 'tools': ['same', 'same']},
])
def test_invalid_shapes_are_reportable(tmp_path, server):
    result = run_mcp_scan(inputs(tmp_path, server))
    assert result.status == ScanStatus.ERROR
    assert 'SCAN-MCP' in {f.check_id for f in result.findings}


def test_selection_is_required_and_isolated(tmp_path):
    cfg = inputs(tmp_path)
    Path(cfg.mcp_config).write_text(json.dumps({'mcpServers': {
        'billing': {'command': 'python', 'tools': ['get_invoice']},
        'other': {'url': 'http://insecure', 'tools': ['send_email']},
    }}))
    assert run_mcp_scan(cfg).status == ScanStatus.ERROR
    cfg.mcp_server = 'billing'
    result = run_mcp_scan(cfg)
    assert result.status == ScanStatus.APPROVED
    assert result.target['server_name'] == 'billing'


def test_unapproved_tools_and_launch_privileges(tmp_path):
    result = run_mcp_scan(inputs(tmp_path, {'command': 'podman', 'args': ['--privileged'],
                                          'tools': ['delete_invoice']}))
    assert {'MCP-01', 'MCP-06'} <= {f.check_id for f in result.findings}


def test_bad_json_redaction(tmp_path):
    cfg = inputs(tmp_path)
    Path(cfg.mcp_config).write_text('secret-token:not-json')
    result = run_mcp_scan(cfg)
    assert result.status == ScanStatus.ERROR
    assert 'secret-token' not in json.dumps(result.as_dict())


def test_cli_yaml_override(tmp_path):
    cfg = inputs(tmp_path)
    config = tmp_path / 'verify.yaml'
    config.write_text(f'target_type: mcp\ntarget_id: wrong\nmcp_config: {cfg.mcp_config}\npolicy: {cfg.policy}\n')
    out = tmp_path / 'out.json'
    run = CliRunner().invoke(main, ['--config', str(config), '--target-id', 'billing-mcp', '--output', str(out)])
    assert run.exit_code == 0, run.output
    assert json.loads(out.read_text())['packet']['target']['type'] == 'mcp'
    assert CliRunner().invoke(main, ['--target-type', 'mcp']).exit_code == 3


def test_runtime_runs_local_groups_only(tmp_path, monkeypatch):
    from blastcontain_verify.contract import CheckGroupResult
    from blastcontain_verify.registry import CheckGroupSpec
    cfg = inputs(tmp_path)
    cfg.scan_scope = 'runtime'
    local = Mock(return_value=CheckGroupResult(passed=['PRIV-01']))
    network = Mock(side_effect=AssertionError('network probe executed'))
    monkeypatch.setattr('blastcontain_verify.registry.BUILTIN_GROUPS', (
        CheckGroupSpec('process', frozenset({'PRIV-01'}), local),
        CheckGroupSpec('network', frozenset({'NET-01'}), network),
    ))
    result = run_mcp_scan(cfg)
    assert result.coverage['runtime_observed']
    local.assert_called_once()
    network.assert_not_called()


def test_capability_hints_are_labeled_not_observed(tmp_path):
    cfg = inputs(tmp_path, {'command': 'python', 'tools': ['read_file', 'send_email']})
    Path(cfg.policy).write_text(json.dumps({'target_id': 'billing-mcp',
                                          'permitted_tools': ['read_file', 'send_email']}))
    result = run_mcp_scan(cfg)
    combo = next(f for f in result.findings if f.check_id == 'MCP-03')
    assert 'heuristic' in combo.detail
    assert len(result.coverage['feature_coverage']) == 10
    assert result.coverage['check_evidence']['MCP-03'] == 'declared_configuration'


def test_signature_covers_target_and_coverage(tmp_path):
    result = run_mcp_scan(inputs(tmp_path))
    packet = write_audit_packet(result, str(tmp_path / 'audit.json'))
    packet['packet']['target']['id'] = 'different-server'
    assert not verify_packet(packet)


def test_mcp_cli_rejects_agent_posting_and_live_probe(tmp_path):
    cfg = inputs(tmp_path)
    args = ['--target-type', 'mcp', '--target-id', 'billing-mcp', '--mcp-config', cfg.mcp_config]
    for extra in (['--blastcontain-url', 'https://ledger.invalid'], ['--api-live-probe'],
                  ['--agent-id', 'not-an-agent']):
        assert CliRunner().invoke(main, args + extra).exit_code == 3


def test_absent_workstation_indicators_are_not_missing_coverage(tmp_path, monkeypatch):
    from blastcontain_verify.contract import CheckGroupResult
    from blastcontain_verify.registry import CheckGroupSpec
    cfg = inputs(tmp_path)
    cfg.scan_scope = 'runtime'
    monkeypatch.setattr('blastcontain_verify.registry.BUILTIN_GROUPS', (
        CheckGroupSpec('local', frozenset({'LOCAL-01'}), lambda ctx: CheckGroupResult(
            skipped=[{'check_id': 'LOCAL-01', 'reason': 'No workstation indicators detected'}])),
    ))
    result = run_mcp_scan(cfg)
    assert result.coverage['complete']
    assert result.skipped[0]['category'] == 'not_applicable'
