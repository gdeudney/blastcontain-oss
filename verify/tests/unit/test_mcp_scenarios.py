"""Exercise the generic adapter against the official MCP SDK over real HTTP."""
import json
from pathlib import Path
import runpy

import pytest

from blastcontain_verify.config import VerifyConfig
from blastcontain_verify.control_validation import validate_controls
from blastcontain_verify.mcp_scenarios import load_plan
from blastcontain_verify.scanner import run_scan

EXAMPLE = Path(__file__).parents[2] / 'examples/practical-validation'
make_manifest = runpy.run_path(str(EXAMPLE / 'plan.py'))['manifest']


def configure(tmp_path, monkeypatch, endpoints):
    monkeypatch.setenv('VERIFY_OBSERVER_TOKEN', endpoints['admin'])
    for role, value in endpoints['tokens'].items():
        monkeypatch.setenv('VERIFY_CALLER_' + role.upper(), value)
    plan = make_manifest(endpoints)
    path = tmp_path / 'validation.json'
    path.write_text(json.dumps(plan))
    config = tmp_path / 'mcp.json'
    config.write_text(json.dumps({'mcpServers': {'reference': {'url': endpoints['mcp_url'],
                                                             'auth': {'type': 'bearer'}, 'tools': ['update_record']}}}))
    policy = tmp_path / 'policy.json'
    policy.write_text('{"target_id":"reference-mcp","permitted_tools":["update_record"]}')
    return VerifyConfig(target_type='mcp', target_id='reference-mcp', mcp_config=str(config),
                        policy=str(policy), control_manifest=str(path), allow_live_tests=True)


@pytest.fixture
def server():
    pytest.importorskip('mcp.server.mcpserver')
    return runpy.run_path(str(EXAMPLE / 'service.py'))['server']


@pytest.mark.parametrize('insecure', [False, True])
def test_official_sdk_all_controls(tmp_path, monkeypatch, server, insecure):
    with server(insecure=insecure) as endpoints:
        result = run_scan(configure(tmp_path, monkeypatch, endpoints))
        report = result.validation
        assert report['complete'], report
        assert report['protocol']['initialized']
        assert len(report['checks']) == 6
        assert {c['status'] for c in report['checks']} == ({'FAIL'} if insecure else {'PASS'}), report
        assert report['cleanup_complete'] and not endpoints['runs']
        assert report['requests_sent'] <= 100
        assert result.coverage['scenario_authentication_validated'] is (not insecure)
        assert not result.coverage['fixture_authentication_validated']
        serialized = json.dumps(result.as_dict())
        assert endpoints['admin'] not in serialized
        assert all(secret not in serialized for secret in endpoints['tokens'].values())


@pytest.mark.parametrize('fault', ['deny_all', 'mutate_denials'])
def test_faults_cannot_earn_all_pass(tmp_path, monkeypatch, server, fault):
    with server(**{fault: True}) as endpoints:
        report = validate_controls(configure(tmp_path, monkeypatch, endpoints))
        assert any(c['status'] != 'PASS' for c in report['checks'])
        assert report['cleanup_complete'] and not endpoints['runs']


@pytest.mark.parametrize('change', ['target', 'credential', 'no-positive', 'duplicate', 'deny-state', 'denial-code'])
def test_invalid_plan_rejected_before_io(tmp_path, monkeypatch, change):
    endpoints = {'mcp_url': 'http://127.0.0.1:9/mcp', 'control_url': 'http://127.0.0.1:8',
                 'admin': 'observer-token-123456789', 'tokens': {k: k + '-test-token-123456789' for k in
                    ('caller', 'limited', 'expired', 'wrong_audience', 'revocable', 'budget', 'invalid')}}
    cfg = configure(tmp_path, monkeypatch, endpoints)
    path = Path(cfg.control_manifest)
    plan = json.loads(path.read_text())
    if change == 'target':
        plan['mcp_url'] = 'http://127.0.0.1:10/mcp'
    elif change == 'credential':
        plan['cases'][0]['credential'] = 'unknown'
    elif change == 'no-positive':
        plan['cases'] = [c for c in plan['cases'] if c['expect'] == 'deny']
    elif change == 'duplicate':
        plan['cases'][1]['id'] = plan['cases'][0]['id']
    elif change == 'deny-state':
        plan['cases'][1]['after'] = {}
    else:
        del plan['cases'][1]['denial_code']
    path.write_text(json.dumps(plan))
    with pytest.raises(ValueError):
        load_plan(cfg)


@pytest.mark.parametrize('fault', ['rpc-error', 'malformed-result', 'cleanup-failure', 'wrong-protocol'])
def test_bad_protocol_evidence_and_cleanup_are_not_passes(tmp_path, monkeypatch, server, fault):
    from blastcontain_verify.mcp_scenarios import ScenarioClient
    original = ScenarioClient.rpc
    original_control = ScenarioClient.control

    def rpc(self, method, params, token, notification=False):
        status, data = original(self, method, params, token, notification)
        if fault == 'wrong-protocol' and method == 'initialize':
            data['result']['protocolVersion'] = 'unknown'
        if method == 'tools/call' and status == 200:
            if fault == 'malformed-result':
                data['result'] = []
            elif fault == 'rpc-error' and data.get('result', {}).get('isError'):
                data.pop('result')
                data['error'] = {'code': -32602, 'message': 'Invalid arguments'}
        return status, data

    def control(self, operation, *args, **kwargs):
        result = original_control(self, operation, *args, **kwargs)
        return {'deleted': False} if fault == 'cleanup-failure' and operation == 'delete' else result

    monkeypatch.setattr(ScenarioClient, 'rpc', rpc)
    monkeypatch.setattr(ScenarioClient, 'control', control)
    with server() as endpoints:
        report = validate_controls(configure(tmp_path, monkeypatch, endpoints))
        if fault == 'rpc-error':
            assert any(c['status'] == 'FAIL' for c in report['checks'])
        else:
            assert not report['complete']
        assert not endpoints['runs']


def test_partial_controls_remain_coverage_gap(tmp_path, monkeypatch, server):
    from blastcontain_verify.models import ScanStatus
    with server() as endpoints:
        cfg = configure(tmp_path, monkeypatch, endpoints)
        path = Path(cfg.control_manifest)
        plan = json.loads(path.read_text())
        plan['cases'] = [c for c in plan['cases'] if c['check_id'] == 'CTL-01']
        path.write_text(json.dumps(plan))
        result = run_scan(cfg)
        assert result.validation['complete']
        assert result.validation['not_tested_controls'] == ['CTL-02', 'CTL-03', 'CTL-04', 'CTL-05', 'CTL-06']
        assert not result.coverage['complete']
        assert result.status == ScanStatus.ERROR


def test_direct_scenario_api_requires_consent(tmp_path, monkeypatch):
    from blastcontain_verify.mcp_scenarios import validate_scenarios
    cfg = VerifyConfig(target_type='mcp', target_id='target', control_manifest='not-opened.json')
    with pytest.raises(ValueError, match='supplied together'):
        validate_scenarios(cfg)


@pytest.mark.parametrize('headers,status,body', [
    ({'Mcp-Session-Id': 'unexpected'}, 200, b'{}'),
    ({'Content-Type': 'text/event-stream'}, 200, b'data: {}\n\n'),
    ({}, 202, b'unexpected body'),
])
def test_unsupported_transport_rejected(headers, status, body):
    import httpx
    from blastcontain_verify.mcp_scenarios import JsonTransport
    transport = JsonTransport()
    transport.inner.close()
    transport.inner = httpx.MockTransport(lambda request: httpx.Response(status, headers=headers, stream=httpx.ByteStream(body)))
    with httpx.Client(transport=transport, trust_env=False) as client:
        with pytest.raises(ValueError):
            client.post('http://127.0.0.1:1/mcp', json={})


def test_transport_does_not_follow_redirects():
    import httpx
    from blastcontain_verify.mcp_scenarios import JsonTransport, ScenarioClient
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(307, headers={'Location': 'http://127.0.0.1:2/steal'}, json={})

    transport = JsonTransport()
    transport.inner.close()
    transport.inner = httpx.MockTransport(respond)
    with httpx.Client(transport=transport, trust_env=False, follow_redirects=False) as client:
        runner = ScenarioClient({'mcp_url': 'http://127.0.0.1:1/mcp'}, 'observer-test-token', client)
        status, _ = runner.rpc('tools/list', {}, 'caller-test-token')
        assert status == 307
        assert len(requests) == 1
        assert requests[0].url.port == 1
