"""Real loopback fixture tests: positive controls, state-based denials and opt-in."""
import json
from pathlib import Path
import runpy
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from blastcontain_verify.cli import main
from blastcontain_verify.config import VerifyConfig
from blastcontain_verify.control_validation import CHECKS, _loopback_url, validate_controls
from blastcontain_verify.models import ScanStatus
from blastcontain_verify.scanner import run_scan

fixture = runpy.run_path(str(Path(__file__).parents[2] / 'examples/control-validation/service.py'))['fixture']


def config(tmp_path, endpoints):
    manifest = tmp_path / 'validation.json'
    manifest.write_text(json.dumps({
        'adapter': 'customer-record-v1', 'target_id': 'synthetic',
        'mcp_url': endpoints['mcp_url'], 'control_url': endpoints['control_url'],
        'admin_token_env': 'VERIFY_FIXTURE_ADMIN_TOKEN',
    }))
    mcp = tmp_path / 'mcp.json'
    mcp.write_text(json.dumps({'mcpServers': {'fixture': {
        'url': endpoints['mcp_url'], 'auth': {'type': 'bearer'}, 'tools': ['update_customer'],
    }}}))
    policy = tmp_path / 'policy.json'
    policy.write_text('{"target_id":"synthetic","permitted_tools":["update_customer"]}')
    return VerifyConfig(target_type='mcp', target_id='synthetic', mcp_config=str(mcp),
                        policy=str(policy), control_manifest=str(manifest), allow_live_tests=True)


@pytest.mark.parametrize('insecure', [False, True])
def test_secure_fixture_passes_and_broken_fixture_fails_each_control(tmp_path, monkeypatch, insecure):
    admin = 'synthetic-admin-test-token-12345'
    monkeypatch.setenv('VERIFY_FIXTURE_ADMIN_TOKEN', admin)
    with fixture(admin, insecure=insecure) as endpoints:
        result = run_scan(config(tmp_path, endpoints))
        validation = result.validation
        assert validation['complete'], validation
        assert validation['cleanup_complete']
        assert endpoints['runs'] == {}
        assert len(validation['checks']) == 6
        assert {c['status'] for c in validation['checks']} == ({'FAIL'} if insecure else {'PASS'})
        assert validation['requests_sent'] <= 100
        assert admin not in json.dumps(result.as_dict())
        assert result.coverage['tools_invoked']
        assert result.status == ScanStatus.REJECTED  # HTTP fixture config is still a finding.
        if insecure:
            assert set(CHECKS) <= {f.check_id for f in result.findings}
        else:
            assert set(CHECKS) <= set(result.passed)


def test_live_requests_need_both_flags(tmp_path, monkeypatch):
    forbidden = Mock(side_effect=AssertionError('network must not be used'))
    monkeypatch.setattr('httpx.Client', forbidden)
    runner = CliRunner()
    for options in (['--validate-controls', 'fixture.json'], ['--allow-live-tests']):
        result = runner.invoke(main, ['--target-type', 'mcp', '--target-id', 'synthetic',
                                      '--mcp-config', 'mcp.json', *options])
        assert result.exit_code == 3
    forbidden.assert_not_called()


@pytest.mark.parametrize('url', ['https://example.com/mcp', 'http://localhost/mcp',
                               'http://169.254.169.254/mcp', 'http://127.0.0.1/mcp?token=x',
                               'http://user:password@127.0.0.1/mcp', 'file:///tmp/mcp'])
def test_only_literal_loopback_is_accepted(url):
    with pytest.raises(ValueError):
        _loopback_url(url)


def test_missing_credential_fails_before_connecting(tmp_path, monkeypatch):
    monkeypatch.delenv('VERIFY_FIXTURE_ADMIN_TOKEN', raising=False)
    endpoints = {'mcp_url': 'http://127.0.0.1:8/mcp', 'control_url': 'http://127.0.0.1:9'}
    cfg = config(tmp_path, endpoints)
    forbidden = Mock(side_effect=AssertionError('network must not be used'))
    monkeypatch.setattr('httpx.Client', forbidden)
    result = run_scan(cfg)
    assert result.status == ScanStatus.ERROR
    assert not result.coverage['complete']
    forbidden.assert_not_called()


def test_wrong_control_credential_cannot_be_reported_as_pass(tmp_path, monkeypatch):
    monkeypatch.setenv('VERIFY_FIXTURE_ADMIN_TOKEN', 'wrong-synthetic-token-123456')
    with fixture('correct-synthetic-token-123456') as endpoints:
        report = validate_controls(config(tmp_path, endpoints))
        assert not report['complete']
        assert 'setup_error' in report
        assert endpoints['runs'] == {}


def test_no_validation_with_incomplete_passive_coverage(tmp_path, monkeypatch):
    cfg = config(tmp_path, {'mcp_url': 'http://127.0.0.1:8/mcp', 'control_url': 'http://127.0.0.1:9'})
    cfg.policy = None
    forbidden = Mock(side_effect=AssertionError('network must not be used'))
    monkeypatch.setattr('httpx.Client', forbidden)
    result = run_scan(cfg)
    assert result.status == ScanStatus.ERROR
    assert not result.validation['complete']
    forbidden.assert_not_called()


@pytest.mark.parametrize('fault', ['deny_all', 'mutate_denials'])
def test_response_only_or_deny_everything_cannot_pass(tmp_path, monkeypatch, fault):
    admin = 'synthetic-admin-test-token-12345'
    monkeypatch.setenv('VERIFY_FIXTURE_ADMIN_TOKEN', admin)
    with fixture(admin, **{fault: True}) as endpoints:
        report = validate_controls(config(tmp_path, endpoints))
        assert report['complete']
        assert {c['status'] for c in report['checks']} == {'FAIL'}
        assert endpoints['runs'] == {}


def test_endpoint_mismatch_is_rejected_without_requests(tmp_path, monkeypatch):
    monkeypatch.setenv('VERIFY_FIXTURE_ADMIN_TOKEN', 'synthetic-admin-test-token-12345')
    cfg = config(tmp_path, {'mcp_url': 'http://127.0.0.1:8/mcp', 'control_url': 'http://127.0.0.1:9'})
    data = json.loads(Path(cfg.control_manifest).read_text())
    data['mcp_url'] = 'http://127.0.0.1:10/mcp'
    Path(cfg.control_manifest).write_text(json.dumps(data))
    forbidden = Mock(side_effect=AssertionError('network must not be used'))
    monkeypatch.setattr('httpx.Client', forbidden)
    assert run_scan(cfg).status == ScanStatus.ERROR
    forbidden.assert_not_called()


def test_redirects_are_not_followed_and_cleanup_errors_are_visible(tmp_path, monkeypatch):
    import httpx
    from blastcontain_verify import control_validation
    monkeypatch.setenv('VERIFY_FIXTURE_ADMIN_TOKEN', 'synthetic-admin-test-token-12345')
    cfg = config(tmp_path, {'mcp_url': 'http://127.0.0.1:8/mcp', 'control_url': 'http://127.0.0.1:9'})
    requests = []
    real_client = httpx.Client

    def response(request):
        requests.append(request)
        return httpx.Response(302, headers={'Location': 'https://external.invalid'}, json={})

    def client(**kwargs):
        assert kwargs == {'trust_env': False, 'follow_redirects': False}
        return real_client(transport=httpx.MockTransport(response), **kwargs)

    monkeypatch.setattr(control_validation.httpx, 'Client', client)
    report = validate_controls(cfg)
    assert not report['complete']
    assert not report['cleanup_complete']
    assert len(requests) == 2  # attempted setup and scoped cleanup, no redirect follow
    assert all(r.url.host == '127.0.0.1' for r in requests)


def test_yaml_cannot_grant_cli_live_consent(tmp_path, monkeypatch):
    config_file = tmp_path / 'verify.yaml'
    config_file.write_text('target_type: mcp\ntarget_id: synthetic\nmcp_config: mcp.json\n'
                           'control_manifest: validation.json\nallow_live_tests: true\n')
    forbidden = Mock(side_effect=AssertionError('network must not be used'))
    monkeypatch.setattr('httpx.Client', forbidden)
    result = CliRunner().invoke(main, ['--config', str(config_file)])
    assert result.exit_code == 3
    forbidden.assert_not_called()


def test_direct_api_requires_consent(tmp_path, monkeypatch):
    cfg = config(tmp_path, {'mcp_url': 'http://127.0.0.1:8/mcp', 'control_url': 'http://127.0.0.1:9'})
    cfg.allow_live_tests = False
    forbidden = Mock(side_effect=AssertionError('network must not be used'))
    monkeypatch.setattr('httpx.Client', forbidden)
    with pytest.raises(ValueError):
        validate_controls(cfg)
    forbidden.assert_not_called()


def test_response_and_request_bounds_reserve_cleanup():
    import httpx
    from blastcontain_verify.control_validation import FixtureClient
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={})))
    with client:
        bounded = FixtureClient({}, 'synthetic', client)
        bounded.count = 99
        with pytest.raises(ValueError):
            bounded.request('GET', 'http://127.0.0.1/unused')
        assert bounded.count == 99
        assert bounded.request('DELETE', 'http://127.0.0.1/unused', cleanup=True)[0] == 200
        assert bounded.count == 100
        with pytest.raises(ValueError):
            bounded.request('DELETE', 'http://127.0.0.1/unused', cleanup=True)
    with httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b'x' * 65537))) as client:
        bounded = FixtureClient({}, 'synthetic', client)
        with pytest.raises(ValueError, match='exceeded bounds'):
            bounded.request('GET', 'http://127.0.0.1/unused')
