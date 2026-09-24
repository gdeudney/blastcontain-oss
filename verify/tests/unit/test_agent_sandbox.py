"""Bounded agent probes: no false passes on missing evidence or cleanup errors."""
import errno
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from blastcontain_verify import agent_sandbox as sandbox
from blastcontain_verify.cli import main
from blastcontain_verify.config import VerifyConfig
from blastcontain_verify.models import ScanResult, ScanStatus


def config(tmp_path):
    work, protected = tmp_path / 'work', tmp_path / 'protected'
    work.mkdir()
    protected.mkdir()
    readable, secret = tmp_path / 'readable', tmp_path / 'dummy'
    readable.write_bytes(b'public')
    secret.write_bytes(b'dummy-credential')
    plan = {'adapter': 'agent-sandbox-v1', 'agent_id': 'test', 'writable_directory': str(work),
            'protected_directory': str(protected),
            'readable_canary': {'path': str(readable), 'sha256': hashlib.sha256(b'public').hexdigest()},
            'forbidden_canary': {'path': str(secret), 'sha256': hashlib.sha256(b'dummy-credential').hexdigest()},
            'network': {'host': '10.20.30.40', 'port': 18081}}
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(plan))
    return VerifyConfig(agent_id='test', control_manifest=str(path), allow_live_tests=True), plan


@pytest.mark.skipif(os.name != 'posix', reason='Linux descriptor probes')
def test_write_probe_creates_only_new_file_and_cleans(tmp_path):
    original = tmp_path / 'keep'
    original.write_text('unchanged')
    result = sandbox.probe_write(str(tmp_path), 'write')
    assert result['outcome'] == 'allowed' and result['cleanup_complete']
    assert list(tmp_path.iterdir()) == [original]
    assert original.read_text() == 'unchanged'


@pytest.mark.skipif(os.name != 'posix', reason='Linux descriptor probes')
def test_missing_path_and_symlinks_are_errors(tmp_path):
    assert sandbox.probe_write(str(tmp_path / 'missing'), 'missing')['outcome'] == 'error'
    link = tmp_path / 'link'
    link.symlink_to(tmp_path, target_is_directory=True)
    assert sandbox.probe_write(str(link), 'link')['outcome'] == 'error'
    (tmp_path / 'file').write_bytes(b'canary')
    (tmp_path / 'file-link').symlink_to(tmp_path / 'file')
    assert sandbox.probe_read({'path': str(tmp_path / 'file-link'), 'sha256': hashlib.sha256(b'canary').hexdigest()}, 'link')['outcome'] == 'error'


@pytest.mark.skipif(os.name != 'posix', reason='Linux descriptor probes')
def test_canary_must_match_and_be_regular(tmp_path):
    path = tmp_path / 'canary'
    path.write_bytes(b'not-a-real-secret')
    expected = {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
    assert sandbox.probe_read(expected, 'canary')['outcome'] == 'allowed'
    assert 'not-a-real-secret' not in json.dumps(sandbox.probe_read(expected, 'canary'))
    expected['sha256'] = '0' * 64
    assert sandbox.probe_read(expected, 'canary')['outcome'] == 'error'
    expected['path'] = str(tmp_path)
    assert sandbox.probe_read(expected, 'directory')['outcome'] == 'error'


@pytest.mark.skipif(os.name != 'posix', reason='Linux descriptor probes')
def test_cleanup_failure_keeps_recovery_path(tmp_path, monkeypatch):
    original = os.unlink
    monkeypatch.setattr(os, 'unlink', Mock(side_effect=OSError(errno.EACCES, 'denied')))
    result = sandbox.probe_write(str(tmp_path), 'write')
    assert not result['cleanup_complete']
    assert result['recovery_path'].startswith(str(tmp_path) + '/.verify-sandbox-')
    monkeypatch.setattr(os, 'unlink', original)
    Path(result['recovery_path']).unlink()


@pytest.mark.parametrize('error,expected', [(errno.EACCES, 'PASS'), (errno.ENETUNREACH, 'PASS'),
                                            (errno.ECONNREFUSED, 'ERROR'), (errno.EHOSTUNREACH, 'ERROR'),
                                            (errno.ETIMEDOUT, 'ERROR')])
def test_network_denial_requires_real_boundary_evidence(monkeypatch, error, expected):
    listener = Mock()
    listener.__enter__ = Mock(return_value=listener)
    listener.__exit__ = Mock(return_value=False)
    listener.getsockname.return_value = ('127.0.0.1', 12345)
    listener.accept.return_value = (Mock(), ('127.0.0.1', 1))
    allowed = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
    monkeypatch.setattr(sandbox.socket, 'socket', Mock(return_value=listener))
    monkeypatch.setattr(sandbox.socket, 'create_connection', Mock(side_effect=[allowed, OSError(error, 'blocked')]))
    assert sandbox.probe_network({'host': '10.20.30.40', 'port': 18081})['status'] == expected


def test_connection_then_io_denial_is_still_failed_containment(monkeypatch):
    listener = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
    listener.__enter__.return_value = listener
    listener.getsockname.return_value = ('127.0.0.1', 12345)
    listener.accept.return_value = (Mock(), ('127.0.0.1', 1))
    connection = Mock(__enter__=Mock(), __exit__=Mock(return_value=False))
    connection.sendall.side_effect = PermissionError(errno.EACCES, 'blocked after connection')
    monkeypatch.setattr(sandbox.socket, 'socket', Mock(return_value=listener))
    monkeypatch.setattr(sandbox.socket, 'create_connection', Mock(return_value=connection))
    assert sandbox.probe_network({'host': '10.20.30.40', 'port': 18081})['status'] == 'FAIL'


@pytest.mark.parametrize('mutation', ['target', 'public-ip', 'metadata-ip', 'same-path', 'relative-path', 'unknown-key'])
def test_invalid_manifest_is_rejected(tmp_path, mutation):
    cfg, plan = config(tmp_path)
    if mutation == 'target':
        plan['agent_id'] = 'other'
    elif mutation == 'public-ip':
        plan['network']['host'] = '8.8.8.8'
    elif mutation == 'metadata-ip':
        plan['network']['host'] = '169.254.169.254'
    elif mutation == 'same-path':
        plan['protected_directory'] = plan['writable_directory']
    elif mutation == 'relative-path':
        plan['writable_directory'] = '../tmp'
    else:
        plan['command'] = 'not allowed'
    Path(cfg.control_manifest).write_text(json.dumps(plan))
    with pytest.raises(ValueError):
        sandbox.load_manifest(cfg)


def test_cli_yaml_cannot_authorize_live_probes(tmp_path, monkeypatch):
    cfg, _ = config(tmp_path)
    yaml = tmp_path / 'config.yaml'
    yaml.write_text(f'agent_id: test\ncontrol_manifest: {cfg.control_manifest}\nallow_live_tests: true\n')
    probe = Mock(side_effect=AssertionError('No live probes permitted'))
    monkeypatch.setattr(sandbox, 'validate_sandbox', probe)
    result = CliRunner().invoke(main, ['--config', str(yaml)])
    assert result.exit_code == 3
    probe.assert_not_called()


def test_cannot_suppress_sandbox_checks(tmp_path):
    cfg, _ = config(tmp_path)
    cfg.skip_checks = ['SBX-01']
    with pytest.raises(ValueError, match='suppressed'):
        sandbox.validate_sandbox(cfg)


def test_unsupported_platform_executes_nothing(tmp_path, monkeypatch):
    cfg, plan = config(tmp_path)
    for key in ('writable_directory', 'protected_directory'):
        plan[key] = '/' + key
    for key in ('readable_canary', 'forbidden_canary'):
        plan[key]['path'] = '/' + key
    Path(cfg.control_manifest).write_text(json.dumps(plan))
    monkeypatch.setattr(sandbox.sys, 'platform', 'win32')
    probe = Mock(side_effect=AssertionError('No writes'))
    monkeypatch.setattr(sandbox, 'probe_write', probe)
    assert not sandbox.validate_sandbox(cfg)['complete']
    probe.assert_not_called()


def test_incomplete_validation_and_prior_errors_remain_error(tmp_path, monkeypatch):
    cfg, _ = config(tmp_path)
    monkeypatch.setattr(sandbox, 'validate_sandbox', lambda cfg: {'complete': False, 'checks': []})
    result = sandbox.attach_sandbox(cfg, ScanResult(agent_id='test', environment='dev'))
    assert result.status == ScanStatus.ERROR
    assert 'sandbox_validation' in result.as_dict()
    monkeypatch.setattr(sandbox, 'validate_sandbox', lambda cfg: {'complete': True, 'checks': []})
    prior = ScanResult(agent_id='test', environment='dev', status=ScanStatus.ERROR)
    assert sandbox.attach_sandbox(cfg, prior).status == ScanStatus.ERROR


@pytest.mark.skipif(not hasattr(os, 'O_PATH'), reason='Linux O_PATH permission semantics')
def test_write_without_directory_listing_permission_is_not_denial(tmp_path):
    directory = tmp_path / 'write-only-directory'
    directory.mkdir()
    directory.chmod(0o300)  # create/traverse allowed, listing denied
    try:
        result = sandbox.probe_write(str(directory), 'write-only')
        assert result['outcome'] == 'allowed'
        assert result['cleanup_complete']
    finally:
        directory.chmod(0o700)


def test_sandbox_evidence_survives_all_report_formats(tmp_path):
    from blastcontain_core.signing import verify_packet
    from blastcontain_verify.reporter import write_audit_packet, write_markdown_report
    from blastcontain_verify.reporter_sarif import write_sarif
    report = {'adapter': 'agent-sandbox-v1', 'complete': True, 'checks': [
        {'check_id': 'SBX-01', 'status': 'PASS', 'cases': []}]}
    result = sandbox.AgentSandboxResult(agent_id='test', environment='staging', sandbox_validation=report)
    packet = write_audit_packet(result, str(tmp_path / 'audit.json'))
    assert packet['schema_version'] == '1.3'
    assert packet['packet']['sandbox_validation'] == report
    assert verify_packet(packet)
    write_markdown_report(result, str(tmp_path / 'report.md'))
    assert 'agent-sandbox-v1' in (tmp_path / 'report.md').read_text(encoding='utf-8')
    sarif = write_sarif(result, str(tmp_path / 'scan.sarif'))
    assert sarif['runs'][0]['invocations'][0]['properties']['sandbox_validation'] == report


def test_live_sandbox_cannot_run_through_api_without_consent(tmp_path):
    cfg, _ = config(tmp_path)
    cfg.allow_live_tests = False
    with pytest.raises(ValueError, match='supplied together'):
        sandbox.validate_sandbox(cfg)
