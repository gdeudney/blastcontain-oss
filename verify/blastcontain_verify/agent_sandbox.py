"""Explicit, bounded probes of the invoking Linux agent's sandbox boundaries."""
from __future__ import annotations

from dataclasses import dataclass, field
import errno
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import uuid

from .mcp_target import _read_json, validate_target_config
from .models import InfraFinding, ScanResult, ScanStatus, Severity

CHECKS = {'SBX-01': 'Workspace and protected filesystem',
          'SBX-02': 'Dummy credential isolation',
          'SBX-03': 'Privilege restrictions', 'SBX-04': 'Network containment'}
_DENIED = {errno.EACCES, errno.EPERM, errno.EROFS}


@dataclass
class AgentSandboxResult(ScanResult):
    sandbox_validation: dict = field(default_factory=dict)

    def as_dict(self):
        data = super().as_dict()
        data['sandbox_validation'] = self.sandbox_validation
        return data


def _path(value):
    if (not isinstance(value, str) or not value.startswith('/') or len(value) > 4096 or value.count('/') > 32 or '\x00' in value
            or any(part in ('.', '..', '') for part in value.split('/')[1:])):
        raise ValueError('Probe paths must be absolute, normalized, non-root paths')
    return value


def load_manifest(cfg):
    plan, digest = _read_json(cfg.control_manifest)
    if set(plan) != {'adapter', 'agent_id', 'writable_directory', 'protected_directory',
                     'readable_canary', 'forbidden_canary', 'network'}:
        raise ValueError('Invalid agent sandbox manifest')
    if plan['adapter'] != 'agent-sandbox-v1' or plan['agent_id'] != cfg.agent_id:
        raise ValueError('Sandbox adapter or agent identity mismatch')
    directories = [_path(plan[key]) for key in ('writable_directory', 'protected_directory')]
    if directories[0] == directories[1]:
        raise ValueError('Positive and negative directories must differ')
    paths = []
    for key in ('readable_canary', 'forbidden_canary'):
        canary = plan[key]
        if (not isinstance(canary, dict) or set(canary) != {'path', 'sha256'}
                or not isinstance(canary['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', canary['sha256'])):
            raise ValueError('Canaries require a path and expected SHA-256')
        paths.append(_path(canary['path']))
    if paths[0] == paths[1]:
        raise ValueError('Positive and negative canaries must differ')
    network = plan['network']
    if not isinstance(network, dict) or set(network) != {'host', 'port'}:
        raise ValueError('A controlled private-network canary endpoint is required')
    if not isinstance(network['host'], str):
        raise ValueError('Network address must be a literal string')
    host = ipaddress.IPv4Address(network['host'])
    if not any(host in ipaddress.ip_network(net) for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')):
        raise ValueError('Network probe requires a literal RFC1918 IPv4 test endpoint')
    if type(network['port']) is not int or not 1024 <= network['port'] <= 65535:
        raise ValueError('Canary port must be an unprivileged TCP port')
    return plan, digest


def _directory(path):
    """Walk via directory descriptors: reject symlinks in every component."""
    fd = os.open('/', os.O_PATH | os.O_DIRECTORY)
    try:
        for component in path.split('/')[1:]:
            child = os.open(component, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def probe_write(path, label):
    name = '.verify-sandbox-' + uuid.uuid4().hex
    result = {'case': label, 'created': False, 'cleanup_complete': True}
    directory = None
    try:
        directory = _directory(path)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        result['created'] = True
        result['cleanup_complete'] = False
        try:
            os.write(fd, b'Verify synthetic sandbox probe\n')
            result['outcome'] = 'allowed'
        finally:
            os.close(fd)
    except OSError as exc:
        result['errno'] = exc.errno
        # If creation succeeded, a later I/O failure must not become a denial.
        result['outcome'] = 'denied' if not result['created'] and exc.errno in _DENIED else 'error'
    finally:
        if result['created']:
            try:
                os.unlink(name, dir_fd=directory)
                result['cleanup_complete'] = True
            except OSError:
                result['recovery_path'] = path + '/' + name
        if directory is not None:
            os.close(directory)
    return result


def probe_read(canary, label):
    directory = None
    try:
        parent, name = canary['path'].rsplit('/', 1)
        directory = _directory(parent) if parent else os.open('/', os.O_PATH | os.O_DIRECTORY)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return {'case': label, 'outcome': 'error'}
            raw = handle.read(4097)
        match = len(raw) <= 4096 and hashlib.sha256(raw).hexdigest() == canary['sha256']
        return {'case': label, 'outcome': 'allowed' if match else 'error', 'canary_matches': match}
    except OSError as exc:
        return {'case': label, 'outcome': 'denied' if exc.errno in _DENIED else 'error', 'errno': exc.errno}
    finally:
        if directory is not None:
            os.close(directory)


# Fixed child operation, no manifest-provided executable or code. Even on success
# the child exits immediately; it never launches a shell or touches another process.
_UID_PROBE = '''import os, sys
try:
    os.setuid(0)
except PermissionError:
    sys.exit(10)
except OSError:
    sys.exit(20)
else:
    sys.exit(0)
'''


def probe_privilege():
    try:
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        evidence = {'uid': os.geteuid(), 'effective_capabilities': int(status['CapEff'].strip(), 16),
                    'no_new_privileges': int(status['NoNewPrivs']), 'seccomp_mode': int(status['Seccomp'])}
        child = subprocess.run([sys.executable, '-I', '-S', '-c', _UID_PROBE],
                               env={}, cwd='/', capture_output=True, timeout=3, check=False)
        evidence['root_transition'] = {0: 'allowed', 10: 'denied'}.get(child.returncode, 'error')
        safe = (evidence['uid'] != 0 and evidence['effective_capabilities'] == 0
                and evidence['no_new_privileges'] == 1 and evidence['seccomp_mode'] == 2
                and evidence['root_transition'] == 'denied')
        return {'status': 'ERROR' if evidence['root_transition'] == 'error' else ('PASS' if safe else 'FAIL'),
                'cases': [{'case': 'privilege-boundary', **evidence}]}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        return {'status': 'ERROR', 'cases': [{'case': 'privilege-boundary', 'error': 'Privilege evidence unavailable'}]}


def probe_network(endpoint):
    cases = []
    try:
        # A local positive control proves the process can create and use TCP
        # sockets. It does not establish that the forbidden endpoint is healthy.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.settimeout(1)
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname(), timeout=1):
                connection, _ = listener.accept()
                connection.close()
        cases.append({'case': 'loopback-positive', 'outcome': 'allowed'})
    except OSError:
        return {'status': 'ERROR', 'cases': [{'case': 'loopback-positive', 'outcome': 'error'}]}
    try:
        connection = socket.create_connection((endpoint['host'], endpoint['port']), timeout=2)
    except OSError as exc:
        # Closed ports, unreachable hosts and timeouts can mean a dead fixture.
        denied = exc.errno in (errno.EACCES, errno.EPERM, errno.ENETUNREACH)
        cases.append({'case': 'forbidden-endpoint', 'outcome': 'denied' if denied else 'error', 'errno': exc.errno})
        return {'status': 'PASS' if denied else 'ERROR', 'cases': cases}
    confirmed = False
    with connection:
        try:
            connection.sendall(b'VERIFY_SANDBOX_PROBE\n')
            confirmed = connection.recv(64) == b'VERIFY_SANDBOX_CANARY\n'
        except OSError:
            pass  # Connection already succeeded; later I/O cannot turn it into PASS.
    cases.append({'case': 'forbidden-endpoint', 'outcome': 'allowed', 'canary_confirmed': confirmed})
    return {'status': 'FAIL', 'cases': cases}


def validate_sandbox(cfg):
    validate_target_config(cfg)
    if cfg.target_type != 'agent' or not cfg.control_manifest or not cfg.allow_live_tests:
        raise ValueError('Agent sandbox validation requires explicit live opt-in')
    plan, digest = load_manifest(cfg)
    report = {'adapter': 'agent-sandbox-v1', 'manifest_sha256': digest, 'checks': [],
              'complete': False, 'cleanup_complete': True,
              'limitations': ['Invoking process only: run inside the actual agent namespace with the same UID and privileges',
                              'Fixed fixture paths and one TCP destination; not proof of all filesystem, credential or egress isolation',
                              'Kernel flags are observed; this is not a kernel escape, seccomp bypass, DNS, noexec or resource-exhaustion test',
                              'Requires trustworthy canary provisioning; not attestation against a compromised verifier']}
    if not sys.platform.startswith('linux'):
        report['reason'] = 'This live sandbox profile requires Linux; no probes executed'
        return report
    report['runtime'] = {'pid': os.getpid(), 'uid': os.geteuid(),
                         'namespaces': {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt', 'net', 'pid')}}
    positive = probe_write(plan['writable_directory'], 'workspace-write')
    negative = probe_write(plan['protected_directory'], 'protected-write')
    cleaned = positive['cleanup_complete'] and negative['cleanup_complete']
    outcomes = [positive['outcome'], negative['outcome']]
    status = 'ERROR' if 'error' in outcomes or not cleaned else ('PASS' if outcomes == ['allowed', 'denied'] else 'FAIL')
    report['cleanup_complete'] = cleaned
    report['checks'].append({'check_id': 'SBX-01', 'title': CHECKS['SBX-01'], 'status': status, 'cases': [positive, negative]})
    positive = probe_read(plan['readable_canary'], 'readable-canary')
    negative = probe_read(plan['forbidden_canary'], 'forbidden-canary')
    outcomes = [positive['outcome'], negative['outcome']]
    status = 'ERROR' if 'error' in outcomes else ('PASS' if outcomes == ['allowed', 'denied'] else 'FAIL')
    report['checks'].append({'check_id': 'SBX-02', 'title': CHECKS['SBX-02'], 'status': status, 'cases': [positive, negative]})
    for check, result in (('SBX-03', probe_privilege()), ('SBX-04', probe_network(plan['network']))):
        report['checks'].append({'check_id': check, 'title': CHECKS[check], **result})
    report['complete'] = cleaned and all(c['status'] != 'ERROR' for c in report['checks'])
    return report


def attach_sandbox(cfg, result):
    try:
        report = validate_sandbox(cfg)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        report = {'adapter': 'agent-sandbox-v1', 'complete': False,
                  'reason': 'Invalid manifest or unavailable runtime evidence; details omitted', 'checks': []}
    combined = AgentSandboxResult(**vars(result), sandbox_validation=report)
    for check in report['checks']:
        if check['status'] == 'PASS':
            combined.passed.append(check['check_id'])
        elif check['status'] == 'FAIL':
            combined.findings.append(InfraFinding(
                check_id=check['check_id'], finding_type='blastcontain.sandbox.validation_failed',
                severity=Severity.HIGH, title=check['title'] + ' validation failed',
                detail='The observed sandbox boundary did not meet the declared expectation.',
                remediation='Fix the agent runtime permissions or containment policy and repeat the live check.',
                evidence='Bounded live probe; dummy data only; see sandbox_validation cases.',
            ))
    combined.status = (combined.derive_status() if report['complete'] and result.status != ScanStatus.ERROR else ScanStatus.ERROR)
    return combined
