"""Compare live probes inside hardened and deliberately misconfigured agents."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid


def run(*args, timeout=180, check=True):
    result = subprocess.run(['podman', *args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'Podman operation failed: {args[0]}: {result.stderr[-2000:]}')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-image', default='localhost/blastcontain-verify:mcp-target')
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    suffix = uuid.uuid4().hex[:12]
    network, witness, image = 'verify-sbx-net-' + suffix, 'verify-sbx-witness-' + suffix, 'localhost/verify-sandbox:' + suffix
    agents = ['verify-sbx-' + mode + '-' + suffix for mode in ('hardened', 'broken')]
    cleanup = []
    packets = {}
    try:
        run('build', '--pull=never', '-t', image, '--build-arg', 'BASE_IMAGE=' + args.base_image,
            '-f', str(root / 'verify/examples/agent-sandbox/Containerfile'), str(root))
        run('network', 'create', '--internal', network)
        run('run', '-d', '--name', witness, '--network', network, '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--user=10001', '--pids-limit=32', '--memory=128m',
            '-v', str(root / 'verify/examples/agent-sandbox/witness.py') + ':/witness.py:ro',
            '--entrypoint=python', image, '-I', '-S', '/witness.py')
        inspected = json.loads(run('inspect', witness).stdout)[0]
        address = inspected['NetworkSettings']['Networks'][network]['IPAddress']
        # Prove the fixture listener works before and after scans. This check is
        # separate from the agent; a dead listener cannot be called containment.
        health_code = "import socket; s=socket.create_connection(('127.0.0.1',18081),2); s.sendall(b'VERIFY_SANDBOX_PROBE\\n'); assert s.recv(64)==b'VERIFY_SANDBOX_CANARY\\n'; s.close()"
        run('exec', witness, 'python', '-I', '-S', '-c', health_code)
        for mode, name in zip(('hardened', 'broken'), agents):
            folder = output / mode
            folder.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='verify-agent-sandbox-') as temp:
                fixtures = Path(temp)
                fixtures.chmod(0o755)
                for directory in ('input', 'protected', 'work', 'reports'):
                    (fixtures / directory).mkdir(mode=0o777)
                    (fixtures / directory).chmod(0o777)
                readable = b'verify-public-canary'
                (fixtures / 'input/readable').write_bytes(readable)
                manifest = {'adapter': 'agent-sandbox-v1', 'agent_id': 'demo-agent',
                            'writable_directory': '/work', 'protected_directory': '/protected',
                            'readable_canary': {'path': '/input/readable', 'sha256': hashlib.sha256(readable).hexdigest()},
                            'forbidden_canary': {'path': '/private-canary/token', 'sha256': hashlib.sha256(b'verify-dummy-credential-not-a-real-secret').hexdigest()},
                            'network': {'host': address, 'port': 18081}}
                (fixtures / 'input/validation.json').write_text(json.dumps(manifest))
                # Mount specification for the disposable container, not a host temp filename.
                options = ['--name', name, '--pids-limit=64', '--memory=1g', '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m',  # nosec B108
                           '-v', str(fixtures / 'input') + ':/input:ro',
                           '-v', str(fixtures / 'work') + ':/work:rw', '-v', str(fixtures / 'reports') + ':/reports:rw',
                           '-v', str(fixtures / 'protected') + ':/protected:' + ('ro' if mode == 'hardened' else 'rw')]
                if mode == 'hardened':
                    options += ['--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--network=none', '--user=10001']
                else:
                    # Still rootless and attached only to the disposable internal
                    # network. Never use --privileged, host namespaces or host secrets.
                    options += ['--network', network, '--user=0']
                result = run('run', *options, image, '--agent-id', 'demo-agent', '--env', 'staging',
                             '--search-path', '/scan', '--egress-probe-target', address + ':18081',
                             '--validate-controls', '/input/validation.json', '--allow-live-tests',
                             '--output', '/reports/audit.json', '--report', '/reports/report.md',
                             '--sarif', '/reports/scan.sarif', check=False)
                (folder / 'console.txt').write_text(result.stdout + result.stderr)
                (folder / 'validation.json').write_text(json.dumps(manifest, indent=2))
                if result.returncode not in (0, 1, 2) or any(not (fixtures / 'reports' / name).is_file() for name in ('audit.json', 'report.md', 'scan.sarif')):
                    raise RuntimeError(f'{mode}: CLI failed; inspect {folder / "console.txt"}')
                for artifact in (fixtures / 'reports').iterdir():
                    (folder / artifact.name).write_bytes(artifact.read_bytes())
                packet = json.loads((folder / 'audit.json').read_text())['packet']
                validation = packet['sandbox_validation']
                expected = 'PASS' if mode == 'hardened' else 'FAIL'
                if not validation['complete'] or len(validation['checks']) != 4 or any(c['status'] != expected for c in validation['checks']):
                    raise RuntimeError(f'{mode}: unexpected sandbox results; inspect {folder}')
                if list((fixtures / 'work').iterdir()) or list((fixtures / 'protected').iterdir()):
                    raise RuntimeError('Probe files were not cleaned')
                packets[mode] = validation
                print(mode, {c['check_id']: c['status'] for c in validation['checks']}, flush=True)
            run('rm', name)
        run('exec', witness, 'python', '-I', '-S', '-c', health_code)
    finally:
        for kind, name, command in [*(('container', name, ('rm', '-f', '--ignore', name)) for name in [*agents, witness]),
                                    ('network', network, ('network', 'rm', network)), ('image', image, ('rmi', image))]:
            result = run(*command, check=False)
            absent = run(kind, 'exists', name, check=False).returncode == 1
            cleanup.append({'kind': kind, 'name': name, 'removal_exit': result.returncode, 'absent': absent})
        (output / 'cleanup.json').write_text(json.dumps({'complete': all(item['absent'] for item in cleanup), 'resources': cleanup}, indent=2))
    if not all(item['absent'] for item in cleanup):
        raise RuntimeError('Container cleanup incomplete; inspect Podman resources')
    lines = ['# Live agent sandbox demonstration', '', '| Boundary | Hardened | Broken |', '|---|---|---|']
    for first, second in zip(packets['hardened']['checks'], packets['broken']['checks']):
        lines.append(f"| {first['title']} | {first['status']} | {second['status']} |")
    lines += ['', 'Probes ran inside each agent container under its own UID and namespaces.',
              'Only disposable files, a dummy credential, and an isolated TCP witness were used.',
              'The witness was healthy before and after testing. Probe files and Podman resources were removed.',
              'Full Verify packet status still includes baseline findings; a probe PASS does not override them.', '']
    (output / 'README.md').write_text('\n'.join(lines))


if __name__ == '__main__':
    main()
