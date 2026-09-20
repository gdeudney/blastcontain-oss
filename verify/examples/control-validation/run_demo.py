"""Compare enforced and broken synthetic controls; save redacted Verify artifacts."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from service import fixture

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output-dir', type=Path, required=True)
args = parser.parse_args()
for mode in ('enforced', 'broken'):
    directory = args.output_dir.resolve() / mode
    directory.mkdir(parents=True, exist_ok=True)
    admin = secrets.token_urlsafe(32)
    with fixture(admin, insecure=mode == 'broken') as endpoints:
        (directory / 'mcp.json').write_text(json.dumps({'mcpServers': {'fixture': {
            'url': endpoints['mcp_url'], 'auth': {'type': 'bearer'}, 'tools': ['update_customer'],
        }}}), encoding='utf-8')
        (directory / 'policy.json').write_text(json.dumps({
            'target_id': 'synthetic', 'permitted_tools': ['update_customer'],
        }), encoding='utf-8')
        (directory / 'validation.json').write_text(json.dumps({
            'adapter': 'customer-record-v1', 'target_id': 'synthetic',
            'mcp_url': endpoints['mcp_url'], 'control_url': endpoints['control_url'],
            'admin_token_env': 'VERIFY_FIXTURE_ADMIN_TOKEN',
        }), encoding='utf-8')
        environment = {**os.environ, 'VERIFY_FIXTURE_ADMIN_TOKEN': admin}
        command = [sys.executable, '-c', 'from blastcontain_verify.cli import main; main()', '--target-type', 'mcp',
                   '--target-id', 'synthetic', '--mcp-config', str(directory / 'mcp.json'),
                   '--policy', str(directory / 'policy.json'),
                   '--validate-controls', str(directory / 'validation.json'), '--allow-live-tests',
                   '--output', str(directory / 'audit.json'), '--report', str(directory / 'report.md'),
                   '--sarif', str(directory / 'scan.sarif')]
        result = subprocess.run(command, env=environment, capture_output=True, text=True, encoding='utf-8', timeout=75)
        (directory / 'console.txt').write_text(result.stdout + result.stderr, encoding='utf-8')
        if not (directory / 'audit.json').exists():
            raise RuntimeError(f'Verify did not write a packet; inspect {directory / "console.txt"}')
        packet = json.loads((directory / 'audit.json').read_text(encoding='utf-8'))
        validation = packet['packet']['control_validation']
        print(mode, 'exit:', result.returncode, 'checks:', {c['check_id']: c['status'] for c in validation['checks']}, flush=True)
        if not validation['complete'] or endpoints['runs']:
            raise RuntimeError('Validation or cleanup incomplete; inspect the saved report')
        expected = 'FAIL' if mode == 'broken' else 'PASS'
        if len(validation['checks']) != 6 or any(c['status'] != expected for c in validation['checks']):
            raise RuntimeError('Unexpected control result; inspect the saved report')
