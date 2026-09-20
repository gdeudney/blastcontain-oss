"""Run CLI validation against an official SDK server; save redacted evidence."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from plan import manifest
from service import server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    summary = ['# Practical MCP validation demonstration', '',
               'Official MCP SDK server; real signed JWT validation; synthetic records.', '',
               '| Controls | Enforced | Broken |', '|---|---|---|']
    reports = {}
    for mode in ('enforced', 'broken'):
        folder = args.output_dir.resolve() / mode
        folder.mkdir(parents=True, exist_ok=True)
        with server(insecure=mode == 'broken') as endpoints:
            plan = manifest(endpoints)
            for name, value in {'validation': plan, 'mcp': {'mcpServers': {'reference': {
                    'url': endpoints['mcp_url'], 'auth': {'type': 'bearer'}, 'tools': ['update_record']}}},
                    'policy': {'target_id': 'reference-mcp', 'permitted_tools': ['update_record']}}.items():
                (folder / f'{name}.json').write_text(json.dumps(value, indent=2), encoding='utf-8')
            env = {**os.environ, 'VERIFY_OBSERVER_TOKEN': endpoints['admin'],
                   **{'VERIFY_CALLER_' + role.upper(): token for role, token in endpoints['tokens'].items()}}
            command = [sys.executable, '-c', 'from blastcontain_verify.cli import main; main()',
                       '--target-type', 'mcp', '--target-id', 'reference-mcp',
                       '--mcp-config', str(folder / 'mcp.json'), '--policy', str(folder / 'policy.json'),
                       '--validate-controls', str(folder / 'validation.json'), '--allow-live-tests',
                       '--output', str(folder / 'audit.json'), '--report', str(folder / 'report.md'),
                       '--sarif', str(folder / 'scan.sarif')]
            process = subprocess.run(command, env=env, capture_output=True, text=True, encoding='utf-8', timeout=90)
            (folder / 'console.txt').write_text(process.stdout + process.stderr, encoding='utf-8')
            packet = json.loads((folder / 'audit.json').read_text(encoding='utf-8'))['packet']
            report = packet['control_validation']
            if not report['complete'] or endpoints['runs'] or process.returncode != 1:
                raise RuntimeError('Incomplete validation, unexpected overall status, or cleanup failure')
            expected = 'PASS' if mode == 'enforced' else 'FAIL'
            if len(report['checks']) != 6 or any(c['status'] != expected for c in report['checks']):
                raise RuntimeError('Unexpected control results')
            reports[mode] = report
            print(mode, {c['check_id']: c['status'] for c in report['checks']}, flush=True)
    for first, second in zip(reports['enforced']['checks'], reports['broken']['checks']):
        summary.append(f"| {first['check_id']} {first['title']} | {first['status']} | {second['status']} |")
    summary.extend(['', 'Each run exercises 21 cases. Both namespaces are deleted and servers stopped.', '',
                    'Both overall scans remain REJECTED because passive assessment flags loopback HTTP.',
                    'This tests the stated cases, not full OAuth conformance or a production deployment.', '',
                    'See enforced/report.md and broken/report.md for evidence and limitations.', ''])
    (args.output_dir / 'README.md').write_text('\n'.join(summary), encoding='utf-8')


if __name__ == '__main__':
    main()
