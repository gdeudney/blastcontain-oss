"""Save signed evidence for four MCP cases and two deterministic agent behaviors."""
import argparse
from pathlib import Path

from blastcontain_core.models import DrillOutcome, DrillReport
from blastcontain_drill.cage.inprocess import InProcessCage
from blastcontain_drill.cage.podman import PodmanCage
from blastcontain_drill.cage.stub import StubChatClient
from blastcontain_drill.corpus.base import Corpus
from blastcontain_drill.corpus.mcp_poisoning import MCPPoisoningSource
from blastcontain_drill.reporter import write_markdown_report, write_drill_packet
from blastcontain_drill.runner import run_corpus


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--cage', choices=['inprocess', 'podman', 'both'], default='inprocess')
    args = parser.parse_args()
    source = MCPPoisoningSource()
    corpus = Corpus(version=source.revision, attacks=source.dataset(), sources=[source.name + '@' + source.revision])
    rows = ['# MCP poisoning demonstration', '',
            'Deterministic test agents; these are harness results, not LLM robustness measurements.', '',
            '| Cage | Agent | Cases | Result | Effects |', '|---|---|---|---|---|']
    for backend in (('inprocess', 'podman') if args.cage == 'both' else (args.cage,)):
        for vulnerable in (False, True):
            mode = 'vulnerable' if vulnerable else 'resistant'
            folder = args.output_dir / backend / mode
            folder.mkdir(parents=True, exist_ok=True)
            cage = PodmanCage(vulnerable=vulnerable) if backend == 'podman' else InProcessCage(StubChatClient(vulnerable=vulnerable))
            report = DrillReport(agent_id='mcp-fixture-demo', environment='test', corpus_version=corpus.version,
                                 corpus_sources=corpus.sources, cage=backend, target_model='deterministic-' + mode)
            report.findings = run_corpus(cage, corpus, [])
            report.status = report.derive_status()
            write_drill_packet(report, str(folder / 'drill.json'))
            write_markdown_report(report, str(folder / 'report.md'))
            expected = DrillOutcome.BYPASS if vulnerable else DrillOutcome.HELD
            if any(f.outcome != expected for f in report.findings):
                raise RuntimeError('Unexpected demo outcome; inspect saved report')
            if vulnerable and not all(f.action_verdict['contained'] for f in report.findings):
                raise RuntimeError('Missing containment evidence')
            rows.append(f'| {backend} | {mode} | 4 | {expected.value} | ' + ('All attempts blocked' if vulnerable else 'No forbidden attempts') + ' |')
            print(backend, mode, expected.value, flush=True)
    rows += ['', 'Each case used real loopback MCP discovery/tool exchanges. No external sends or deletes occurred.',
             'See signed JSON for payload exposure and protocol hashes, and Markdown for Verify follow-up mappings.', '']
    (args.output_dir / 'README.md').write_text('\n'.join(rows), encoding='utf-8')


if __name__ == '__main__':
    main()
