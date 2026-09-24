"""Write the legacy report fixture to a NEW directory for reviewed comparisons.

From the repo root: PYTHONPATH=core:drill python
    drill/tests/fixtures/capture_signed_baseline.py /tmp/drill-baseline-review
No live model or service is called. The public default signing key is advisory.
"""

from pathlib import Path
import os
import sys
from unittest.mock import patch

from blastcontain_core.models import DrillReport
from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.corpus import BuiltinReplaySource, JailbreakBenchSource, MCPPoisoningSource
from blastcontain_drill.corpus.base import Corpus
from blastcontain_drill.reporter import write_drill_packet
from blastcontain_drill.runner import run_corpus
from blastcontain_drill.scoring import HeuristicContentScorer


def representative_corpus():
    sources = [BuiltinReplaySource(), MCPPoisoningSource()]
    attacks = [attack for source in sources for attack in source.dataset()]
    jbb = JailbreakBenchSource()
    attacks.extend([jbb.dataset()[0], next(a for a in jbb.dataset() if not a.expected_refusal)])
    return Corpus(
        "contracts-v1-baseline", attacks, [f"{s.name}@{s.revision}" for s in [*sources, jbb]]
    )


def capture_report(cage=None, scorers=None):
    corpus = representative_corpus()
    with patch(
        "blastcontain_drill.cage.inprocess.new_canary", return_value="BCN-CANARY-compatibility"
    ):
        findings = run_corpus(
            cage or InProcessCage(StubChatClient(True)),
            corpus,
            scorers or [HeuristicContentScorer()],
        )
    for finding in findings:
        if finding.outcome.value == "ERROR":
            raise RuntimeError(f"Baseline fixture failed: {finding.attack_id}")
        finding.detection_latency_ms = 0.0  # timing is not part of the semantic baseline
    report = DrillReport(
        "contracts-baseline",
        "dev",
        corpus.version,
        corpus.sources,
        drill_id="00000000-0000-0000-0000-000000000001",
        drilled_at="2026-09-20T00:00:00Z",
        target_model="stub",
        cage="inprocess",
        findings=findings,
    )
    report.status = report.derive_status()
    return report


if __name__ == "__main__":
    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=False)
    report = capture_report()
    # Explicit, public fixture key; never capture a developer's real signing key.
    with (
        patch.dict(os.environ, {"BLASTCONTAIN_SIGNING_KEY": "local-verify-default"}, clear=True),
        patch("blastcontain_drill.reporter._utc_now_iso", return_value=report.drilled_at),
    ):
        write_drill_packet(report, str(output / "contracts-v1-signed-report.json"))
    print(f"Captured {len(report.findings)} controlled findings in {output}")
