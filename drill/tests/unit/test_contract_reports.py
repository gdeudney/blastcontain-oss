"""Keep existing signed packets and diff consumers stable through the wrappers."""

import json
import os
from pathlib import Path
import runpy

from blastcontain_core.signing import verify_packet
from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.contracts.legacy import LegacyCageAdapter, LegacyEvaluatorAdapter
from blastcontain_drill.diff import diff_reports, load_report
from blastcontain_drill.reporter import write_drill_packet
from blastcontain_drill.scoring import HeuristicContentScorer

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_signed_legacy_report_and_wrapped_report_have_identical_payloads(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("BLASTCONTAIN_SIGNING_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "local-verify-default")
    baseline_path = FIXTURES / "contracts-v1-signed-report.json"
    baseline = json.loads(baseline_path.read_text())
    assert baseline["schema_version"] == "1.1"
    assert baseline["signature"]["advisory"] is True
    assert verify_packet(baseline)
    # This is a trusted repository fixture generator, never a plugin or user path.
    capture = runpy.run_path(str(FIXTURES / "capture_signed_baseline.py"))["capture_report"]
    cage = LegacyCageAdapter(
        InProcessCage(StubChatClient(True)),
        capabilities=(
            "prompt.single",
            "prompt.multiturn",
            "inject.document",
            "inject.mcp_description",
            "inject.mcp_response",
        ),
        observations=("model_output", "tool_actions", "payload_delivery"),
    )
    report = capture(cage, [LegacyEvaluatorAdapter(HeuristicContentScorer())])
    output = tmp_path / "wrapped.json"
    packet = write_drill_packet(report, str(output))
    assert verify_packet(packet)
    assert packet["packet"] == baseline["packet"]
    delta = diff_reports(load_report(str(baseline_path)), load_report(str(output)))
    assert not any(delta["counts"].values())
    packet["packet"]["findings"][0]["outcome"] = "ERROR"
    assert not verify_packet(packet)
