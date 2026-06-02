"""Reporter — signed packet round-trip and Markdown rendering."""
from __future__ import annotations

import json
import os

from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.reporter import write_drill_packet, write_markdown_report
from blastcontain_drill.runner import run_corpus
from blastcontain_drill.scoring import HeuristicContentScorer
from blastcontain_core.models import DrillReport
from blastcontain_core.signing import verify_packet


def _report() -> DrillReport:
    corpus = load_corpus()
    findings = run_corpus(InProcessCage(StubChatClient(True)), corpus, [HeuristicContentScorer()])
    r = DrillReport(
        agent_id="t", environment="staging",
        corpus_version=corpus.version, corpus_sources=corpus.sources,
        target_model="stub", cage="inprocess",
    )
    r.findings = findings
    r.status = r.derive_status()
    return r


def test_packet_signs_and_verifies(tmp_path, monkeypatch):
    for k in list(os.environ):
        if k.startswith("BLASTCONTAIN_"):
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "unit-test-key")

    pkt = write_drill_packet(_report(), str(tmp_path / "drill.json"))
    assert pkt["packet"]["generator"] == "blastcontain-drill"
    assert pkt["packet"]["corpus_version"]
    assert verify_packet(pkt) is True

    # Tampering with a finding breaks the signature.
    pkt["packet"]["findings"][0]["outcome"] = "HELD"
    assert verify_packet(pkt) is False


def test_packet_is_valid_json_on_disk(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "unit-test-key")
    path = tmp_path / "drill.json"
    write_drill_packet(_report(), str(path))
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == "1.1"
    assert "signature" in on_disk


def test_markdown_report_has_key_sections(tmp_path):
    path = tmp_path / "drill.md"
    write_markdown_report(_report(), str(path))
    text = path.read_text(encoding="utf-8")
    assert "BlastContain Drill" in text
    assert "MITRE ATLAS Coverage" in text
    assert "AML.T0110" in text  # tool-poisoning technique appears in coverage
