"""Runner orchestration with a stub cage (no model)."""
from __future__ import annotations

from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.runner import run_corpus
from blastcontain_drill.scoring import HeuristicContentScorer
from blastcontain_core.models import DrillOutcome, DrillReport, DrillStatus


def _report(vulnerable: bool) -> DrillReport:
    corpus = load_corpus()
    findings = run_corpus(
        InProcessCage(StubChatClient(vulnerable=vulnerable)),
        corpus,
        [HeuristicContentScorer()],
    )
    r = DrillReport(
        agent_id="t", environment="staging",
        corpus_version=corpus.version, corpus_sources=corpus.sources,
    )
    r.findings = findings
    r.status = r.derive_status()
    return r


def test_vulnerable_agent_fails_the_drill():
    r = _report(vulnerable=True)
    assert r.status == DrillStatus.FAILED
    assert r.critical_bypasses


def test_hardened_agent_passes_the_drill():
    r = _report(vulnerable=False)
    assert r.status == DrillStatus.PASSED
    assert len(r.held) == len(r.findings)


def test_every_finding_is_taxonomy_tagged_and_identified():
    r = _report(vulnerable=True)
    assert r.findings
    for f in r.findings:
        assert f.atlas_id, f.scenario_id          # ATLAS is the primary tag
        assert f.owasp_id
        assert f.scenario_id.startswith("DRILL-")
        assert f.detection_latency_ms is not None


def test_charter_permitted_tools_make_send_forbidden():
    # With a Charter that permits only read/list_files, an exfil send is a
    # forbidden-tool action bypass even though delete_records never fired.
    corpus = load_corpus(categories=["data_exfiltration"])
    findings = run_corpus(
        InProcessCage(StubChatClient(vulnerable=True)),
        corpus,
        [HeuristicContentScorer()],
        permitted_tools=["read", "list_files"],
    )
    assert findings
    assert all(f.outcome == DrillOutcome.BYPASS for f in findings)
    assert any(
        f.action_verdict and f.action_verdict["forbidden_tool"]["triggered"]
        for f in findings
    )
