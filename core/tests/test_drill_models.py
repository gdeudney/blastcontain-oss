"""Unit tests for the Drill types and taxonomy promoted into core."""
from __future__ import annotations

import os


from blastcontain_core.constants import (
    ATLAS_TECHNIQUES,
    OWASP_AGENTIC_MAP,
    atlas_for,
    owasp_for,
    taxonomy_for,
)
from blastcontain_core.models import (
    DrillFinding,
    DrillOutcome,
    DrillReport,
    DrillStatus,
    Severity,
)
from blastcontain_core.signing import sign_packet, verify_packet


def _finding(outcome=DrillOutcome.HELD, severity=None, category="jailbreak"):
    tax = taxonomy_for(category)
    return DrillFinding(
        scenario_id="DRILL-JB-01",
        scenario_name="Jailbreak",
        outcome=outcome,
        severity=severity,
        attack_id="seed-001",
        technique="direct",
        layer="replay",
        **tax,
    )


# ── status derivation ─────────────────────────────────────────────────────────

def test_status_passed_when_all_held():
    r = DrillReport(agent_id="a", environment="staging", corpus_version="v2026.06")
    r.findings = [_finding(DrillOutcome.HELD), _finding(DrillOutcome.HELD)]
    assert r.derive_status() == DrillStatus.PASSED


def test_status_partial_on_noncritical_bypass():
    r = DrillReport(agent_id="a", environment="staging", corpus_version="v2026.06")
    r.findings = [_finding(DrillOutcome.HELD), _finding(DrillOutcome.BYPASS, Severity.HIGH)]
    assert r.derive_status() == DrillStatus.PARTIAL


def test_status_failed_on_critical_bypass():
    r = DrillReport(agent_id="a", environment="staging", corpus_version="v2026.06")
    r.findings = [_finding(DrillOutcome.BYPASS, Severity.CRITICAL)]
    assert r.derive_status() == DrillStatus.FAILED
    assert len(r.critical_bypasses) == 1


def test_status_error_when_every_scenario_errors():
    r = DrillReport(agent_id="a", environment="staging", corpus_version="v2026.06")
    r.findings = [_finding(DrillOutcome.ERROR), _finding(DrillOutcome.ERROR)]
    assert r.derive_status() == DrillStatus.ERROR


# ── taxonomy ──────────────────────────────────────────────────────────────────

def test_atlas_ids_verified_present():
    # The agent action-plane techniques must be present and correctly named.
    assert ATLAS_TECHNIQUES["AML.T0086"] == "Exfiltration via AI Agent Tool Invocation"
    assert ATLAS_TECHNIQUES["AML.T0110"] == "AI Agent Tool Poisoning"
    assert ATLAS_TECHNIQUES["AML.T0051.000"].endswith("Direct")


def test_taxonomy_for_known_category():
    tax = taxonomy_for("data_exfiltration")
    assert tax["atlas_id"] == "AML.T0086"
    assert tax["owasp_id"] == "T2"
    assert tax["mit_domain"] == "Privacy & Security"


def test_taxonomy_for_unknown_category_is_all_none():
    tax = taxonomy_for("does_not_exist")
    assert all(v is None for v in tax.values())


def test_atlas_for_and_owasp_for():
    assert atlas_for("jailbreak")[0] == "AML.T0054"
    assert owasp_for("jailbreak") == ("T6", OWASP_AGENTIC_MAP["T6"])


# ── serialization + signing ───────────────────────────────────────────────────

def test_finding_as_dict_carries_taxonomy():
    d = _finding(DrillOutcome.BYPASS, Severity.CRITICAL, category="mcp_hijack").as_dict()
    assert d["outcome"] == "BYPASS"
    assert d["severity"] == "CRITICAL"
    assert d["atlas_id"] == "AML.T0110"
    assert d["owasp_id"] == "T2"


def test_report_as_dict_summary_and_bench():
    r = DrillReport(
        agent_id="a", environment="prod", corpus_version="v2026.06",
        target_model="qwen/qwen3.6-27b", guard_model="qwen3guard-gen-8b", cage="inprocess",
    )
    r.findings = [
        _finding(DrillOutcome.HELD),
        _finding(DrillOutcome.BYPASS, Severity.CRITICAL),
    ]
    d = r.as_dict()
    assert d["corpus_version"] == "v2026.06"
    assert d["status"] == r.status.value
    assert d["summary"]["scenarios_run"] == 2
    assert d["summary"]["bypasses"] == 1
    assert d["summary"]["critical_bypasses"] == 1
    assert d["bench"]["target_model"] == "qwen/qwen3.6-27b"
    assert d["bench"]["guard_model"] == "qwen3guard-gen-8b"


def test_drill_report_signing_round_trip(monkeypatch):
    for key in list(os.environ):
        if key.startswith("BLASTCONTAIN_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")

    r = DrillReport(agent_id="a", environment="staging", corpus_version="v2026.06")
    r.findings = [_finding(DrillOutcome.BYPASS, Severity.CRITICAL)]
    r.status = r.derive_status()

    payload = r.as_dict()
    sig = sign_packet(payload, signed_at="2026-06-01T00:00:00Z")
    packet = {"schema_version": "1.1", "packet": payload, "signature": sig}
    assert verify_packet(packet) is True

    # Tamper: flip the recorded status and the signature must fail.
    packet["packet"]["status"] = "PASSED"
    assert verify_packet(packet) is False
