"""Unit tests for blastcontain_core.models."""
from __future__ import annotations

from blastcontain_core.models import (
    InfraFinding,
    ScanResult,
    ScanStatus,
    Severity,
)


def _finding(check_id="X-01", severity=Severity.HIGH):
    return InfraFinding(
        check_id=check_id,
        finding_type="blastcontain.test.demo",
        severity=severity,
        title="demo",
        detail="demo",
        remediation="demo",
    )


def test_derive_status_approved_with_no_findings():
    result = ScanResult(agent_id="a", environment="staging")
    assert result.derive_status() == ScanStatus.APPROVED


def test_derive_status_rejected_on_high():
    result = ScanResult(agent_id="a", environment="staging")
    result.findings.append(_finding(severity=Severity.HIGH))
    assert result.derive_status() == ScanStatus.REJECTED


def test_derive_status_quarantined_on_critical():
    result = ScanResult(agent_id="a", environment="staging")
    result.findings.append(_finding(severity=Severity.HIGH))
    result.findings.append(_finding(severity=Severity.CRITICAL))
    assert result.derive_status() == ScanStatus.QUARANTINED


def test_as_dict_summary_counts():
    result = ScanResult(agent_id="a", environment="staging")
    result.findings.append(_finding(severity=Severity.CRITICAL))
    result.findings.append(_finding(severity=Severity.HIGH))
    result.findings.append(_finding(severity=Severity.MEDIUM))
    result.passed = ["P-01", "P-02"]
    result.skipped = [{"check_id": "S-01", "reason": "skip"}]
    d = result.as_dict()
    assert d["summary"]["critical"] == 1
    assert d["summary"]["high"] == 1
    assert d["summary"]["medium"] == 1
    assert d["summary"]["passed"] == 2
    assert d["summary"]["skipped"] == 1
