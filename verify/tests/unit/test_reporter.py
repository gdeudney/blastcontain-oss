"""Tests for blastcontain_verify.reporter."""
from __future__ import annotations

import json
import os

from blastcontain_verify.models import InfraFinding, ScanResult, ScanStatus, Severity
from blastcontain_verify.reporter import write_markdown_report, write_audit_packet


def _make_result() -> ScanResult:
    result = ScanResult(agent_id="test-agent", environment="prod")
    result.findings = [
        InfraFinding(
            check_id="ENV-01",
            finding_type="blastcontain.env.kernel_isolation_missing",
            severity=Severity.CRITICAL,
            title="Kernel Isolation Missing",
            detail="Running on host kernel",
            remediation="Use gVisor",
            mit_domain="System Deficiencies",
            mit_causal_id="MIT-SYS-02",
            mit_causal_label="Missing Sandbox Isolation",
        )
    ]
    result.passed = ["ENV-02", "PRIV-01"]
    result.skipped = [{"check_id": "MCP-01", "reason": "No --mcp-config provided"}]
    result.status = ScanStatus.QUARANTINED
    return result


class TestMarkdownReport:
    def test_creates_file(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        assert os.path.exists(report_path)

    def test_contains_agent_id(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        content = open(report_path, encoding="utf-8").read()
        assert "test-agent" in content

    def test_contains_status(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        content = open(report_path, encoding="utf-8").read()
        assert "QUARANTINED" in content

    def test_contains_finding_check_id(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        content = open(report_path, encoding="utf-8").read()
        assert "ENV-01" in content

    def test_contains_mit_mapping(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        content = open(report_path, encoding="utf-8").read()
        assert "MIT-SYS-02" in content

    def test_passed_checks_listed(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        content = open(report_path, encoding="utf-8").read()
        assert "ENV-02" in content
        assert "PRIV-01" in content

    def test_skipped_checks_listed(self, tmp_path):
        result = _make_result()
        report_path = str(tmp_path / "report.md")
        write_markdown_report(result, report_path)
        content = open(report_path, encoding="utf-8").read()
        assert "MCP-01" in content


class TestAuditPacket:
    def test_creates_valid_json(self, tmp_path):
        result = _make_result()
        packet_path = str(tmp_path / "audit.json")
        write_audit_packet(result, packet_path)
        assert os.path.exists(packet_path)
        with open(packet_path, encoding="utf-8") as f:
            loaded = json.load(f)
        assert "packet" in loaded
        assert "signature" in loaded

    def test_packet_contains_findings(self, tmp_path):
        result = _make_result()
        packet_path = str(tmp_path / "audit.json")
        packet = write_audit_packet(result, packet_path)
        assert len(packet["packet"]["findings"]) == 1

    def test_signature_present(self, tmp_path):
        result = _make_result()
        packet_path = str(tmp_path / "audit.json")
        packet = write_audit_packet(result, packet_path)
        assert packet["signature"]["algorithm"] == "sha256-hmac"
        assert len(packet["signature"]["value"]) == 64  # SHA-256 hex
