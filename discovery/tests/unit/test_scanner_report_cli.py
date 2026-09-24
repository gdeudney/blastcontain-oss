"""Orchestrator, signed report, and CLI."""
from __future__ import annotations

import json

from blastcontain_core.signing import verify_packet
from click.testing import CliRunner

from blastcontain_discovery.cli import main
from blastcontain_discovery.models import AssetClassification, DiscoveredAsset, DiscoveryReport
from blastcontain_discovery.report import sign_report, write_report
from blastcontain_discovery.scanner import run_discovery


def test_run_discovery_offline_stamps_and_classifies(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    (tmp_path / "agent.json").write_text("{}", encoding="utf-8")
    report = run_discovery(
        environment="dev", search_path=str(tmp_path),
        process_scan=False, copilot_scan=False, now="2026-07-06T00:00:00Z",
    )
    assert report.scanned_at == "2026-07-06T00:00:00Z"
    assert report.environment == "dev"
    assert report.summary()["shadow_ai"] >= 1
    assert report.generator_version


def test_run_discovery_bootstraps_local_for_shadow(tmp_path):
    (tmp_path / "agent.yaml").write_text("name: x", encoding="utf-8")
    charters = tmp_path / "out"
    report = run_discovery(
        environment="dev", search_path=str(tmp_path), process_scan=False,
        copilot_scan=False, bootstrap_charter=True, charter_output_dir=str(charters),
        now="2026-07-06T00:00:00Z",
    )
    shadow = report.shadow_ai
    assert shadow and all(a.draft_charter_ref for a in shadow)
    assert list(charters.glob("draft-*.yaml"))


def test_signed_report_verifies(monkeypatch):
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    report = DiscoveryReport(
        environment="prod", scanned_at="2026-07-06T00:00:00Z",
        assets=[DiscoveredAsset("copilot-x", "copilot", "/x",
                                classification=AssetClassification.UNKNOWN_SHADOW_AI)],
    )
    bundle = sign_report(report)
    assert verify_packet(bundle) is True
    assert bundle["packet"]["summary"]["shadow_ai"] == 1


def test_write_report_signed(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    report = DiscoveryReport(environment="prod", scanned_at="2026-07-06T00:00:00Z")
    out = tmp_path / "report.json"
    write_report(report, str(out), sign=True)
    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert "packet" in bundle and "signature" in bundle
    assert verify_packet(bundle) is True


def test_cli_exits_2_on_shadow(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    (tmp_path / "agent.json").write_text("{}", encoding="utf-8")
    result = CliRunner().invoke(main, [
        "--env", "dev", "--search-path", str(tmp_path),
        "--no-process-scan", "--no-copilot-scan",
    ])
    assert result.exit_code == 2
    assert "SHADOW" in result.output


def test_cli_clean_exits_0(tmp_path):
    result = CliRunner().invoke(main, [
        "--env", "dev", "--search-path", str(tmp_path),
        "--no-process-scan", "--no-copilot-scan",
    ])
    assert result.exit_code == 0


def test_cli_writes_report(tmp_path, monkeypatch):
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "test-key")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(main, [
        "--env", "dev", "--search-path", str(tmp_path),
        "--no-process-scan", "--no-copilot-scan",
        "--report", str(out), "--no-fail-on-shadow",
    ])
    assert result.exit_code == 0
    assert out.exists()
