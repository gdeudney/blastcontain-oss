"""Integration tests for the scanner orchestrator."""
from __future__ import annotations


from blastcontain_verify.config import VerifyConfig
from blastcontain_verify.models import ScanResult, ScanStatus
from blastcontain_verify.scanner import run_scan


class TestRunScan:
    def test_returns_scan_result(self, tmp_path):
        cfg = VerifyConfig(
            agent_id="test-agent",
            environment="dev",
            search_path=str(tmp_path),
            model_dir=str(tmp_path / "nonexistent-models"),
        )
        result = run_scan(cfg)
        assert isinstance(result, ScanResult)
        assert result.agent_id == "test-agent"
        assert result.environment == "dev"
        assert result.status in ScanStatus.__members__.values()

    def test_status_derives_from_findings(self, tmp_path):
        # Inject a credential to trigger CRED-01
        (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-realkey123456789\n")
        cfg = VerifyConfig(
            agent_id="test-agent",
            environment="dev",
            search_path=str(tmp_path),
        )
        result = run_scan(cfg)
        # Should be REJECTED or QUARANTINED because of credential finding
        assert result.status in (ScanStatus.REJECTED, ScanStatus.QUARANTINED)

    def test_clean_environment_may_approve(self, tmp_path):
        cfg = VerifyConfig(
            agent_id="clean-agent",
            environment="dev",
            search_path=str(tmp_path),
            model_dir="",
        )
        result = run_scan(cfg)
        # Dev environment on a workstation may produce LOCAL-01 but that's HIGH
        assert result.status != ScanStatus.ERROR

    def test_augmentation_flags_in_result(self, tmp_path):
        cfg = VerifyConfig(agent_id="test-agent", environment="dev", search_path=str(tmp_path))
        result = run_scan(cfg)
        assert "presidio" in result.augmentation
        assert "cisco_mcp" in result.augmentation

    def test_blast_radius_factor_tier0(self, tmp_path):
        cfg = VerifyConfig(agent_id="agent", environment="dev", max_tier=0)
        result = run_scan(cfg)
        assert result.blast_radius_factor == 1.0

    def test_blast_radius_factor_tier3(self, tmp_path):
        cfg = VerifyConfig(agent_id="agent", environment="dev", max_tier=3)
        result = run_scan(cfg)
        assert result.blast_radius_factor == 4.0
