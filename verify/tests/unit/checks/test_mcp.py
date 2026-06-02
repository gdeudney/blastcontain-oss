"""Tests for blastcontain_verify.checks.mcp."""
from __future__ import annotations

import json

from blastcontain_verify.checks.mcp import (
    check_mcp02_missing_auth,
    check_mcp03_dangerous_combinations,
)
from blastcontain_verify.models import Severity


class TestMcp02MissingAuth:
    def test_no_mcp_config_skip(self):
        findings, status, _ = check_mcp02_missing_auth(None)
        assert status == "SKIP"

    def test_missing_config_file_skip(self):
        findings, status, _ = check_mcp02_missing_auth("/nonexistent/mcp.json")
        assert status == "SKIP"

    def test_server_with_auth_passes(self, tmp_path):
        config = {
            "mcpServers": {
                "data-mcp": {
                    "url": "https://mcp.internal:3001",
                    "auth": {"type": "bearer", "token": "secret"},
                }
            }
        }
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(config))
        findings, status, _ = check_mcp02_missing_auth(str(f))
        assert status == "PASS"

    def test_server_without_auth_fails(self, tmp_path):
        config = {
            "mcpServers": {
                "data-mcp": {"url": "https://mcp.internal:3001"}
            }
        }
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(config))
        findings, status, _ = check_mcp02_missing_auth(str(f))
        assert status == "FAIL"
        assert findings[0].severity == Severity.HIGH

    def test_http_url_flagged(self, tmp_path):
        config = {
            "mcpServers": {
                "data-mcp": {
                    "url": "http://mcp.internal:3001",  # plaintext
                    "auth": {"type": "bearer"},
                }
            }
        }
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(config))
        findings, status, _ = check_mcp02_missing_auth(str(f))
        assert status == "FAIL"


class TestMcp03DangerousCombinations:
    def _write_config(self, tmp_path, tools: list[str]) -> str:
        config = {"mcpServers": {"test-mcp": {"tools": tools, "url": "https://mcp:3001"}}}
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(config))
        return str(f)

    def test_no_mcp_config_skip(self):
        findings, status, _ = check_mcp03_dangerous_combinations(None)
        assert status == "SKIP"

    def test_safe_tools_pass(self, tmp_path):
        config_path = self._write_config(tmp_path, ["query_db", "search"])
        findings, status, _ = check_mcp03_dangerous_combinations(config_path)
        assert status in ("PASS", "SKIP")  # 1 category = no dangerous pair

    def test_read_send_combination_critical(self, tmp_path):
        config_path = self._write_config(tmp_path, ["read_file", "send_email"])
        findings, status, _ = check_mcp03_dangerous_combinations(config_path)
        assert status == "FAIL"
        assert findings[0].severity == Severity.CRITICAL

    def test_credential_send_critical(self, tmp_path):
        config_path = self._write_config(tmp_path, ["get_secret", "http_post"])
        findings, status, _ = check_mcp03_dangerous_combinations(config_path)
        assert status == "FAIL"
        assert findings[0].severity == Severity.CRITICAL

    def test_execute_write_critical(self, tmp_path):
        config_path = self._write_config(tmp_path, ["exec", "write_file"])
        findings, status, _ = check_mcp03_dangerous_combinations(config_path)
        assert status == "FAIL"
        assert findings[0].severity == Severity.CRITICAL
