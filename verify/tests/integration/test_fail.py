"""
FAIL scenario tests — every check that CAN fire should fire.

Test groups:
  1. File-based checks   — use dirty/ fixture, hardened container
  2. Environment checks  — network probe tests require joining testnet
  3. Env-var checks      — inject specific env vars into container
  4. Privilege checks    — remove security flags to expose PRIV-01 / CAP-01
  5. MCP checks          — mcp-config with inline dangerous tool list

MCP-01 is omitted: it SKIPs when permitted_tools=None (current CLI
behaviour — will be wired in Phase 3 once Charter is implemented).
"""
from __future__ import annotations

from conftest import (
    failed_checks,
    findings_for,
    skipped_checks,
)

# ---------------------------------------------------------------------------
# 1. File-based checks (hardened, --network none)
# ---------------------------------------------------------------------------

class TestFileBasedFail:

    def test_cred01_hardcoded_secrets(self, run_verify):
        """CRED-01: .env with real-looking API keys and secrets fires."""
        result = run_verify("dirty")
        assert "CRED-01" in failed_checks(result), (
            f"CRED-01 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_cred03_wildcard_permissions(self, run_verify):
        """CRED-03: config.yaml with roles: '*' fires."""
        result = run_verify("dirty")
        assert "CRED-03" in failed_checks(result), (
            f"CRED-03 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_code01_critical_eval_exec(self, run_verify):
        """CODE-01 CRITICAL: src/agent.py contains eval(), exec(), os.system(), shell=True."""
        result = run_verify("dirty")
        assert "CODE-01" in failed_checks(result), (
            f"CODE-01 did not fire.\nstdout:\n{result['stdout']}"
        )
        findings = findings_for(result, "CODE-01")
        assert findings, "Finding present but empty"
        assert findings[0]["severity"] in ("CRITICAL", "HIGH")

    def test_code01_high_pickle_yaml(self, run_verify):
        """CODE-01 HIGH: src/loader.py contains pickle.load(), yaml.load(), marshal.loads()."""
        result = run_verify("dirty")
        # CODE-01 fires once with up to 10 combined hits; just confirm it fired
        assert "CODE-01" in failed_checks(result)

    def test_tls01_plaintext_http(self, run_verify):
        """TLS-01: config.yaml has three http:// service URLs."""
        result = run_verify("dirty")
        assert "TLS-01" in failed_checks(result), (
            f"TLS-01 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_sup01_model_without_attestation(self, run_verify):
        """SUP-01: models/weights.bin has no .sha256 alongside it."""
        result = run_verify(
            "dirty",
            extra_args=["--model-dir", "//scan/models"],
        )
        assert "SUP-01" in failed_checks(result), (
            f"SUP-01 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_skill01_exfil_tools(self, run_verify):
        """SKILL-01: skills/ contains http_post, upload_file, exec, s3_put."""
        result = run_verify(
            "dirty",
            extra_args=["--skills-dir", "//scan/skills"],
        )
        assert "SKILL-01" in failed_checks(result), (
            f"SKILL-01 did not fire.\nstdout:\n{result['stdout']}"
        )
        findings = findings_for(result, "SKILL-01")
        assert any(
            kw in findings[0].get("evidence", "")
            for kw in ("http_post", "upload_file", "exec", "s3_put", "webhook", "send_email")
        ), f"Expected exfil tool names in evidence. Got: {findings[0].get('evidence')}"

    def test_api01_destructive_endpoints(self, run_verify):
        """API-01: openapi.yaml has DELETE /users and POST /admin/destroy."""
        result = run_verify(
            "dirty",
            extra_args=["--api-spec", "//scan/openapi.yaml"],
        )
        assert "API-01" in failed_checks(result), (
            f"API-01 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_api02_unauthenticated_endpoints(self, run_verify):
        """API-02: all four paths in dirty openapi.yaml lack security declarations."""
        result = run_verify(
            "dirty",
            extra_args=["--api-spec", "//scan/openapi.yaml"],
        )
        assert "API-02" in failed_checks(result), (
            f"API-02 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_mem01_pii_in_context(self, run_verify):
        """MEM-01: context.txt contains SSN, email, credit card, IBAN."""
        result = run_verify(
            "dirty",
            extra_args=["--context-file", "//scan/context.txt"],
        )
        assert "MEM-01" in failed_checks(result), (
            f"MEM-01 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_env03_writable_model_dir(self, run_verify):
        """ENV-03: writable /models directory is detected via canary write."""
        result = run_verify("dirty", writable_model_dir=True)
        assert "ENV-03" in failed_checks(result), (
            f"ENV-03 did not fire.\nstdout:\n{result['stdout']}"
        )


# ---------------------------------------------------------------------------
# 2. MCP checks — config-file based (no live server needed for 02/03)
# ---------------------------------------------------------------------------

class TestMcpFail:

    def test_mcp02_no_auth_and_http(self, run_verify):
        """MCP-02: dirty mcp-config.json uses http:// with no auth block."""
        result = run_verify(
            "dirty",
            extra_args=["--mcp-config", "//scan/mcp-config.json"],
        )
        assert "MCP-02" in failed_checks(result), (
            f"MCP-02 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_mcp03_dangerous_combination(self, run_verify):
        """MCP-03: inline tools include Read+Send+Credential+Execute+Write."""
        result = run_verify(
            "dirty",
            extra_args=["--mcp-config", "//scan/mcp-config.json"],
        )
        assert "MCP-03" in failed_checks(result), (
            f"MCP-03 did not fire.\nstdout:\n{result['stdout']}"
        )
        findings = findings_for(result, "MCP-03")
        assert findings[0]["severity"] == "CRITICAL", (
            f"Expected CRITICAL, got {findings[0]['severity']}"
        )

    def test_mcp01_skips_without_charter(self, run_verify):
        """MCP-01: SKIPs when permitted_tools=None (no Charter yet — Phase 3)."""
        result = run_verify(
            "dirty",
            extra_args=["--mcp-config", "//scan/mcp-config.json"],
        )
        assert "MCP-01" in skipped_checks(result), (
            "MCP-01 should SKIP when permitted_tools=None. "
            "If this fails, Charter integration has been implemented — "
            "update this test to assert MCP-01 fires instead."
        )


# ---------------------------------------------------------------------------
# 3. Environment-variable injected checks
# ---------------------------------------------------------------------------

class TestEnvVarFail:

    def test_cred02_secret_in_process_env(self, run_verify):
        """CRED-02: OPENAI_API_KEY injected into container environment."""
        result = run_verify(
            "dirty",
            extra_env={"OPENAI_API_KEY": "sk-proj-abc123thisisafakekeyforlongenough"},
        )
        assert "CRED-02" in failed_checks(result), (
            f"CRED-02 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_cred02_aws_secret_key(self, run_verify):
        """CRED-02: AWS_SECRET_ACCESS_KEY injected into container environment."""
        result = run_verify(
            "dirty",
            extra_env={"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYrIVALID"},
        )
        assert "CRED-02" in failed_checks(result)

    def test_mem03_generic_vector_namespace(self, run_verify):
        """MEM-03: Pinecone env vars with generic 'default' index name."""
        result = run_verify(
            "dirty",
            extra_env={
                "PINECONE_API_KEY":     "test-key-abc123",
                "PINECONE_ENVIRONMENT": "us-east-1-gcp",
                "PINECONE_INDEX":       "default",
            },
        )
        assert "MEM-03" in failed_checks(result), (
            f"MEM-03 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_local01_vscode_env_var(self, run_verify):
        """LOCAL-01: VSCODE_PID injected signals developer workstation."""
        result = run_verify(
            "dirty",
            extra_env={"VSCODE_PID": "12345"},
        )
        assert "LOCAL-01" in failed_checks(result), (
            f"LOCAL-01 did not fire.\nstdout:\n{result['stdout']}"
        )

    def test_local01_cursor_env_var(self, run_verify):
        """LOCAL-01: CURSOR_TRACE_ID injected signals Cursor IDE."""
        result = run_verify(
            "dirty",
            extra_env={"CURSOR_TRACE_ID": "trace-abc-123"},
        )
        assert "LOCAL-01" in failed_checks(result)


# ---------------------------------------------------------------------------
# 4. Privilege and capability checks
# ---------------------------------------------------------------------------

class TestPrivilegeFail:

    def test_priv01_running_as_root(self, run_verify):
        """PRIV-01: container run without --user fires root detection."""
        result = run_verify("dirty", as_root=True)
        assert "PRIV-01" in failed_checks(result), (
            f"PRIV-01 did not fire when running as root.\nstdout:\n{result['stdout']}"
        )

    def test_cap01_sys_admin_capability(self, run_verify):
        """CAP-01: --cap-add SYS_ADMIN triggers dangerous capability detection."""
        result = run_verify("dirty", extra_caps=["SYS_ADMIN"])
        assert "CAP-01" in failed_checks(result), (
            f"CAP-01 did not fire with SYS_ADMIN.\nstdout:\n{result['stdout']}"
        )

    def test_disk02_writable_root_filesystem(self, run_verify):
        """DISK-02: removing --read-only exposes writable root filesystem."""
        # Must run as root: /var and /usr are root-owned, so an unprivileged
        # uid cannot write to them even when the root fs is not --read-only.
        result = run_verify("dirty", as_root=True, no_read_only=True)
        assert "DISK-02" in failed_checks(result), (
            f"DISK-02 did not fire without --read-only.\nstdout:\n{result['stdout']}"
        )


# ---------------------------------------------------------------------------
# 5. Network-required checks (joins blastcontain-testnet)
# ---------------------------------------------------------------------------

class TestNetworkFail:

    def test_env02_egress_unrestricted(self, run_verify):
        """
        ENV-02: TCP egress probe succeeds when container is on testnet.
        mcp-server is reachable at mcp-server:8080 — used as probe target
        so the test is deterministic even in firewalled CI environments.
        """
        result = run_verify(
            "dirty",
            network=True,
            extra_args=["--egress-probe-target", "mcp-server:8080"],
        )
        assert "ENV-02" in failed_checks(result), (
            f"ENV-02 did not fire on testnet.\nstdout:\n{result['stdout']}"
        )

    def test_net01_dns_egress_open(self, run_verify):
        """
        NET-01: UDP DNS probe to 8.8.8.8:53 succeeds on testnet.
        Requires the runner to have internet access (GitHub Actions: yes).
        """
        result = run_verify("dirty", network=True)
        assert "NET-01" in failed_checks(result), (
            f"NET-01 did not fire on testnet.\n"
            "If running in an air-gapped environment, this is expected — "
            "mark with @pytest.mark.skip.\n"
            f"stdout:\n{result['stdout']}"
        )

    def test_mem05_pii_plus_open_egress(self, run_verify):
        """
        MEM-05: composite check fires when both MEM-01 (PII) and ENV-02
        (open egress) fire in the same run.
        """
        result = run_verify(
            "dirty",
            network=True,
            extra_args=[
                "--context-file", "//scan/context.txt",
                "--egress-probe-target", "mcp-server:8080",
            ],
        )
        # MEM-05 fires only when both MEM-01 and ENV-02 fired
        fired = failed_checks(result)
        assert "MEM-01" in fired, f"MEM-01 prerequisite did not fire: {fired}"
        assert "ENV-02" in fired, f"ENV-02 prerequisite did not fire: {fired}"
        assert "MEM-05" in fired, (
            f"MEM-05 (composite) did not fire even though MEM-01 and ENV-02 both fired.\n"
            f"All fired: {fired}"
        )
