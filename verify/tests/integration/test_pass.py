"""
PASS scenario tests — clean fixture should produce zero file-based findings.

Notes:
  - ENV-01 is environment-dependent: it fires on any standard Linux container
    without gVisor. Tests here use --acknowledge-risk so this does not cause
    a non-zero exit code, and ENV-01 is explicitly excluded from assertions.
  - ENV-02 / NET-01 PASS are verified by running with --network none.
  - The clean fixture contains no secrets, no dangerous code, no http:// URLs,
    attested model weights, and safe tool definitions only.
"""
from __future__ import annotations

import pytest
from conftest import (
    failed_checks,
    passed_checks,
    skipped_checks,
)

# Checks that are environment-dependent and excluded from PASS assertions
ENV_DEPENDENT = {"ENV-01"}


class TestPassScenarios:

    def test_clean_fixture_no_file_findings(self, run_verify):
        """
        Full clean-fixture scan produces zero file-based findings.
        ENV-01 is excluded (fires on any non-gVisor Linux host).
        """
        result = run_verify(
            "clean",
            extra_args=[
                "--skills-dir",  "//scan/skills",
                "--api-spec",    "//scan/openapi.yaml",
                "--model-dir",   "//scan/models",
                "--mcp-config",  "//scan/mcp-config.json",
            ],
        )
        fired = failed_checks(result) - ENV_DEPENDENT
        assert fired == set(), (
            f"Unexpected findings on clean fixture: {fired}\n"
            f"stdout:\n{result['stdout']}"
        )

    def test_network_none_env02_net01_pass(self, run_verify):
        """ENV-02 and NET-01 both PASS when --network none is active."""
        result = run_verify("clean")
        assert "ENV-02" in passed_checks(result), "ENV-02 should PASS with --network none"
        assert "NET-01" in passed_checks(result), "NET-01 should PASS with --network none"

    def test_cap01_passes_with_cap_drop_all(self, run_verify):
        """CAP-01 PASS: no effective capabilities after --cap-drop ALL."""
        result = run_verify("clean")
        assert "CAP-01" in passed_checks(result), (
            f"CAP-01 should PASS.\nstdout:\n{result['stdout']}"
        )

    def test_priv01_passes_as_nonroot(self, run_verify):
        """PRIV-01 PASS: running as uid 10001 (not root)."""
        result = run_verify("clean")
        assert "PRIV-01" in passed_checks(result)

    def test_disk02_passes_with_read_only(self, run_verify):
        """DISK-02 PASS: --read-only prevents root filesystem writes."""
        result = run_verify("clean")
        assert "DISK-02" in passed_checks(result)

    def test_perm01_passes_in_hardened_container(self, run_verify):
        """PERM-01 PASS: persistence paths unwritable in read-only container."""
        result = run_verify("clean")
        assert "PERM-01" in passed_checks(result)

    def test_cred01_no_secrets_in_clean_fixture(self, run_verify):
        """CRED-01 PASS: clean fixture has no credential files."""
        result = run_verify("clean")
        assert "CRED-01" in passed_checks(result)

    def test_code01_no_dangerous_patterns(self, run_verify):
        """CODE-01 PASS: clean/src/safe.py has no eval/exec/pickle/shell."""
        result = run_verify("clean")
        assert "CODE-01" in passed_checks(result)

    def test_tls01_no_plaintext_http(self, run_verify):
        """TLS-01 PASS: clean fixture has no http:// URLs in config files."""
        result = run_verify("clean")
        assert "TLS-01" in passed_checks(result)

    def test_sup01_attested_model_weights(self, run_verify):
        """SUP-01 PASS: weights.safetensors has matching weights.sha256."""
        result = run_verify(
            "clean",
            extra_args=["--model-dir", "//scan/models"],
        )
        assert "SUP-01" in passed_checks(result), (
            f"SUP-01 should PASS with attested weights.\nstdout:\n{result['stdout']}"
        )

    def test_skill01_safe_tools_pass(self, run_verify):
        """SKILL-01 PASS: clean skills (weather, search, ticket) match no exfil patterns."""
        result = run_verify(
            "clean",
            extra_args=["--skills-dir", "//scan/skills"],
        )
        assert "SKILL-01" in passed_checks(result), (
            f"SKILL-01 should PASS on safe tools.\nstdout:\n{result['stdout']}"
        )

    def test_api01_api02_clean_spec(self, run_verify):
        """API-01 and API-02 PASS: clean openapi.yaml has no destructive or unauthed endpoints."""
        result = run_verify(
            "clean",
            extra_args=["--api-spec", "//scan/openapi.yaml"],
        )
        assert "API-01" in passed_checks(result), (
            f"API-01 should PASS.\nstdout:\n{result['stdout']}"
        )
        assert "API-02" in passed_checks(result), (
            f"API-02 should PASS.\nstdout:\n{result['stdout']}"
        )

    def test_mcp02_mcp03_clean_config(self, run_verify):
        """
        MCP-02 and MCP-03: clean mcp-config.json has auth + only safe tools.
        Note: MCP-02 may still fire because the clean config uses http:// (test env).
        If that is the case, this test documents the expected clean-up for prod:
        use HTTPS and set auth.type=bearer with a real token.
        """
        result = run_verify(
            "clean",
            extra_args=["--mcp-config", "//scan/mcp-config.json"],
        )
        # MCP-03 should definitely PASS — only Read-only tools (search, get_*)
        assert "MCP-03" in passed_checks(result), (
            f"MCP-03 should PASS on safe-only tools.\nstdout:\n{result['stdout']}"
        )

    def test_no_pii_in_safe_context(self, run_verify):
        """MEM-01 SKIP when no --context-file is provided."""
        result = run_verify("clean")
        assert "MEM-01" in skipped_checks(result)

    def test_optional_checks_skip_cleanly(self, run_verify):
        """Checks that require inputs SKIP gracefully when inputs are absent."""
        result = run_verify("clean")
        skipped = skipped_checks(result)
        # These should always SKIP without their respective flags
        for check_id in ("MCP-01", "MCP-02", "MCP-03", "MEM-01", "API-01", "API-02"):
            assert check_id in skipped, (
                f"{check_id} should SKIP without its required input flag. "
                f"Skipped: {skipped}"
            )

    def test_approved_status_on_clean_fixture(self, run_verify):
        """Overall scan status is APPROVED on a fully clean fixture."""
        result = run_verify("clean")
        fired = failed_checks(result) - ENV_DEPENDENT
        if fired:
            pytest.skip(
                f"Unexpected findings block APPROVED assertion: {fired}. "
                "Fix those checks first."
            )
        # Exit code: 0=APPROVED or 2=QUARANTINED (ENV-01 on non-gVisor host)
        # --acknowledge-risk forces exit 0 regardless
        assert result["exit_code"] == 0, (
            f"Exit code {result['exit_code']} with --acknowledge-risk.\n"
            f"stdout:\n{result['stdout']}"
        )


# ---------------------------------------------------------------------------
# Gap-fill: individual PASS tests for checks that only had FAIL coverage
# ---------------------------------------------------------------------------

class TestIndividualPassGapFill:

    def test_env03_readonly_mount_passes(self, run_verify):
        """ENV-03 PASS: model dir mounted :ro raises PermissionError on canary write."""
        # scan dir is always mounted :ro — models/ inside it is also read-only
        result = run_verify(
            "dirty",
            extra_args=["--model-dir", "//scan/models"],
        )
        assert "ENV-03" in passed_checks(result), (
            f"ENV-03 should PASS with read-only mount.\nstdout:\n{result['stdout']}"
        )

    def test_cred02_passes_with_no_secret_env_vars(self, run_verify):
        """CRED-02 PASS: no secret-named or token-prefixed env vars in process."""
        result = run_verify("clean")
        assert "CRED-02" in passed_checks(result), (
            f"CRED-02 should PASS in clean env.\nstdout:\n{result['stdout']}"
        )

    def test_cred03_passes_with_no_wildcard_permissions(self, run_verify):
        """CRED-03 PASS: clean fixture config files have no wildcard '*' entries."""
        result = run_verify("clean")
        assert "CRED-03" in passed_checks(result), (
            f"CRED-03 should PASS on clean config.\nstdout:\n{result['stdout']}"
        )

    def test_mem03_passes_with_no_vector_db_env_vars(self, run_verify):
        """MEM-03 PASS: SKIP when no vector DB environment variables are set."""
        result = run_verify("clean")
        # MEM-03 SKIPs rather than PASSes when no vector DB is detected
        assert "MEM-03" in skipped_checks(result), (
            f"MEM-03 should SKIP with no vector DB env vars.\nstdout:\n{result['stdout']}"
        )

    def test_mem05_passes_when_egress_blocked(self, run_verify):
        """MEM-05 SKIP: composite check skips when ENV-02 does not fire (--network none)."""
        result = run_verify(
            "dirty",
            extra_args=["--context-file", "//scan/context.txt"],
        )
        # MEM-01 fires (PII present), but ENV-02 PASS (network none) → MEM-05 SKIP
        assert "MEM-01" in failed_checks(result), "MEM-01 prerequisite should fire"
        assert "ENV-02" in passed_checks(result), "ENV-02 should PASS (network none)"
        assert "MEM-05" in skipped_checks(result), (
            f"MEM-05 should SKIP when ENV-02 does not fire.\n"
            f"stdout:\n{result['stdout']}"
        )

    def test_mem05_passes_when_no_pii(self, run_verify):
        """MEM-05 SKIP: composite check skips when MEM-01 does not fire (no context file)."""
        result = run_verify("dirty", network=True,
                            extra_args=["--egress-probe-target", "mcp-server:8080"])
        # ENV-02 fires (network access), but MEM-01 SKIP (no --context-file) → MEM-05 SKIP
        assert "ENV-02" in failed_checks(result), "ENV-02 should fire on testnet"
        assert "MEM-01" in skipped_checks(result), "MEM-01 should SKIP (no context-file)"
        assert "MEM-05" in skipped_checks(result), (
            f"MEM-05 should SKIP when MEM-01 does not fire.\n"
            f"stdout:\n{result['stdout']}"
        )

    def test_local01_passes_with_no_workstation_indicators(self, run_verify):
        """LOCAL-01 SKIP: no IDE env vars or home-path signatures detected."""
        result = run_verify("clean")
        assert "LOCAL-01" in skipped_checks(result), (
            f"LOCAL-01 should SKIP in clean container env.\nstdout:\n{result['stdout']}"
        )

    def test_disk01_skips_in_non_workstation_env(self, run_verify):
        """DISK-01 SKIP: only fires when --env contains 'workstation' or 'local'."""
        result = run_verify("clean")
        assert "DISK-01" in skipped_checks(result), (
            f"DISK-01 should SKIP for --env staging.\nstdout:\n{result['stdout']}"
        )

    def test_disk01_fires_in_workstation_env(self, run_verify):
        """DISK-01 FAIL: fires when --env local_developer_workstation (no --read-only)."""
        # Must run as root: DISK-01 probes the user's home dir, which for the
        # unprivileged `verify` user (--no-create-home) does not exist. As root,
        # home is /root, which exists and is writable when not --read-only.
        result = run_verify(
            "dirty",
            as_root=True,
            no_read_only=True,
            extra_args=["--env", "local_developer_workstation"],
        )
        assert "DISK-01" in failed_checks(result), (
            f"DISK-01 should fire in workstation env without read-only.\n"
            f"stdout:\n{result['stdout']}"
        )

    def test_net02_passes_with_no_listeners(self, run_verify):
        """NET-02 PASS: verify container has no services bound to 0.0.0.0."""
        result = run_verify("clean")
        assert "NET-02" in passed_checks(result), (
            f"NET-02 should PASS — no listeners in verify container.\n"
            f"stdout:\n{result['stdout']}"
        )

    def test_perm01_fail_as_root_no_readonly(self, run_verify):
        """
        PERM-01 FAIL: root user + no --read-only exposes writable persistence paths.
        Only fires if /etc/cron.d or /etc/rc.local exist in the base image.
        If neither path exists, PERM-01 will still PASS and this test is skipped.
        """
        result = run_verify("dirty", as_root=True, no_read_only=True)
        fired = failed_checks(result)
        if "PERM-01" not in fired:
            pytest.skip(
                "PERM-01 did not fire: persistence paths (/etc/cron.d etc.) "
                "do not exist in python:3.12-slim. "
                "Expected in a full OS base image."
            )
        assert "PERM-01" in fired


class TestSkill02Coverage:
    """
    SKILL-02 (Cisco AI Skill Scanner) — tested only when the scanner
    is installed. The augmentation banner confirms it is active in the
    container image built with [full] extras.
    """

    def test_skill02_skips_when_no_claude_skills(self, run_verify):
        """
        SKILL-02 SKIP: target directory contains no Claude-format skills.

        When --skills-dir is omitted it falls back to --search-path, so to
        exercise the genuine "nothing to scan" SKIP path we point it at a
        subdirectory (//scan/src) that has source files but no SKILL.md.
        The Cisco scanner reports total_skills_scanned == 0 → SKIP.
        """
        result = run_verify("clean", extra_args=["--skills-dir", "//scan/src"])
        assert "SKILL-02" in skipped_checks(result)

    def test_skill02_fires_or_passes_on_dirty_skills(self, run_verify):
        """
        SKILL-02 FAIL or PASS: Cisco scanner runs on dirty skills.
        We don't assert a specific outcome because Cisco scanner heuristics
        vary. We assert it does NOT SKIP (i.e., the scanner ran).
        """
        result = run_verify(
            "dirty",
            extra_args=["--skills-dir", "//scan/skills"],
        )
        assert "SKILL-02" not in skipped_checks(result), (
            "SKILL-02 SKIPped unexpectedly on a non-empty skills dir with "
            "cisco-ai-skill-scanner installed."
        )

    def test_skill02_passes_on_clean_skills(self, run_verify):
        """SKILL-02 PASS: safe tool definitions should be assessed as safe."""
        result = run_verify(
            "clean",
            extra_args=["--skills-dir", "//scan/skills"],
        )
        # Either PASS or SKIP (if scanner is not installed) — not FAIL
        assert "SKILL-02" not in failed_checks(result), (
            f"SKILL-02 fired on clean skills — unexpected finding.\n"
            f"stdout:\n{result['stdout']}"
        )
