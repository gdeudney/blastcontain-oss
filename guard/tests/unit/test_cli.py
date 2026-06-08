"""The CLI surface: lint, simulate, compile."""
from click.testing import CliRunner

from blastcontain_guard.cli import main

POLICY = """\
apiVersion: governance.toolkit/v1
name: t
default_action: deny
rules:
  - name: ask-delete
    condition: "action.type == 'delete'"
    action: require_approval
    approvers: [self]
    concern: no-prod-data-mutation
  - name: allow-read
    condition: "tool_name == 'query'"
    action: allow
"""

CHARTER = """\
agent_id: bot
environment: prod
version: "1.0"
trust_tier: 1
permitted_tools: [query, list]
environment_constraints:
  egress_blocked: true
hitl_config:
  required_for: [destructive_apis]
"""


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return str(p)


def test_lint_ok(tmp_path):
    path = _write(tmp_path, "policy.yaml", POLICY)
    result = CliRunner().invoke(main, ["lint", path])
    assert result.exit_code == 0
    assert "ok" in result.output
    assert "ask-delete" in result.output


def test_lint_rejects_bad_policy(tmp_path):
    path = _write(tmp_path, "bad.yaml", "rules:\n  - name: x\n    condition: \"os.system('x')\"\n    action: allow\n")
    result = CliRunner().invoke(main, ["lint", path])
    assert result.exit_code == 1
    assert "invalid" in result.output


def test_simulate_deny(tmp_path):
    path = _write(tmp_path, "policy.yaml", POLICY)
    result = CliRunner().invoke(
        main, ["simulate", "-p", path, "--tool", "drop_table", "--action-type", "delete"]
    )
    assert result.exit_code == 0
    assert "ask" in result.output
    assert "no-prod-data-mutation" in result.output or "self" in result.output


def test_simulate_json(tmp_path):
    path = _write(tmp_path, "policy.yaml", POLICY)
    result = CliRunner().invoke(
        main, ["simulate", "-p", path, "--tool", "query", "--as-json"]
    )
    assert result.exit_code == 0
    assert '"action": "allow"' in result.output


def test_simulate_via_charter(tmp_path):
    path = _write(tmp_path, "charter.yaml", CHARTER)
    result = CliRunner().invoke(
        main, ["simulate", "--charter", path, "--tool", "query", "--action-type", "read"]
    )
    assert result.exit_code == 0
    assert "allow" in result.output


def test_compile_charter(tmp_path):
    path = _write(tmp_path, "charter.yaml", CHARTER)
    result = CliRunner().invoke(main, ["compile", path])
    assert result.exit_code == 0
    assert "governance.toolkit/v1" in result.output
    assert "allow-permitted-tools" in result.output


def test_compile_autonomous_flips_to_deny(tmp_path):
    path = _write(tmp_path, "charter.yaml", CHARTER)
    result = CliRunner().invoke(main, ["compile", path, "--autonomy-mode", "autonomous"])
    assert result.exit_code == 0
    assert "require_approval" not in result.output  # autonomy switch -> deny


def test_export_agt_stdout(tmp_path):
    path = _write(tmp_path, "policy.yaml", POLICY)
    result = CliRunner().invoke(main, ["export-agt", "-p", path])
    assert result.exit_code == 0
    assert "apiVersion: governance.toolkit/v1" in result.output


def test_export_agt_no_metadata_is_minimal(tmp_path):
    path = _write(tmp_path, "policy.yaml", POLICY)
    result = CliRunner().invoke(main, ["export-agt", "-p", path, "--no-metadata"])
    assert result.exit_code == 0
    assert "metadata" not in result.output


def test_export_agt_from_charter(tmp_path):
    path = _write(tmp_path, "charter.yaml", CHARTER)
    result = CliRunner().invoke(main, ["export-agt", "--charter", path, "-o", str(tmp_path / "agt.yaml")])
    assert result.exit_code == 0
    written = (tmp_path / "agt.yaml").read_text(encoding="utf-8")
    assert "governance.toolkit/v1" in written


def test_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "blastcontain-guard" in result.output
