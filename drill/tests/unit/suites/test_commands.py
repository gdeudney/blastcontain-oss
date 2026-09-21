"""CLI decisions, trust, exit codes and lifecycle round trips."""

from dataclasses import replace
import json
from pathlib import Path

from click.testing import CliRunner
import pytest

from blastcontain_drill.contracts import PluginManifest
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.suites.artifacts import read_document, write_document
from blastcontain_drill.suites.catalog import builtin_catalog
from blastcontain_drill.suites.cli import main
from blastcontain_drill.suites.schema import Selection, SuiteSpec, TargetSpec


@pytest.fixture
def cli(tmp_path):
    runner = CliRunner()

    def invoke(*args, code=0):
        result = runner.invoke(main, [str(a) for a in args])
        assert result.exit_code == code, result.output + repr(result.exception)
        return result

    return invoke


def setup(tmp_path, cli, *, vulnerable=False, kind="agent"):
    spec = SuiteSpec(
        "cli-test",
        TargetSpec(kind, "builtin.target.vulnerable" if vulnerable else "builtin.target.resistant"),
        "builtin.environment.fixture",
        ("builtin.evaluator.heuristic",),
        (Selection("selected", "mcp-poisoning", ("*",)),),
    )
    suite, plan, decisions, lock = (
        tmp_path / name for name in ("suite.json", "plan.json", "decisions.json", "lock.json")
    )
    write_document(suite, spec.to_dict())
    cli("plan", suite, "--output", plan)
    digest = read_document(plan)["content_digest"]
    cli(
        "accept",
        plan,
        "--expected-digest",
        digest,
        "--reviewer",
        "tester",
        "--reason",
        "Controlled fixture only",
        "--output",
        decisions,
    )
    cli("plan", suite, "--acceptances", decisions, "--lock", lock)
    return suite, plan, decisions, lock


@pytest.mark.parametrize(
    "kind,vulnerable", [("agent", False), ("agent", True), ("mcp", False), ("mcp", True)]
)
def test_signed_cli_roundtrip_and_legacy_exit_codes(tmp_path, cli, kind, vulnerable):
    _, _, decisions, lock = setup(tmp_path, cli, kind=kind, vulnerable=vulnerable)
    keys = tmp_path / "keys"
    cli("keygen", keys)
    code = 2 if vulnerable else 0
    result = cli(
        "run",
        lock,
        "--acceptances",
        decisions,
        "--run-root",
        tmp_path / "runs",
        "--signing-key",
        keys / "signing-key.pem",
        "--require-signing",
        code=code,
    )
    created, final = (json.loads(line) for line in result.output.splitlines())
    directory = Path(created["directory"])
    assert len(final["cases"]) == 4 and final["reported_security_passed"] is (not vulnerable)
    verify = ["verify", directory, "--trusted-key", keys / "verification-key.pub", "--lock", lock]
    verified = json.loads(cli(*verify, code=code).output)
    assert verified["trusted"] and verified["replayed"]
    assert verified["attested_pass"] is (not vulnerable)
    cli("verify", directory, "--trusted-key", keys / "verification-key.pub", code=2)
    cli("verify", directory, "--lock", lock, code=1)
    assert json.loads(cli("cancel", directory).output) == {"requested": False}
    assert json.loads(cli("purge-raw", directory).output) == {"removed": 0}
    cli(
        "export-legacy",
        directory,
        "--trusted-key",
        keys / "verification-key.pub",
        "--lock",
        lock,
        "--output",
        tmp_path / "legacy.json",
    )
    report = read_document(tmp_path / "legacy.json")
    assert len(report["findings"]) == 4 and report["warnings"]
    rerun = cli(
        "rerun",
        directory,
        lock,
        "--acceptances",
        decisions,
        "--run-root",
        tmp_path / "runs",
        "--trusted-key",
        keys / "verification-key.pub",
        code=code,
    )
    assert json.loads(rerun.output.splitlines()[0])["run_id"] != created["run_id"]


def test_acceptance_requires_reviewed_digest_and_current_plan(tmp_path, cli):
    suite, plan, decisions, lock = setup(tmp_path, cli)
    before = decisions.read_bytes()
    base = [
        "accept",
        plan,
        "--reviewer",
        "tester",
        "--reason",
        "reviewed",
        "--output",
        tmp_path / "next.json",
    ]
    cli(*base, "--expected-digest", "sha256:" + "0" * 64, code=1)
    assert not (tmp_path / "next.json").exists()
    data = read_document(plan)
    data["plan"]["spec"]["target"]["binding"] = "builtin.target.vulnerable"
    altered = tmp_path / "altered.json"
    write_document(altered, data)
    cli(
        "accept",
        altered,
        "--expected-digest",
        data["content_digest"],
        "--reviewer",
        "tester",
        "--reason",
        "reviewed",
        "--output",
        tmp_path / "next.json",
        code=1,
    )
    cli(
        *base,
        "--expected-digest",
        read_document(plan)["content_digest"],
        "--acceptances",
        decisions,
        "--decision",
        "revoked",
    )
    cli(
        "run",
        lock,
        "--acceptances",
        tmp_path / "next.json",
        "--run-root",
        tmp_path / "runs",
        code=1,
    )
    assert not (tmp_path / "runs").exists() and decisions.read_bytes() == before


def test_plugin_decision_requires_exact_scope_and_history_is_not_overwritten(tmp_path, cli):
    manifest = PluginManifest(
        "review-plugin",
        "1",
        "sha256:" + "a" * 64,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0",
        access_requests=("broker.target",),
    )
    path, output = tmp_path / "manifest.json", tmp_path / "decision.json"
    write_document(path, manifest.to_dict())
    args = [
        "accept",
        path,
        "--kind",
        "plugin",
        "--expected-digest",
        review_digest(manifest),
        "--reviewer",
        "tester",
        "--reason",
        "reviewed",
        "--output",
        output,
    ]
    cli(*args, code=1)
    cli(*args, "--grant-access", "broker.target")
    cli(*args, "--grant-access", "broker.target", code=1)
    assert len(read_document(output)["records"]) == 1


def test_required_signing_and_credential_mapping_fail_before_dispatch(tmp_path, cli):
    _, _, decisions, lock = setup(tmp_path, cli)
    args = ["run", lock, "--acceptances", decisions, "--run-root", tmp_path / "runs"]
    cli(*args, "--require-signing", code=1)
    cli(*args, "--credential", "key=DO_NOT_PRINT_SECRET_VALUE!", code=1)
    assert not (tmp_path / "runs").exists()


def test_content_acceptance_preserves_exact_data_digest(tmp_path, cli):
    original = builtin_catalog().sources[0]
    source = replace(
        original,
        id="review-source",
        scenarios=tuple(
            replace(s, source=replace(s.source, name="review-source")) for s in original.scenarios
        ),
    )
    path = tmp_path / "source.json"
    write_document(path, source.to_dict())
    cli(
        "accept",
        path,
        "--kind",
        "content",
        "--expected-digest",
        source.content_digest,
        "--reviewer",
        "tester",
        "--reason",
        "reviewed",
        "--output",
        tmp_path / "decisions.json",
    )
    assert (
        read_document(tmp_path / "decisions.json")["records"][0]["artifact_digest"]
        == source.content_digest
    )


def test_benign_control_reports_utility_failure_instead_of_security_success(tmp_path, cli):
    example = Path(__file__).parents[3] / "examples/suites/benign-control.json"
    plan, decisions, lock = (
        tmp_path / name for name in ("plan.json", "decisions.json", "lock.json")
    )
    cli("plan", example, "--output", plan)
    cli(
        "accept",
        plan,
        "--expected-digest",
        read_document(plan)["content_digest"],
        "--reviewer",
        "tester",
        "--reason",
        "Benign control",
        "--output",
        decisions,
    )
    cli("plan", example, "--acceptances", decisions, "--lock", lock)
    output = cli("run", lock, "--acceptances", decisions, "--run-root", tmp_path / "runs", code=2)
    directory = json.loads(output.output.splitlines()[0])["directory"]
    verified = json.loads(
        cli("verify", directory, "--lock", lock, "--allow-advisory", code=2).output
    )
    assert verified["replayed"] and not verified["security_passed"]
    cli(
        "export-legacy",
        directory,
        "--lock",
        lock,
        "--allow-advisory",
        "--output",
        tmp_path / "legacy.json",
    )
    assert read_document(tmp_path / "legacy.json")["findings"][0]["outcome"] == "OVER_REFUSAL"
