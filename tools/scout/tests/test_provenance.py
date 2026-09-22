"""Real Git objects, SQLite history and Drill contracts; no research/attack execution."""

import asyncio
from dataclasses import replace
import hashlib
import json
import subprocess

from click.testing import CliRunner
import pytest

from blastcontain_drill.contracts import (
    AcceptanceRecord,
    ContractError,
    PluginManifest,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
)
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.suites.artifacts import write_document
from blastcontain_drill.suites.catalog import SourceSnapshot, builtin_catalog
from blastcontain_drill.suites.durable import execute_run, verify_run
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.schema import Selection, SuiteSpec, TargetSpec
from blastcontain_drill.suites.service import ExecutionInputs
from blastcontain_scout.arxiv import Paper
from blastcontain_scout.provenance import (
    ArtifactRef,
    CoverageReview,
    GitObjects,
    PaperRef,
    ResearchMap,
    inspect_mapping,
    latest_mappings,
    refresh_mapping,
    relative_path,
    trace_lock,
)
from blastcontain_scout.storage import copy_database
from blastcontain_scout.tracker import Tracker, fingerprint
from blastcontain_scout.tracking_cli import main


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, check=True, text=True
    ).stdout.strip()


def commit(root, message):
    git(root, "add", ".")
    git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        message,
    )
    return git(root, "rev-parse", "HEAD")


def decision(kind, subject, value, grants=()):
    return AcceptanceRecord(
        subject,
        kind,
        value,
        "fixture",
        "accepted",
        "2026-09-21T00:00:00Z",
        "controlled review",
        grants,
    )


@pytest.fixture
def prepared(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    artifacts = []
    for name, kind, text in (
        ("source.py", "code", 'raise RuntimeError("must not import")'),
        ("validation.json", "validation", '{"scope":"controlled fixture","result":"passed"}'),
        ("LICENSE", "license", "Apache-2.0 fixture"),
    ):
        (root / name).write_text(text, encoding="utf-8")
        artifacts.append(ArtifactRef(name, hashlib.sha256(text.encode()).hexdigest(), kind))
    code = commit(root, "controlled code and records")
    papers = [
        Paper(
            pid, "Untrusted <script>title</script>", "fixture metadata", "2026-01-01", "2026-01-01"
        )
        for pid in ("2601.12345", "2601.23456")
    ]
    db = tmp_path / "scout.sqlite3"
    with Tracker(db) as tracker:
        tracker.ingest(papers)
    scenario = ScenarioSpec(
        "mapped",
        "jailbreak",
        "replay",
        SourceRef("mapped.source", "1"),
        "controlled request",
        SecurityExpectation("content"),
        attack_objective="Exercise the controlled fixture policy",
    )
    source = SourceSnapshot("mapped.source", "1", "sha256:" + "c" * 64, (scenario,))
    accepted = decision("content", source.id, source.content_digest)
    mapping = ResearchMap(
        "mapping.one",
        tuple(PaperRef(p.arxiv_id, fingerprint(p)) for p in papers),
        source,
        (),
        ("mapped",),
        code,
        tuple(artifacts),
        "research_informed_examples",
        "Original synthetic fixture only; no paper reproduction.",
        CoverageReview("Gordon", "Reviewed limited original scenarios", "Apache-2.0", "reviewed"),
        (accepted,),
    )
    (root / "mapping.json").write_text(json.dumps(mapping.to_dict()), encoding="utf-8")
    head = commit(root, "mapping")
    return root, db, papers, mapping, head


def inspect(prepared, *, head=None):
    root, db, _, _, initial = prepared
    with Tracker(db, readonly=True) as tracker:
        return inspect_mapping(root, head or initial, "mapping.json", tracker, main_ref="main")


def store(prepared, report):
    with Tracker(prepared[1]) as tracker:
        return refresh_mapping(tracker, report, actor="Gordon", expected_revision=tracker.revision)


def test_idempotent_refresh_many_paper_mapping_backup_and_no_code_import(prepared, tmp_path):
    report = inspect(prepared)
    assert report["git_and_reviews_current"] and len(report["papers"]) == 2
    assert report["validation_evidence"] == "committed_records_not_independently_rerun"
    assert store(prepared, report)
    with Tracker(prepared[1]) as tracker:
        before = tracker.snapshot()
        assert not refresh_mapping(
            tracker, report, actor="Gordon", expected_revision=tracker.revision
        )
        assert tracker.snapshot() == before
        assert list(latest_mappings(tracker, repo_key=report["repo_key"])) == ["mapping.one"]
    backup, restored = tmp_path / "backup.sqlite3", tmp_path / "restored.sqlite3"
    copy_database(prepared[1], backup)
    copy_database(backup, restored)
    with Tracker(restored, readonly=True) as tracker:
        assert tracker.snapshot() == before


def test_unknown_paper_refresh_is_transactional(prepared):
    report = inspect(prepared)
    report["papers"].append(
        {"id": "2601.99999", "fingerprint": "f" * 64, "metadata_current": False}
    )
    with Tracker(prepared[1]) as tracker:
        before = tracker.snapshot()
        with pytest.raises(ContractError, match="Import"):
            refresh_mapping(tracker, report, actor="Gordon", expected_revision=tracker.revision)
        assert tracker.snapshot() == before


def test_changed_metadata_source_and_unmerged_mapping_are_explicit(prepared):
    root, db, papers, mapping, head = prepared
    git(root, "switch", "-c", "proposal")
    changed = replace(mapping, limitations="Unmerged new scope")
    (root / "mapping.json").write_text(json.dumps(changed.to_dict()))
    proposal = commit(root, "unmerged mapping")
    report = inspect(prepared, head=proposal)
    assert "mapping_unmerged" in report["diagnostics"] and not report["git_and_reviews_current"]
    git(root, "switch", "main")
    (root / "source.py").write_text("changed capability")
    commit(root, "new source capability")
    with Tracker(db) as tracker:
        tracker.ingest([replace(papers[0], summary="changed paper method")])
    report = inspect(prepared)
    assert "current_artifact_changed:source.py" in report["diagnostics"]
    assert "paper_metadata_unknown_or_changed:2601.12345" in report["diagnostics"]
    assert not report["git_and_reviews_current"]


@pytest.mark.parametrize("change", ["license", "content", "plugin", "digest"])
def test_license_revocation_capability_change_and_forged_git_digest(prepared, change):
    root, _, _, mapping, _ = prepared
    if change == "license":
        mapping = replace(mapping, review=replace(mapping.review, license_status="incompatible"))
    elif change == "content":
        mapping = replace(
            mapping,
            acceptances=(*mapping.acceptances, replace(mapping.acceptances[0], decision="revoked")),
        )
    elif change == "plugin":
        plugin = PluginManifest(
            "attack.one",
            "1",
            "sha256:" + "e" * 64,
            ("attack_strategy",),
            ("prompt.single",),
            "MIT",
            access_requests=("broker.target",),
        )
        approval = decision("plugin", plugin.id, review_digest(plugin), plugin.access_requests)
        mapping = replace(
            mapping,
            plugins=(replace(plugin, access_requests=("broker.target", "broker.attacker")),),
            acceptances=(*mapping.acceptances, approval),
        )
    else:
        mapping = replace(
            mapping, files=(replace(mapping.files[0], sha256="f" * 64), *mapping.files[1:])
        )
    (root / "mapping.json").write_text(json.dumps(mapping.to_dict()))
    head = commit(root, "changed review")
    if change == "digest":
        with pytest.raises(ContractError, match="digest"):
            inspect(prepared, head=head)
    else:
        report = inspect(prepared, head=head)
        assert not report["git_and_reviews_current"] and report["diagnostics"]


@pytest.mark.parametrize(
    "path", [".", "../outside", "/absolute", "a/../b", ".git/config", "C:config", "a\\b", "a\npath"]
)
def test_repository_paths_cannot_escape_or_become_git_options(path):
    with pytest.raises(ContractError):
        relative_path(path)


def test_unsubstantiated_full_reproduction_is_rejected(prepared):
    with pytest.raises(ContractError, match="comparison protocol"):
        replace(prepared[3], coverage="full_reproduction")


def lock_for(mapping):
    catalog = builtin_catalog(external_sources=(mapping.source,))
    spec = SuiteSpec(
        "mapped.suite",
        TargetSpec("agent", "builtin.target.resistant"),
        "builtin.environment.fixture",
        ("builtin.evaluator.heuristic",),
        (Selection("mapped", mapping.source.id, ("mapped",)),),
    )
    plan = plan_suite(spec, catalog, records=mapping.acceptances)
    assert plan.ready
    records = (*mapping.acceptances, decision("suite", spec.id, plan.content_digest))
    return create_lock(plan, catalog, records=records), ExecutionInputs(catalog, records)


def test_run_to_paper_trace_uses_existing_verifier_and_exact_lock_identities(prepared, tmp_path):
    report = inspect(prepared)
    lock, inputs = lock_for(prepared[3])
    stored = asyncio.run(
        execute_run(
            lock, tmp_path / "runs", current_inputs=lambda: inputs, raw_retention_seconds=120
        )
    )
    verified = verify_run(stored.directory, lock=lock, allow_advisory=True)
    traced = trace_lock(lock, [report], verification=verified)
    assert traced["run_replayed"] and not traced["run_trusted"]
    assert traced["run_security_passed"] and traced["provenance_complete"]
    row = traced["cases"][0]
    assert row["result"]["security"] == "held" and row["mappings"][0]["identity_matches"]
    assert len(row["mappings"][0]["papers"]) == 2
    assert trace_lock(lock, [report], paper_id="2601.12345")["cases"]
    assert not trace_lock(lock, [report], paper_id="2601.99999")["cases"]
    changed = {**report, "source_content_digest": "sha256:" + "f" * 64}
    assert not trace_lock(lock, [changed])["cases"][0]["mappings"][0]["identity_matches"]
    with pytest.raises(ContractError, match="lock"):
        trace_lock(
            lock,
            [report],
            verification=replace(
                verified, run=replace(verified.run, lock_digest="sha256:" + "f" * 64)
            ),
        )


def test_cli_refresh_trace_divergence_is_readonly_and_does_not_reaccept(prepared, tmp_path):
    root, db, _, mapping, head = prepared
    runner = CliRunner()
    args = ["--database", str(db)]
    with Tracker(db, readonly=True) as tracker:
        revision = tracker.revision
    result = runner.invoke(
        main,
        args
        + [
            "refresh-mapping",
            "--repo",
            str(root),
            "--commit",
            head,
            "--manifest",
            "mapping.json",
            "--main-ref",
            "main",
            "--actor",
            "Gordon",
            "--expected-revision",
            str(revision),
        ],
    )
    assert result.exit_code == 0, result.output
    lock, _ = lock_for(mapping)
    path = tmp_path / "lock.json"
    write_document(path, lock.to_dict())
    (root / "source.py").write_text("changed since review")
    commit(root, "new capability")
    before = db.read_bytes()
    result = runner.invoke(
        main, args + ["trace", "--repo", str(root), "--main-ref", "main", "--lock", str(path)]
    )
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["database_divergence"] == ["mapping.one"]
    assert not data["cases"][0]["mappings"][0]["git_and_reviews_current"]
    assert db.read_bytes() == before


def test_plugin_present_elsewhere_in_suite_does_not_match_the_wrong_case(prepared):
    from blastcontain_drill.suites.catalog import RuntimeProbe

    source = prepared[3].source
    plugins = tuple(
        PluginManifest(
            name,
            "1",
            "sha256:" + hex(i)[2:] * 64,
            ("attack_strategy",),
            ("prompt.single",),
            "MIT",
            access_requests=("broker.target",),
        )
        for i, name in ((10, "strategy.a"), (11, "strategy.b"))
    )
    catalog = builtin_catalog(external_sources=(source,), plugins=plugins)
    records = (
        *prepared[3].acceptances,
        *(decision("plugin", p.id, review_digest(p), p.access_requests) for p in plugins),
    )
    probes = tuple(
        RuntimeProbe(p.id, p.artifact_digest, True, "2026-09-21T00:00:00Z") for p in plugins
    )
    spec = SuiteSpec(
        "two.strategies",
        TargetSpec("agent", "builtin.target.resistant"),
        "builtin.environment.fixture",
        ("builtin.evaluator.heuristic",),
        tuple(Selection(p.id, source.id, ("mapped",), strategy=p.id) for p in plugins),
    )
    plan = plan_suite(spec, catalog, records=records, probes=probes)
    assert plan.ready
    records = (*records, decision("suite", spec.id, plan.content_digest))
    lock = create_lock(plan, catalog, records=records, probes=probes)
    report = inspect(prepared)
    plugin = plugins[0]
    report["plugins"] = [
        {
            "id": plugin.id,
            "review_digest": review_digest(plugin),
            "artifact_digest": plugin.artifact_digest,
            "roles": list(plugin.roles),
        }
    ]
    result = trace_lock(lock, [report])
    assert {r["plugin_id"]: r["mappings"][0]["identity_matches"] for r in result["cases"]} == {
        "strategy.a": True,
        "strategy.b": False,
    }
    assert not result["provenance_complete"]
    assert not trace_lock(lock, [report], paper_id="2601.99999")["provenance_complete"]


def test_git_reader_rejects_nonregular_and_oversized_artifacts(prepared):
    root = prepared[0]
    (root / "too-large").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    head = commit(root, "oversized artifact")
    with pytest.raises(ContractError, match="2 MiB"):
        GitObjects(root).blob(head, "too-large")
    (root / "folder").mkdir()
    (root / "folder/child").write_text("data")
    head = commit(root, "directory artifact")
    with pytest.raises(ContractError, match="regular"):
        GitObjects(root).blob(head, "folder")


def test_cli_verifies_actual_run_and_does_not_claim_advisory_trust(prepared, tmp_path):
    report = inspect(prepared)
    store(prepared, report)
    lock, inputs = lock_for(prepared[3])
    stored = asyncio.run(
        execute_run(
            lock, tmp_path / "runs", current_inputs=lambda: inputs, raw_retention_seconds=120
        )
    )
    lock_path = tmp_path / "lock.json"
    write_document(lock_path, lock.to_dict())
    result = CliRunner().invoke(
        main,
        [
            "--database",
            str(prepared[1]),
            "trace",
            "--repo",
            str(prepared[0]),
            "--main-ref",
            "main",
            "--lock",
            str(lock_path),
            "--run",
            str(stored.directory),
            "--allow-advisory",
        ],
    )
    assert result.exit_code == 0, result.output
    traced = json.loads(result.output)
    assert traced["run_id"] and traced["run_replayed"] and traced["provenance_complete"]
    assert not traced["run_trusted"]
