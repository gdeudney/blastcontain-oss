"""Suite coverage and lock trust boundaries, using model-free data only."""

from dataclasses import replace
import json
from pathlib import Path
import socket
import subprocess

from click.testing import CliRunner
import pytest

from blastcontain_drill.contracts import (
    AcceptanceRecord,
    ContractError,
    Injection,
    PluginManifest,
    SourceRef,
)
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.suites.artifacts import canonical, read_document, write_document
from blastcontain_drill.suites.catalog import (
    RuntimeProbe,
    SourceSnapshot,
    builtin_catalog,
)
from blastcontain_drill.suites.cli import main
from blastcontain_drill.suites.lock import SuiteLock, create_lock, validate_lock
from blastcontain_drill.suites.planner import ResolvedPlan, plan_suite
from blastcontain_drill.suites.schema import Limits, ModelSettings, Selection, SuiteSpec, TargetSpec

SHA = "sha256:" + "a" * 64
OTHER_SHA = "sha256:" + "b" * 64
TIME = "2026-09-20T12:00:00Z"
ENDPOINT = "http://127.0.0.1:1234/v1"
EXAMPLES = Path(__file__).parents[3] / "examples" / "suites"


@pytest.fixture(scope="module")
def catalog():
    return builtin_catalog()


def spec(**changes):
    return replace(
        SuiteSpec(
            "test-suite",
            TargetSpec("agent", "builtin.target.resistant"),
            "builtin.environment.fixture",
            ("builtin.evaluator.heuristic",),
            (Selection("baseline", "builtin", ("*",)),),
        ),
        **changes,
    )


def decision(subject, kind, content_digest, **changes):
    return replace(
        AcceptanceRecord(
            subject,
            kind,
            content_digest,
            "reviewer",
            "accepted",
            TIME,
            "Reviewed controlled fixture",
        ),
        **changes,
    )


def lock_plan(plan, catalog, records=(), probes=()):
    records = (*records, decision(plan.spec.id, "suite", plan.content_digest))
    return create_lock(plan, catalog, records=records, probes=probes), records


def external(catalog, *, plugin=True):
    original = next(s for s in catalog.sources if s.id == "builtin").scenarios[0]
    scenario = replace(
        original,
        source=SourceRef("research", "paper-v1"),
        attack_objective="Attempt the controlled fixture objective",
    )
    source = SourceSnapshot("research", "paper-v1", SHA, (scenario,))
    manifest = PluginManifest(
        "reference",
        "1.0",
        SHA,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0",
        access_requests=("broker.attacker",),
    )
    probe = RuntimeProbe(manifest.id, SHA, True, TIME)
    records = (decision(source.id, "content", source.content_digest),)
    if plugin:
        records += (
            decision(
                manifest.id,
                "plugin",
                review_digest(manifest),
                granted_access=manifest.access_requests,
            ),
        )
    cat = replace(
        catalog, sources=(*catalog.sources, source), plugins=(manifest,) if plugin else ()
    )
    suite = spec(
        models=(ModelSettings("attacker", ENDPOINT, "local-abliterated"),) if plugin else (),
        selections=(
            Selection(
                "research", "research", (scenario.id,), strategy=manifest.id if plugin else None
            ),
        ),
    )
    return cat, suite, records, (probe,) if plugin else ()


def test_builtin_inventory_and_roundtrip(catalog):
    assert sum(len(s.scenarios) for s in catalog.sources) == 501
    plan = plan_suite(spec(), catalog)
    assert plan.ready and len(plan.cases) == 14
    assert ResolvedPlan.from_dict(json.loads(canonical(plan.to_dict()))) == plan
    lock, records = lock_plan(plan, catalog)
    assert SuiteLock.from_dict(json.loads(canonical(lock.to_dict()))) == lock
    validate_lock(lock, catalog, records=records)


def test_equivalent_input_order_yields_identical_lock(catalog):
    cat, suite, records, probes = external(catalog)
    suite = replace(suite, seeds=(8, 2), selections=(*suite.selections, spec().selections[0]))
    plan = plan_suite(suite, cat, records=records, probes=probes)
    left, decisions = lock_plan(plan, cat, records, probes)
    reordered = replace(
        suite, seeds=tuple(reversed(suite.seeds)), selections=tuple(reversed(suite.selections))
    )
    other_cat = replace(
        cat,
        sources=tuple(
            replace(s, scenarios=tuple(reversed(s.scenarios))) for s in reversed(cat.sources)
        ),
        bindings=tuple(reversed(cat.bindings)),
    )
    other = plan_suite(reordered, other_cat, records=tuple(reversed(records)), probes=probes)
    right = create_lock(other, other_cat, records=tuple(reversed(decisions)), probes=probes)
    assert left == right
    assert canonical(left.to_dict()) == canonical(right.to_dict())


@pytest.mark.parametrize(
    "change",
    [
        {"seeds": ()},
        {"seeds": (1, 1)},
        {"seeds": (-1,)},
        {"seeds": (True,)},
        {"concurrency": 0},
        {"concurrency": 65},
        {"concurrency": True},
        {"selections": ()},
        {"evaluators": ()},
        {"case_limits": Limits(model_calls=201)},
    ],
)
def test_invalid_suite_inputs(change):
    with pytest.raises(ContractError):
        spec(**change)


@pytest.mark.parametrize("selectors", [(), ("x", "x"), ("*", "x"), ("",)])
def test_invalid_selectors(selectors):
    with pytest.raises(ContractError):
        Selection("bad", "builtin", selectors)


def test_overlapping_selections_rejected(catalog):
    first = next(s for s in catalog.sources if s.id == "builtin").scenarios[0].id
    with pytest.raises(ContractError, match="Duplicate scenario"):
        plan_suite(
            spec(selections=(*spec().selections, Selection("again", "builtin", (first,)))), catalog
        )


def test_selection_limit_is_bounded(catalog):
    with pytest.raises(ContractError, match="10000"):
        plan_suite(spec(seeds=tuple(range(1000))), catalog)


@pytest.mark.parametrize("missing", ["source", "scenario", "plugin"])
@pytest.mark.parametrize("required", [True, False])
def test_required_and_optional_missing_inputs_remain_in_roster(catalog, missing, required):
    selection = Selection("missing", "builtin", ("absent",), required=required)
    if missing == "source":
        selection = replace(selection, source="absent")
    if missing == "plugin":
        selection = replace(selection, scenarios=("*",), strategy="absent")
    suite = spec(selections=(Selection("good", "mcp-poisoning", ("*",)), selection))
    plan = plan_suite(suite, catalog)
    failed = [c for c in plan.cases if c.selection_id == "missing"]
    assert failed and all(c.diagnostics for c in failed)
    assert {c.disposition for c in failed} == {"blocked" if required else "excluded"}
    assert plan.ready is not required
    if required:
        with pytest.raises(ContractError, match="blocked"):
            lock_plan(plan, catalog)
    else:
        lock, records = lock_plan(plan, catalog)
        validate_lock(lock, catalog, records=records)


def test_all_excluded_and_empty_source_cannot_pass(catalog):
    empty = SourceSnapshot("empty", "v1", SHA, ())
    cat = replace(catalog, sources=(*catalog.sources, empty))
    plan = plan_suite(spec(selections=(Selection("empty", "empty", ("*",), required=False),)), cat)
    assert len(plan.cases) == 1 and not plan.ready
    assert plan.cases[0].scenario is None
    with pytest.raises(ContractError, match="entirely excluded"):
        lock_plan(plan, cat)


@pytest.mark.parametrize(
    "change,diagnostic",
    [
        ({"target": TargetSpec("agent", "builtin.evaluator.heuristic")}, "role mismatch"),
        ({"target": TargetSpec("mcp", "builtin.target.resistant")}, "MCP target"),
        ({"target": TargetSpec("agent", "builtin.target.llm")}, "missing target model"),
    ],
)
def test_binding_compatibility(catalog, change, diagnostic):
    plan = plan_suite(spec(**change), catalog)
    assert not plan.ready
    assert any(diagnostic in d for c in plan.cases for d in c.diagnostics)


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("capabilities", (), "Missing capabilities"),
        ("observations", ("model_output", "tool_actions"), "Missing observations"),
    ],
)
def test_omitted_mcp_requirements_cannot_hide_needed_support(catalog, field, value, message):
    mcp = next(s for s in catalog.sources if s.id == "mcp-poisoning")
    mcp = replace(
        mcp,
        scenarios=tuple(
            replace(s, required_capabilities=(), required_observations=()) for s in mcp.scenarios
        ),
    )
    cat = replace(
        catalog,
        sources=tuple(mcp if s.id == mcp.id else s for s in catalog.sources),
        bindings=tuple(
            replace(b, **{field: value}) if b.role == "environment" else b for b in catalog.bindings
        ),
    )
    plan = plan_suite(spec(selections=(Selection("mcp", mcp.id, ("*",)),)), cat)
    assert not plan.ready and all(any(message in d for d in c.diagnostics) for c in plan.cases)


def test_unsupported_surface_task_and_evaluator_are_explicit(catalog):
    cat, suite, records, probes = external(catalog, plugin=False)
    source = cat.sources[-1]
    scenario = replace(
        source.scenarios[0],
        injections=(Injection("memory", "test"),),
        legitimate_task="Test task",
        task_checks=("unsupported",),
        security=replace(source.scenarios[0].security, goal="content"),
    )
    source = replace(source, scenarios=(scenario,))
    cat = replace(
        cat,
        sources=(*cat.sources[:-1], source),
        bindings=tuple(
            replace(b, capabilities=()) if b.role == "evaluator" else b for b in cat.bindings
        ),
    )
    records = (decision(source.id, "content", source.content_digest),)
    plan = plan_suite(suite, cat, records=records)
    errors = " ".join(plan.cases[0].diagnostics)
    assert "inject.memory" in errors and "task-check" in errors and "rubric" in errors


def test_external_content_plugin_and_suite_require_separate_acceptances(catalog):
    cat, suite, records, probes = external(catalog)
    assert not plan_suite(suite, cat, probes=probes).ready
    assert not plan_suite(suite, cat, records=records[:1], probes=probes).ready
    plan = plan_suite(suite, cat, records=records, probes=probes)
    assert plan.ready
    with pytest.raises(ContractError, match="suite has no current acceptance"):
        create_lock(plan, cat, records=records, probes=probes)
    lock, records = lock_plan(plan, cat, records, probes)
    assert {r.kind for r in lock.acceptances} == {"plugin", "content", "suite"}
    validate_lock(lock, cat, records=records, probes=probes)


@pytest.mark.parametrize("kind", ["plugin", "content", "suite"])
@pytest.mark.parametrize("decision_value", ["rejected", "revoked"])
def test_latest_decision_in_file_order_overrides_prior_acceptance(catalog, kind, decision_value):
    cat, suite, records, probes = external(catalog)
    plan = plan_suite(suite, cat, records=records, probes=probes)
    lock, records = lock_plan(plan, cat, records, probes)
    original = next(r for r in records if r.kind == kind)
    # Earlier timestamp and different digest do not undo the latest file-order revocation.
    records += (
        replace(
            original,
            decision=decision_value,
            artifact_digest=OTHER_SHA,
            recorded_at="2020-01-01T00:00:00Z",
        ),
    )
    with pytest.raises(ContractError):
        validate_lock(lock, cat, records=records, probes=probes)


@pytest.mark.parametrize("change", ["data", "code", "image", "scope", "target", "model", "probe"])
def test_changes_invalidate_reviewed_lock(catalog, change):
    cat, suite, records, probes = external(catalog)
    suite = replace(suite, models=(ModelSettings("attacker", ENDPOINT, "abliterated"),))
    plan = plan_suite(suite, cat, records=records, probes=probes)
    lock, records = lock_plan(plan, cat, records, probes)
    if change in ("data", "code"):
        source = cat.sources[-1]
        if change == "data":
            source = replace(
                source, scenarios=(replace(source.scenarios[0], entry_prompt="changed"),)
            )
        else:
            source = replace(source, code_digest=OTHER_SHA)
        cat = replace(cat, sources=(*cat.sources[:-1], source))
    if change in ("image", "scope"):
        changes = {"artifact_digest": OTHER_SHA} if change == "image" else {"access_requests": ()}
        cat = replace(cat, plugins=(replace(cat.plugins[0], **changes),))
    if change == "probe":
        probes = (replace(probes[0], available=False),)
    if change in ("target", "model"):
        changed = (
            replace(suite, target=TargetSpec("agent", "builtin.target.vulnerable"))
            if (change == "target")
            else replace(suite, models=(replace(suite.models[0], temperature=1.0),))
        )
        new_plan = plan_suite(changed, cat, records=records, probes=probes)
        assert new_plan.content_digest != plan.content_digest
        with pytest.raises(ContractError, match="stale"):
            create_lock(new_plan, cat, records=records, probes=probes)
    else:
        with pytest.raises(ContractError, match="Plan changed"):
            validate_lock(lock, cat, records=records, probes=probes)


def test_probe_required_and_not_implicitly_reused_from_lock(catalog):
    cat, suite, records, probes = external(catalog)
    assert not plan_suite(suite, cat, records=records).ready
    assert not plan_suite(
        suite, cat, records=records, probes=(replace(probes[0], artifact_digest=OTHER_SHA),)
    ).ready
    plan = plan_suite(suite, cat, records=records, probes=probes)
    lock, records = lock_plan(plan, cat, records, probes)
    with pytest.raises(ContractError):
        validate_lock(lock, cat, records=records)


@pytest.mark.parametrize(
    "change,diagnostic",
    [
        ({"roles": ("evaluator",)}, "role mismatch"),
        ({"capabilities": ()}, "Strategy does not support"),
        ({"access_requests": ("network.host",)}, "Unsupported access"),
        ({"config_schema": {"type": "string"}}, "empty configuration"),
    ],
)
def test_external_manifest_cannot_invent_supported_worker_features(catalog, change, diagnostic):
    cat, suite, records, probes = external(catalog)
    manifest = replace(cat.plugins[0], **change)
    cat = replace(cat, plugins=(manifest,))
    records = (
        records[0],
        decision(
            manifest.id, "plugin", review_digest(manifest), granted_access=manifest.access_requests
        ),
    )
    plan = plan_suite(suite, cat, records=records, probes=probes)
    assert not plan.ready
    assert diagnostic in " ".join(plan.cases[0].diagnostics)


def test_builtin_pair_retains_abliterated_model_and_needs_objective(catalog):
    cat, suite, records, probes = external(catalog, plugin=False)
    suite = replace(
        suite, selections=(replace(suite.selections[0], strategy="builtin.strategy.pair"),)
    )
    assert not plan_suite(suite, cat, records=records).ready
    suite = replace(suite, models=(ModelSettings("attacker", ENDPOINT, "local-abliterated"),))
    plan = plan_suite(suite, cat, records=records)
    assert plan.ready and plan.spec.models[0].model_ref == "local-abliterated"
    source = cat.sources[-1]
    source = replace(source, scenarios=(replace(source.scenarios[0], attack_objective=None),))
    cat = replace(cat, sources=(*cat.sources[:-1], source))
    plan = plan_suite(suite, cat, records=(decision(source.id, "content", source.content_digest),))
    assert not plan.ready and "objective" in " ".join(plan.cases[0].diagnostics)


def test_endpoint_change_and_builtin_code_change_need_new_review(catalog):
    suite = spec(
        target=TargetSpec("agent", "builtin.target.llm"),
        models=(ModelSettings("target", ENDPOINT, "target-model"),),
    )
    plan = plan_suite(suite, catalog)
    lock, records = lock_plan(plan, catalog)
    changed = replace(
        suite, models=(replace(suite.models[0], endpoint_url="http://localhost:9999/v1"),)
    )
    replanned = plan_suite(changed, catalog)
    assert plan.content_digest != replanned.content_digest
    with pytest.raises(ContractError, match="stale"):
        create_lock(replanned, catalog, records=records)
    cat = replace(
        catalog, bindings=tuple(replace(b, artifact_digest=OTHER_SHA) for b in catalog.bindings)
    )
    with pytest.raises(ContractError, match="Plan changed"):
        validate_lock(lock, cat, records=records)


def test_acceptance_timestamps_do_not_change_content_digest(catalog):
    cat, suite, records, probes = external(catalog)
    plan = plan_suite(suite, cat, records=records, probes=probes)
    left, records = lock_plan(plan, cat, records, probes)
    renewed = tuple(
        replace(r, actor="second-reviewer", recorded_at="2026-09-21T00:00:00Z") for r in records
    )
    right = create_lock(plan, cat, records=renewed, probes=probes)
    assert left.content_digest == right.content_digest
    assert left.lock_digest != right.lock_digest


def test_unknown_revision_cannot_lock(catalog):
    cat, suite, records, probes = external(catalog, plugin=False)
    source = cat.sources[-1]
    source = replace(
        source,
        revision="unknown",
        scenarios=(replace(source.scenarios[0], source=SourceRef(source.id, "unknown")),),
    )
    cat = replace(cat, sources=(*cat.sources[:-1], source))
    plan = plan_suite(suite, cat, records=(decision(source.id, "content", source.content_digest),))
    assert not plan.ready and "not pinned" in " ".join(plan.cases[0].diagnostics)


def test_tampered_plan_or_acceptance_detected(catalog):
    plan = plan_suite(spec(), catalog)
    lock, records = lock_plan(plan, catalog)
    for location in ("case", "acceptance"):
        data = lock.to_dict()
        if location == "case":
            data["plan"]["cases"][0]["scenario"]["entry_prompt"] = "tampered"
        else:
            data["acceptances"][0]["actor"] = "different"
        with pytest.raises(ContractError, match="digest mismatch"):
            SuiteLock.from_dict(data)
    with pytest.raises(ContractError, match="case IDs"):
        replace(plan, cases=(plan.cases[0], plan.cases[0]))


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1}',
        b'{"number":NaN}',
        b'{"number":Infinity}',
    ],
)
def test_strict_json_rejects_ambiguous_input(tmp_path, raw):
    path = tmp_path / "bad.json"
    path.write_bytes(raw)
    with pytest.raises(ContractError):
        read_document(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("authorization", "secret-sentinel"),
    ],
)
def test_strict_wire_rejects_unknown_fields_and_versions(field, value):
    data = spec().to_dict()
    data[field] = value
    with pytest.raises(ContractError):
        SuiteSpec.from_dict(data)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:secret@example.com",
        "https://example.com?token=secret",
        "Bearer secret",
        "../credentials",
        "https://example.com/#secret",
    ],
)
def test_credentials_urls_and_paths_cannot_be_binding_configuration(endpoint):
    with pytest.raises(ContractError):
        ModelSettings("target", endpoint, "test-model")


def test_model_settings_finite_and_pinned_identity():
    for value in (float("nan"), float("inf")):
        with pytest.raises(ContractError):
            ModelSettings("target", ENDPOINT, "model", temperature=value)
    with pytest.raises(ContractError):
        ModelSettings("target", ENDPOINT, "model", identity="pinned")
    model = ModelSettings("target", ENDPOINT, "model", identity="pinned", model_digest=SHA)
    assert ModelSettings.from_dict(model.to_dict()) == model


def test_artifact_safety_limits_and_no_overwrite(tmp_path):
    path = tmp_path / "data.json"
    write_document(path, {"test": 1})
    with pytest.raises(FileExistsError):
        write_document(path, {"test": 2})
    with pytest.raises(ContractError, match="traverse"):
        read_document(tmp_path / ".." / "data.json")
    huge = tmp_path / "huge.json"
    with huge.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)
    with pytest.raises(ContractError, match="16 MiB"):
        read_document(huge)


def test_symlink_artifacts_rejected(tmp_path):
    path = tmp_path / "data.json"
    write_document(path, {"test": 1})
    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except OSError:
        pytest.skip("This host does not permit creating symlinks")
    with pytest.raises(ContractError, match="symlinks"):
        read_document(link)


def test_planning_does_not_probe_execute_import_plugins_or_read_credentials(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Planning must not execute processes or open network connections")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr("blastcontain_drill.llm.ChatClient.chat", forbidden)
    monkeypatch.setattr("blastcontain_drill.plugins.runtime.local_image_available", forbidden)
    monkeypatch.setattr("blastcontain_drill.plugins.runtime.PodmanWorker.prepare", forbidden)
    monkeypatch.setenv("OPENAI_API_KEY", "secret-sentinel-never-read")
    marker = tmp_path / "imported"
    (tmp_path / "hostile_plugin.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    cat, suite, records, probes = external(builtin_catalog())
    manifest = replace(cat.plugins[0], upstream="hostile_plugin:entrypoint")
    cat = replace(cat, plugins=(manifest,))
    records = (
        records[0],
        decision(
            manifest.id, "plugin", review_digest(manifest), granted_access=manifest.access_requests
        ),
    )
    plan = plan_suite(suite, cat, records=records, probes=probes)
    lock, _ = lock_plan(plan, cat, records, probes)
    assert not marker.exists()
    assert b"secret-sentinel" not in canonical(lock.to_dict())
    llm_suite = spec(
        target=TargetSpec("agent", "builtin.target.llm"),
        models=(ModelSettings("target", ENDPOINT, "test-model"),),
    )
    assert plan_suite(llm_suite, cat).ready


@pytest.mark.parametrize("name,count", [("agent", 28), ("mcp", 4)])
def test_example_plan_cli_and_lock_roundtrip(tmp_path, catalog, name, count):
    runner = CliRunner()
    output, lock_file = tmp_path / "plan.json", tmp_path / "lock.json"
    command = ["plan", str(EXAMPLES / f"{name}.json"), "--output", str(output)]
    result = runner.invoke(main, command)
    assert result.exit_code == 0, result.output
    data = read_document(output)
    assert data["ready"] and len(data["plan"]["cases"]) == count
    acceptance = decision(data["plan"]["spec"]["id"], "suite", data["content_digest"])
    decisions = tmp_path / "acceptances.json"
    write_document(decisions, {"schema_version": 1, "records": [acceptance.to_dict()]})
    result = runner.invoke(
        main,
        [
            "plan",
            str(EXAMPLES / f"{name}.json"),
            "--lock",
            str(lock_file),
            "--acceptances",
            str(decisions),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(main, ["check-lock", str(lock_file), "--acceptances", str(decisions)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(main, ["check-lock", str(lock_file)])
    assert result.exit_code != 0 and "acceptance" in result.output


def test_blocked_cli_emits_diagnostics_without_writing_lock(tmp_path):
    suite_file, output, lock_file = (tmp_path / name for name in ("suite", "plan", "lock"))
    write_document(suite_file, spec(environment="absent").to_dict())
    result = CliRunner().invoke(
        main, ["plan", str(suite_file), "--output", str(output), "--lock", str(lock_file)]
    )
    assert result.exit_code != 0 and not lock_file.exists()
    data = read_document(output)
    assert not data["ready"] and data["plan"]["cases"][0]["diagnostics"]


def test_external_cannot_shadow_builtins(catalog):
    with pytest.raises(ContractError, match="source IDs"):
        builtin_catalog(external_sources=(catalog.sources[0],))
    plugin = PluginManifest("builtin.target.resistant", "v1", SHA, ("target",), (), "MIT")
    with pytest.raises(ContractError, match="binding/plugin IDs"):
        builtin_catalog(plugins=(plugin,))
