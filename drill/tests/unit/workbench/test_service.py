"""UI shares the CLI's plan, policy, execution and verification boundaries."""

from dataclasses import replace
import asyncio
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blastcontain_drill.contracts import ContractError, PluginManifest, SourceRef
from blastcontain_drill.suites.catalog import SourceSnapshot
from blastcontain_drill.suites.durable import execute_run, verify_run
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.privacy import read_json, write_json
from blastcontain_drill.suites.schema import ModelSettings
from blastcontain_drill.suites.signatures import Signer
from blastcontain_drill.workbench.service import Runs, Workspace

SHA = "sha256:" + "a" * 64


@pytest.fixture
def workspace(tmp_path):
    value = Workspace(tmp_path / "workspace")
    yield value
    value.close()


def accept(workspace, kind="suite", subject=None, decision="accepted", grants=()):
    state = workspace.snapshot()
    if kind == "suite":
        subject, digest = state["suite"]["id"], state["plan"]["content_digest"]
    else:
        artifact = next(a for a in state["artifacts"] if a["id"] == subject)
        digest = artifact["review_digest"]
    return workspace.decide(
        kind=kind,
        subject=subject,
        expected_digest=digest,
        actor="test-reviewer",
        rationale="Controlled fixture scope",
        decision=decision,
        grants=list(grants),
        expected_revision=state["revision"],
    )


def configure(workspace, *, kind="agent", target="resistant", **changes):
    state = workspace.snapshot()
    suite = {
        **state["suite"],
        "target": {"kind": kind, "binding": "builtin.target." + target},
        "selections": [{"id": "mcp", "source": "mcp-poisoning", "scenarios": ["*"]}],
        **changes,
    }
    return workspace.save_suite(suite, state["revision"])


def lock(workspace):
    accept(workspace)
    workspace.lock(workspace.snapshot()["revision"])
    return workspace.snapshot()


@pytest.mark.parametrize(
    "kind,target,passed", [("agent", "resistant", True), ("mcp", "vulnerable", False)]
)
def test_ui_cli_same_lock_and_deterministic_outcomes(workspace, tmp_path, kind, target, passed):
    configure(workspace, kind=kind, target=target)
    inputs = workspace.inputs()
    cli_plan = plan_suite(workspace.read().suite, inputs.catalog, records=inputs.records)
    assert workspace.plan_document(cli_plan) == workspace.snapshot()["plan"]
    state = lock(workspace)
    signer = Signer(Ed25519PrivateKey.generate())
    runs = Runs(workspace, signer=signer)
    try:
        job = runs.start(state["revision"], request_id="1" * 32)
        assert runs.start(state["revision"], request_id="1" * 32) == job
        with pytest.raises(ContractError, match="different action"):
            runs.start(state["revision"], request_id="1" * 32, raw_retention_seconds=60)
        runs.jobs[job["job_id"]]["thread"].join(20)
        assert not runs.jobs[job["job_id"]]["error"]
        run_id = runs.jobs[job["job_id"]]["run_id"]
        ui_result = runs.verify(run_id)
        locked = workspace.selected_lock(state["revision"])
        direct = asyncio.run(
            execute_run(
                locked,
                tmp_path / "cli-runs",
                current_inputs=workspace.inputs,
                signer=signer,
                require_signing=True,
            )
        )
        cli_result = verify_run(direct.directory, lock=locked, trusted_public_key=signer.public_key)
        assert ui_result["trusted"] and ui_result["replayed"]
        assert ui_result["security_passed"] is cli_result.security_passed is passed
        assert ui_result["attested_pass"] is passed
        assert [c["result"]["security"] for c in ui_result["cases"]] == [
            c.result.security for c in cli_result.run.cases
        ]
        assert len(runs.snapshot()["runs"]) == 1
        assert workspace.export()["lock"] == locked.to_dict()
    finally:
        runs.close()


def test_atomic_bad_import_stale_edit_and_exclusive_lease(workspace):
    state = workspace.snapshot()
    with pytest.raises(ContractError, match="owns"):
        Workspace(workspace.root)
    collision = PluginManifest("builtin.target.resistant", "1", SHA, ("target",), (), "MIT")
    with pytest.raises(ContractError):
        workspace.import_artifact("plugin", collision.to_dict(), state["revision"])
    assert workspace.snapshot() == state
    configure(workspace, kind="mcp")
    with pytest.raises(ContractError, match="changed"):
        workspace.save_suite(state["suite"], state["revision"])
    assert workspace.snapshot()["suite"]["target"]["kind"] == "mcp"


def test_separate_acceptance_and_changed_scope_invalidates(workspace):
    plugin = PluginManifest(
        "fixture-plugin",
        "1",
        SHA,
        ("attack_strategy",),
        ("prompt.single",),
        "MIT",
        access_requests=("broker.attacker",),
    )
    state = workspace.import_artifact("plugin", plugin.to_dict(), workspace.snapshot()["revision"])
    assert not state["artifacts"][0]["current_acceptance"]
    with pytest.raises(ContractError, match="exactly match"):
        accept(workspace, "plugin", plugin.id)
    state = accept(workspace, "plugin", plugin.id, grants=plugin.access_requests)
    assert state["artifacts"][0]["current_acceptance"]
    assert not any(d["kind"] == "suite" for d in state["decisions"])
    updated = replace(plugin, version="2", access_requests=("broker.attacker", "broker.evaluator"))
    state = workspace.import_artifact("plugin", updated.to_dict(), state["revision"])
    assert not state["artifacts"][0]["current_acceptance"]
    assert state["artifacts"][0]["previous"] == plugin.to_dict()
    assert len(state["decisions"]) == 1
    scenario = workspace.inputs().catalog.sources[0].scenarios[0]
    source = SourceSnapshot(
        "research", "v1", SHA, (replace(scenario, source=SourceRef("research", "v1")),)
    )
    state = workspace.import_artifact("source", source.to_dict(), state["revision"])
    state = accept(workspace, "content", "research")
    assert next(a for a in state["artifacts"] if a["id"] == "research")["current_acceptance"]


def test_revoke_invalidates_current_lock_and_tampering_is_detected(workspace):
    configure(workspace)
    state = lock(workspace)
    assert state["lock_digest"]
    state = accept(workspace, decision="revoked")
    assert state["lock_digest"] is None
    with pytest.raises(ContractError):
        workspace.lock(state["revision"])
    reference = workspace.read().acceptances
    path = workspace.root / "artifacts" / (reference[7:] + ".json")
    value = read_json(path)
    value["records"][-1]["decision"] = "accepted"
    write_json(path, value, replace=True)
    with pytest.raises(ContractError, match="changed"):
        workspace.snapshot()


def test_active_cancel_and_provider_errors_do_not_leak(workspace):
    started = threading.Event()

    async def transport(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    configure(
        workspace,
        target="llm",
        models=[ModelSettings("target", "http://127.0.0.1:1234/v1", "org/model:tag").to_dict()],
    )
    state = lock(workspace)
    runs = Runs(workspace, transport=transport)
    try:
        job = runs.start(state["revision"], request_id="2" * 32)
        assert started.wait(15)
        runs.cancel(job["job_id"])
        runs.jobs[job["job_id"]]["thread"].join(15)
        assert not runs.jobs[job["job_id"]]["thread"].is_alive()
        snapshot = runs.snapshot()
        assert not snapshot["runs"][0]["reported_security_passed"]
        assert not runs.verify(snapshot["runs"][0]["run_id"])["security_passed"]
    finally:
        runs.close()
    with pytest.raises(ContractError, match="closed"):
        runs.start(state["revision"], request_id="3" * 32)


@pytest.mark.parametrize("model", ["org/model:tag", "org/model@v2", "qwen2.5:32b"])
def test_provider_model_ids_preserved(model):
    settings = ModelSettings("target", "http://127.0.0.1:1234/v1", model)
    assert ModelSettings.from_dict(settings.to_dict()).model_ref == model


@pytest.mark.parametrize("model", ["bad model", "a\nmodel", "a" * 257, "$(secret)"])
def test_unsafe_model_ids_rejected(model):
    with pytest.raises(ContractError):
        ModelSettings("target", "http://127.0.0.1:1234/v1", model)
    with pytest.raises(ContractError):
        ModelSettings("target", "http://127.0.0.1:1234/v1", "good", credential_ref="org/secret")


def test_browser_integer_temperature_normalizes_without_loosening_budgets():
    settings = ModelSettings("target", "http://127.0.0.1:1234/v1", "org/model")
    assert ModelSettings.from_dict({**settings.to_dict(), "temperature": 0}) == settings
    with pytest.raises(ContractError):
        ModelSettings.from_dict({**settings.to_dict(), "temperature": True})
    with pytest.raises(ContractError):
        ModelSettings.from_dict({**settings.to_dict(), "max_output_tokens": 1.5})
