"""Real pinned package and actual worker tests. Missing image is a failure, never a skip."""

import asyncio
from dataclasses import replace
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess

import pytest

from blastcontain_drill.contracts import AcceptanceRecord, Injection
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.plugins.runtime import (
    BudgetExceeded,
    PodmanWorker,
    WorkerError,
    WorkerLimits,
)
from blastcontain_drill.suites.artifacts import read_document
from blastcontain_drill.suites.catalog import builtin_catalog
from blastcontain_drill.suites.durable import execute_run, verify_run
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.run_store import request_cancel
from blastcontain_drill.suites.schema import SuiteSpec
from blastcontain_drill.suites.service import ExecutionInputs

PLUGIN = Path(__file__).parents[1]


def command(*args):
    return subprocess.run(
        ["podman", "--remote=false", *args], capture_output=True, text=True, check=True, timeout=120
    ).stdout.strip()


@pytest.fixture(scope="module")
def image():
    image_id = os.environ["DRILL_PYRIT_IMAGE"]
    assert image_id.startswith("sha256:")
    command("image", "inspect", image_id)
    return image_id


def decision(subject, kind, value, grants=()):
    return AcceptanceRecord(
        subject,
        kind,
        value,
        "container-fixture",
        "accepted",
        "2026-09-21T00:00:00Z",
        "Controlled fixture only",
        grants,
    )


@pytest.fixture
def prepared(image, tmp_path):
    definition = spec_from_file_location("pyrit_fixture_preparation", PLUGIN / "prepare.py")
    module = module_from_spec(definition)
    definition.loader.exec_module(module)
    manifest, source, probe = module.prepare(image, tmp_path / "inputs")
    records = [
        decision(manifest.id, "plugin", review_digest(manifest), manifest.access_requests),
        decision(source.id, "content", source.content_digest),
    ]
    assert probe.available, read_document(tmp_path / "inputs" / "review.json")["runtime_diagnostic"]
    return manifest, source, probe, records


def removed(worker):
    result = subprocess.run(
        ["podman", "--remote=false", "container", "exists", worker.name], check=False
    )
    assert result.returncode == 1


def test_real_upstream_parity_inside_bounded_image(image):
    output = command(
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--read-only-tmpfs=false",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--user=65532:65532",
        "--cap-drop=all",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--memory-swap=256m",
        "--pids-limit=64",
        "--unsetenv-all",
        "--env=HOME=/tmp",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--entrypoint=/usr/local/bin/python",
        image,
        "/opt/plugin/validate.py",
    )
    assert json.loads(output) == {
        "pyrit": "1.1.0",
        "direct_adapter_parity": True,
        "fresh_memory": True,
        "cases": 2,
    }


def test_reset_and_two_independently_observed_static_calls(prepared):
    manifest, source, _, records = prepared
    observed = []

    async def target(injection, context):
        observed.append((context.scenario_id, injection.payload))
        return {"response_text": "Controlled reply", "outcome": "BYPASS"}

    worker = PodmanWorker(
        manifest, records, bindings={"target": target}, limits=WorkerLimits(max_calls=2)
    )

    async def run():
        async with worker:
            await worker.prepare()
            for name in ("first", "second"):
                await worker.reset(replace(source.scenarios[0], id=name))
                result = await worker.execute()
                assert (
                    result.claims["target_calls"] == 1
                    and result.claims["upstream_outcome"] == "undetermined"
                )
            await worker.finish()

    asyncio.run(run())
    assert [i for i, _ in observed] == ["first", "second"] and len(worker.calls) == 2
    removed(worker)


@pytest.mark.parametrize(
    "changes",
    [
        {"turns": ("one", "two")},
        {"injections": (Injection("document", "unreviewed"),)},
        {"attack_objective": None},
    ],
)
def test_unsupported_scope_fails_without_target_dispatch(prepared, changes):
    manifest, source, _, records = prepared

    async def target(*args):
        pytest.fail("Unsupported scenario reached target")

    worker = PodmanWorker(manifest, records, bindings={"target": target})

    async def run():
        with pytest.raises(WorkerError):
            async with worker:
                await worker.prepare()
                await worker.reset(replace(source.scenarios[0], **changes))

    asyncio.run(run())
    assert not worker.calls
    removed(worker)


def test_resets_do_not_replenish_worker_call_budget(prepared):
    manifest, source, _, records = prepared

    async def target(*args):
        return {"response_text": "fixture"}

    worker = PodmanWorker(
        manifest, records, bindings={"target": target}, limits=WorkerLimits(max_calls=1)
    )

    async def run():
        with pytest.raises(BudgetExceeded):
            async with worker:
                await worker.prepare()
                await worker.reset(source.scenarios[0])
                await worker.execute()
                await worker.reset(replace(source.scenarios[0], id="second"))
                await worker.execute()

    asyncio.run(run())
    assert len(worker.calls) == 1
    removed(worker)


@pytest.mark.parametrize("target", ["resistant", "vulnerable"])
def test_suite_evidence_is_host_reduced_signed_and_replayable(prepared, tmp_path, target):
    manifest, source, probe, records = prepared
    catalog = builtin_catalog(external_sources=(source,), plugins=(manifest,))
    spec = SuiteSpec.from_dict(read_document(tmp_path / "inputs" / (target + ".json")))
    plan = plan_suite(spec, catalog, records=records, probes=(probe,))
    assert plan.ready
    records.append(decision(spec.id, "suite", plan.content_digest))
    lock = create_lock(plan, catalog, records=records, probes=(probe,))
    inputs = ExecutionInputs(catalog, tuple(records), (probe,))
    stored = asyncio.run(
        execute_run(
            lock, tmp_path / "runs", current_inputs=lambda: inputs, raw_retention_seconds=120
        )
    )
    assert len(stored.run.cases) == 2
    assert all(c.disposition == "completed" and len(c.attempts) == 1 for c in stored.run.cases)
    assert stored.run.passed is (target == "resistant")
    verified = verify_run(stored.directory, allow_advisory=True)
    assert verified.replayed and verified.security_passed is (target == "resistant")
    assert not request_cancel(stored.directory)


def test_active_model_cancellation_removes_pyrit_worker_and_keeps_roster(
    prepared, tmp_path, monkeypatch
):
    from blastcontain_drill.suites import adaptive
    from blastcontain_drill.suites.schema import ModelSettings, TargetSpec

    manifest, source, probe, records = prepared
    catalog = builtin_catalog(external_sources=(source,), plugins=(manifest,))
    spec = SuiteSpec.from_dict(read_document(tmp_path / "inputs/resistant.json"))
    spec = replace(
        spec,
        target=TargetSpec("agent", "builtin.target.llm"),
        models=(ModelSettings("target", "http://127.0.0.1:1234/v1", "recording-fixture"),),
    )
    plan = plan_suite(spec, catalog, records=records, probes=(probe,))
    records.append(decision(spec.id, "suite", plan.content_digest))
    lock = create_lock(plan, catalog, records=records, probes=(probe,))
    inputs = ExecutionInputs(catalog, tuple(records), (probe,))
    workers = []

    class RecordedWorker(PodmanWorker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            workers.append(self)

    monkeypatch.setattr(adaptive, "PodmanWorker", RecordedWorker)

    async def exercise():
        started, stopped = asyncio.Event(), asyncio.Event()
        directories = []

        async def blocked(*args):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        task = asyncio.create_task(
            execute_run(
                lock,
                tmp_path / "runs",
                current_inputs=lambda: inputs,
                raw_retention_seconds=120,
                transport=blocked,
                on_created=directories.append,
            )
        )
        await asyncio.wait_for(started.wait(), 30)
        assert request_cancel(directories[0])
        stored = await asyncio.wait_for(task, 20)
        assert stopped.is_set() and len(stored.run.cases) == 2
        assert all(c.disposition == "cancelled" for c in stored.run.cases)
        verified = verify_run(stored.directory, allow_advisory=True)
        assert verified.replayed and not verified.security_passed

    asyncio.run(exercise())
    assert len(workers) == 1
    removed(workers[0])
