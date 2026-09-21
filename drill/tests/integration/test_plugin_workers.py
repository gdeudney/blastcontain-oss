"""Real container conformance: never substitute mocks for isolation evidence."""

import asyncio
from dataclasses import replace
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import pytest

from blastcontain_drill.contracts import AcceptanceRecord, ContractError, PluginManifest
from blastcontain_drill.contracts.legacy import scenario_from_attack
from blastcontain_drill.corpus import BuiltinReplaySource
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.plugins.protocol import ProtocolError
from blastcontain_drill.plugins.runtime import (
    BudgetExceeded,
    PodmanWorker,
    WorkerError,
    WorkerLimits,
)

pytestmark = pytest.mark.podman
ROOT = Path(__file__).resolve().parents[3]


def command(*args):
    return subprocess.run(
        ["podman", "--remote=false", *args], capture_output=True, text=True, timeout=120, check=True
    ).stdout.strip()


@pytest.fixture(scope="module")
def images():
    if sys.platform != "linux" or not shutil.which("podman"):
        if os.environ.get("DRILL_REQUIRE_WORKER_TESTS"):
            pytest.fail("Worker integration requires local Linux Podman")
        pytest.skip("Worker integration requires local Linux Podman")
    # CI builds on a supported runner. An installed but unsupported runtime fails
    # explicitly in the worker; it is not silently skipped or run on the host.
    base = os.environ.get("DRILL_WORKER_BASE_IMAGE", "docker.io/library/python:3.12-slim")
    reference = command(
        "build",
        "-q",
        "--build-arg",
        f"BASE_IMAGE={base}",
        "-f",
        str(ROOT / "drill/plugins/reference/Containerfile"),
        str(ROOT),
    ).splitlines()[-1]
    hostile = command(
        "build",
        "-q",
        "--build-arg",
        f"BASE_IMAGE={reference}",
        "-f",
        str(ROOT / "drill/tests/integration/fixtures/PluginWorker.Containerfile"),
        str(ROOT),
    ).splitlines()[-1]
    yield tuple("sha256:" + image.removeprefix("sha256:") for image in (reference, hostile))
    command("rmi", hostile, reference)


def setup(image, **limit_changes):
    manifest = PluginManifest(
        "fixture",
        "1",
        image,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0",
        access_requests=("broker.target",),
    )
    acceptance = AcceptanceRecord(
        "fixture",
        "plugin",
        review_digest(manifest),
        "test-reviewer",
        "accepted",
        "2026-09-20T00:00:00Z",
        "Controlled test",
        ("broker.target",),
    )
    return manifest, [acceptance], WorkerLimits(**limit_changes)


def scenario(mode="normal", **changes):
    return replace(
        scenario_from_attack(BuiltinReplaySource().dataset()[0]), technique=mode, **changes
    )


async def echo(injection, context):
    assert context.remaining() > 0
    return {"response_text": "fixture response", "scenario": context.scenario_id}


def assert_removed(worker):
    result = subprocess.run(
        ["podman", "--remote=false", "container", "exists", worker.name], check=False
    )
    assert result.returncode == 1


def test_reference_strategy_runs_without_core_changes_and_resets(images):
    async def run():
        manifest, records, limits = setup(images[0], max_calls=4)
        worker = PodmanWorker(manifest, records, bindings={"target": echo}, limits=limits)
        async with worker:
            await worker.prepare()
            await worker.reset(scenario(id="first"))
            result = await worker.execute()
            assert result.claims["attempts"] == 2 and len(result.calls) == 2
            await worker.reset(scenario(id="second"))
            result = await worker.execute()
            assert all(call.scenario_id == "second" for call in result.calls)
            await worker.finish()
        assert len(worker.calls) == 4
        assert_removed(worker)

    asyncio.run(run())


def test_real_denied_file_network_credentials_and_allowed_broker(images, tmp_path, monkeypatch):
    sentinel = tmp_path / "host-private.txt"
    sentinel.write_text("host-only-canary")
    monkeypatch.setenv("BLASTCONTAIN_TEST_SECRET", "must-not-reach-plugin")

    async def run():
        async def handle(reader, writer):
            await reader.read(100)
            writer.write(b"fixture-service")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]

        async def bound_service(injection, context):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"controlled request")
            await writer.drain()
            response = await reader.read(100)
            writer.close()
            await writer.wait_closed()
            return {"response_text": response.decode()}

        manifest, records, limits = setup(images[1])
        worker = PodmanWorker(manifest, records, bindings={"target": bound_service}, limits=limits)
        try:
            async with worker:
                await worker.prepare()
                await worker.reset(
                    scenario("probe", entry_prompt=str(sentinel), attack_objective=str(port))
                )
                evidence = (await worker.execute()).claims
                assert evidence == {
                    "host_file_visible": False,
                    "uid": 65532,
                    "network": False,
                    "writable_root": False,
                    "secret": None,
                    "caps": "0000000000000000",
                    "no_new_privs": "1",
                    "seccomp": "2",
                    "memory_limit": "268435456",
                    "pids_limit": "64",
                    "engine_socket": False,
                    "broker_result": {"response_text": "fixture-service"},
                }
        finally:
            server.close()
            await server.wait_closed()
        assert_removed(worker)

    asyncio.run(run())


@pytest.mark.parametrize(
    "mode,error,calls",
    [
        ("budget", BudgetExceeded, 2),
        ("replay", ProtocolError, 1),
        ("unauthorized", WorkerError, 0),
        ("oversize", ProtocolError, 0),
        ("malformed", ProtocolError, 0),
        ("wrong-id", ProtocolError, 0),
        ("stderr-flood", WorkerError, 0),
        ("stdout-flood", ProtocolError, 0),
        ("stderr-sustained", WorkerError, 0),
        ("exit", WorkerError, 0),
        ("hang", BudgetExceeded, 0),
    ],
)
def test_faults_fail_closed_and_cleanup(images, mode, error, calls):
    async def run():
        manifest, records, limits = setup(
            images[1], max_calls=2, wall_seconds=5 if mode == "hang" else 30
        )
        worker = PodmanWorker(manifest, records, bindings={"target": echo}, limits=limits)
        started = time.monotonic()
        with pytest.raises(error):
            async with worker:
                await worker.prepare()
                await worker.reset(scenario(mode))
                await worker.execute()
        assert len(worker.calls) == calls
        assert time.monotonic() - started < limits.wall_seconds + 16
        assert_removed(worker)

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["normal", "stdout-broker-flood", "stderr-broker-flood"])
@pytest.mark.parametrize("stop", ["cancel", "deadline"])
def test_cancellation_stops_plugin_and_cancels_pending_broker_call(images, mode, stop):
    async def run():
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def blocking(injection, context):
            started.set()
            try:
                await asyncio.sleep(60)
            finally:
                cancelled.set()

        manifest, records, limits = setup(images[1], wall_seconds=5 if stop == "deadline" else 30)
        worker = PodmanWorker(manifest, records, bindings={"target": blocking}, limits=limits)
        async with worker:
            await worker.prepare()
            await worker.reset(scenario(mode))
            task = asyncio.create_task(worker.execute())
            await asyncio.wait_for(started.wait(), 5)
            if "flood" in mode:
                await asyncio.sleep(0.5)
            with pytest.raises(WorkerError, match="Concurrent"):
                await worker.execute()
            if stop == "deadline":
                with pytest.raises(BudgetExceeded):
                    await asyncio.wait_for(task, 20)
            else:
                await asyncio.wait_for(worker.cancel(), 16)
                assert task.cancelled()
            assert cancelled.is_set()
            assert worker.process.returncode is not None
        assert len(worker.calls) == 1 and worker.calls[0].error == "CancelledError"
        assert_removed(worker)

    asyncio.run(run())


def test_reset_does_not_reset_call_budget(images):
    async def run():
        manifest, records, limits = setup(images[1], max_calls=1)
        worker = PodmanWorker(manifest, records, bindings={"target": echo}, limits=limits)
        with pytest.raises(BudgetExceeded):
            async with worker:
                await worker.prepare()
                await worker.reset(scenario(id="first"))
                await worker.execute()
                await worker.reset(scenario(id="second"))
                await worker.execute()
        assert len(worker.calls) == 1
        assert_removed(worker)

    asyncio.run(run())


def test_deadline_stops_idle_worker_without_another_request(images):
    async def run():
        manifest, records, limits = setup(images[1], wall_seconds=5)
        worker = PodmanWorker(manifest, records, bindings={"target": echo}, limits=limits)
        async with worker:
            await worker.prepare()
            await asyncio.sleep(5.1)
            await worker.close()
            assert worker._expired
        assert_removed(worker)

    asyncio.run(run())


def test_missing_acceptance_never_creates_a_container(images):
    async def run():
        manifest, _, limits = setup(images[0])
        worker = PodmanWorker(manifest, [], bindings={"target": echo}, limits=limits)
        with pytest.raises(ContractError):
            await worker.start()
        assert worker.process is None
        assert_removed(worker)

    asyncio.run(run())


def test_engine_deadline_removes_worker_without_python_watchdog(images):
    async def run():
        manifest, records, limits = setup(images[1], wall_seconds=5)
        worker = PodmanWorker(manifest, records, bindings={"target": echo}, limits=limits)
        async with worker:
            await worker.prepare()
            # Model loss of the controller's timer. Conmon still owns the hard
            # execution timeout and auto-removal outside this Python process.
            worker._watchdog.cancel()
            await asyncio.gather(worker._watchdog, return_exceptions=True)
            await asyncio.sleep(6)
            assert_removed(worker)
        assert_removed(worker)

    asyncio.run(run())


def suite_lock(image, *, technique="normal", **changes):
    """Accepted reference worker, controlled content seed and explicitly bound target."""
    from blastcontain_drill.contracts import ScenarioSpec, SecurityExpectation, SourceRef
    from blastcontain_drill.suites.catalog import RuntimeProbe, SourceSnapshot, builtin_catalog
    from blastcontain_drill.suites.lock import create_lock
    from blastcontain_drill.suites.planner import plan_suite
    from blastcontain_drill.suites.schema import ModelSettings, Selection, SuiteSpec, TargetSpec
    from blastcontain_drill.suites.service import ExecutionInputs

    manifest, records, _ = setup(image)
    seed = ScenarioSpec(
        "worker-suite",
        "jailbreak",
        technique,
        SourceRef("worker-suite", "1"),
        "Controlled test",
        SecurityExpectation("content"),
        attack_objective="violate the controlled policy",
    )
    source = SourceSnapshot("worker-suite", "1", image, (seed,))
    catalog = builtin_catalog(external_sources=(source,), plugins=(manifest,))
    records.append(
        AcceptanceRecord(
            source.id,
            "content",
            source.content_digest,
            "tester",
            "accepted",
            "2026-09-21T00:00:00Z",
            "Controlled content",
        )
    )
    probes = (RuntimeProbe(manifest.id, image, True, "2026-09-21T00:00:00Z"),)
    spec = replace(
        SuiteSpec(
            "worker-suite",
            TargetSpec("agent", "builtin.target.llm"),
            "builtin.environment.fixture",
            ("builtin.evaluator.heuristic",),
            (Selection("test", source.id, ("*",), strategy=manifest.id),),
            models=(ModelSettings("target", "http://127.0.0.1:1234/v1", "fixture"),),
        ),
        **changes,
    )
    plan = plan_suite(spec, catalog, records=records, probes=probes)
    assert plan.ready
    records.append(
        AcceptanceRecord(
            spec.id,
            "suite",
            plan.content_digest,
            "tester",
            "accepted",
            "2026-09-21T00:00:00Z",
            "Controlled suite",
        )
    )
    return (
        create_lock(plan, catalog, records=records, probes=probes),
        ExecutionInputs(catalog, tuple(records), probes),
    )


@pytest.mark.parametrize("total", [3, 4])
def test_reference_strategy_in_suite_shares_concurrent_budget_and_preserves_evidence(
    images, monkeypatch, total
):
    from blastcontain_drill.evidence import reduce_evidence
    from blastcontain_drill.suites import adaptive
    from blastcontain_drill.suites.broker import ModelReply
    from blastcontain_drill.suites.schema import Limits
    from blastcontain_drill.suites.service import run_suite

    workers, calls = [], []

    class RecordedWorker(PodmanWorker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            workers.append(self)

    monkeypatch.setattr(adaptive, "PodmanWorker", RecordedWorker)
    lock, inputs = suite_lock(
        images[0],
        seeds=(1, 2),
        concurrency=2,
        global_limits=replace(Limits(), model_calls=total),
        case_limits=replace(Limits(), model_calls=2),
    )

    async def transport(*args):
        calls.append(True)
        return ModelReply("DONE: I cannot help with that request.")

    result = asyncio.run(run_suite(lock, current_inputs=lambda: inputs, transport=transport))
    assert result.usage.model_calls == len(calls) == total, result
    assert sum(c.usage.model_calls for c in result.cases) == total
    assert result.passed is (total == 4)
    attempts = [a for c in result.cases for a in c.attempts]
    assert len({a.environment_identity for a in attempts}) == len(attempts)
    for attempt in attempts:
        assert (
            reduce_evidence(
                attempt.scenario, attempt.evidence, attempt.receipt, policy=attempt.reduction_policy
            ).result
            == attempt.result
        )
    if total == 4:
        assert all(len(c.attempts) == 2 and c.plugin_claim_digest for c in result.cases)
        assert result.usage.strategy_iterations == 4
    else:
        assert any(c.disposition == "incomplete" for c in result.cases)
    assert len(workers) == 2
    for worker in workers:
        assert_removed(worker)


def test_plugin_claim_alone_cannot_pass_suite(images):
    from blastcontain_drill.suites.service import run_suite

    lock, inputs = suite_lock(images[1], technique="claims-only")
    result = asyncio.run(run_suite(lock, current_inputs=lambda: inputs))
    case = result.cases[0]
    assert not result.passed and case.plugin_claim_digest
    assert case.disposition == "error" and case.result.security == "unknown"
    assert result.usage.model_calls == 0 and not case.attempts
    assert "strategy_produced_no_target_evidence" in case.diagnostics


@pytest.mark.parametrize("persist", [False, True])
def test_suite_cancellation_cleans_actual_worker_and_active_target(
    images, monkeypatch, tmp_path, persist
):
    from blastcontain_drill.suites import adaptive
    from blastcontain_drill.suites.durable import execute_run, verify_run
    from blastcontain_drill.suites.run_store import request_cancel
    from blastcontain_drill.suites.service import run_suite

    workers = []

    class RecordedWorker(PodmanWorker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            workers.append(self)

    monkeypatch.setattr(adaptive, "PodmanWorker", RecordedWorker)
    lock, inputs = suite_lock(images[0])

    async def exercise():
        started, cancel, stopped = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def transport(*args):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        directories = []
        operation = (
            execute_run(
                lock,
                tmp_path / "runs",
                current_inputs=lambda: inputs,
                transport=transport,
                on_created=directories.append,
                raw_retention_seconds=120,
            )
            if persist
            else run_suite(lock, current_inputs=lambda: inputs, transport=transport, cancel=cancel)
        )
        task = asyncio.create_task(operation)
        await asyncio.wait_for(started.wait(), 30)
        if persist:
            assert request_cancel(directories[0])
        else:
            cancel.set()
        result = await asyncio.wait_for(task, 20)
        if persist:
            result = result.run
            verified = verify_run(directories[0], allow_advisory=True)
            assert verified.replayed and not verified.security_passed
            assert verified.run.cases[0].disposition == "cancelled"
        assert stopped.is_set() and result.cases[0].disposition == "cancelled", result
        assert result.usage.model_calls == 1 and not result.passed

    asyncio.run(exercise())
    assert len(workers) == 1
    assert_removed(workers[0])
