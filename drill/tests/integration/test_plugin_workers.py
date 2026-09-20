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
        assert time.monotonic() - started < limits.wall_seconds + 12
        assert_removed(worker)

    asyncio.run(run())


def test_cancellation_stops_plugin_and_cancels_pending_broker_call(images):
    async def run():
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def blocking(injection, context):
            started.set()
            try:
                await asyncio.sleep(60)
            finally:
                cancelled.set()

        manifest, records, limits = setup(images[1])
        worker = PodmanWorker(manifest, records, bindings={"target": blocking}, limits=limits)
        async with worker:
            await worker.prepare()
            await worker.reset(scenario())
            task = asyncio.create_task(worker.execute())
            await asyncio.wait_for(started.wait(), 5)
            with pytest.raises(WorkerError, match="Concurrent"):
                await worker.execute()
            await worker.cancel()
            assert task.cancelled() and cancelled.is_set()
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
