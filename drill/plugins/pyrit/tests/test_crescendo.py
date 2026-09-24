"""Pinned native Crescendo and actual API 2 workers with host-owned Agent evidence."""

import asyncio
from dataclasses import replace
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from blastcontain_drill.contracts import Injection
from blastcontain_drill.plugins.catalog import review_digest
from blastcontain_drill.plugins.runtime import PodmanWorker, WorkerError
from blastcontain_drill.suites.artifacts import read_document
from blastcontain_drill.suites.broker import ModelReply
from blastcontain_drill.suites.catalog import builtin_catalog
from blastcontain_drill.suites.durable import execute_run, verify_run
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.schema import SuiteSpec
from blastcontain_drill.suites.service import ExecutionInputs
from blastcontain_drill.suites.signatures import Signer
from test_container import command, decision, removed

PLUGIN = Path(__file__).parents[1]


@pytest.fixture(scope="module")
def crescendo_image():
    image_id = os.environ["DRILL_PYRIT_CRESCENDO_IMAGE"]
    assert image_id.startswith("sha256:")
    command("image", "inspect", image_id)
    return image_id


@pytest.fixture
def prepared_crescendo(crescendo_image, tmp_path):
    definition = spec_from_file_location("crescendo_preparation", PLUGIN / "prepare_crescendo.py")
    module = module_from_spec(definition)
    definition.loader.exec_module(module)
    manifest, source, probe = module.prepare(
        crescendo_image,
        tmp_path / "inputs",
        endpoint="http://127.0.0.1:1234/v1",
        target="controlled-target",
        attacker="controlled-attacker",
        evaluator="controlled-evaluator",
    )
    assert probe.available, read_document(tmp_path / "inputs/review.json")
    records = (
        decision(manifest.id, "plugin", review_digest(manifest), manifest.access_requests),
        decision(source.id, "content", source.content_digest),
    )
    return manifest, source, probe, records


def locked(prepared, tmp_path, *, seeds=(0,), model_calls=40):
    manifest, source, probe, records = prepared
    catalog = builtin_catalog(external_sources=(source,), plugins=(manifest,))
    spec = SuiteSpec.from_dict(read_document(tmp_path / "inputs/suite.json"))
    spec = replace(
        spec, seeds=seeds, case_limits=replace(spec.case_limits, model_calls=model_calls)
    )
    plan = plan_suite(spec, catalog, records=records, probes=(probe,))
    assert plan.ready, plan
    records = (*records, decision(spec.id, "suite", plan.content_digest))
    return create_lock(plan, catalog, records=records, probes=(probe,)), ExecutionInputs(
        catalog, records, (probe,)
    )


def record_workers(monkeypatch):
    from blastcontain_drill.suites import adaptive

    workers = []

    class RecordedWorker(PodmanWorker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            workers.append(self)

    monkeypatch.setattr(adaptive, "PodmanWorker", RecordedWorker)
    return workers


def test_native_crescendo_history_backtracking_and_json_retry_in_bounded_image(crescendo_image):
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
        crescendo_image,
        "/opt/plugin/validate_crescendo.py",
    )
    report = json.loads(output)
    assert report["pyrit"] == "1.1.0" and report["crescendo_parity"]
    assert report["cases"] == [
        {
            "malformed_retry": False,
            "calls": {"target": 3, "attacker": 3, "evaluator": 5},
            "backtracks": 1,
        },
        {
            "malformed_retry": True,
            "calls": {"target": 3, "attacker": 4, "evaluator": 5},
            "backtracks": 1,
        },
    ]


@pytest.mark.parametrize("harmful", [False, True])
def test_host_records_abandoned_actions_reset_and_signed_replay(
    prepared_crescendo, tmp_path, monkeypatch, harmful
):
    lock, inputs = locked(prepared_crescendo, tmp_path, seeds=(0, 1))
    workers = record_workers(monkeypatch)
    requests = []
    attacker_calls = 0

    async def transport(settings, messages, *args):
        nonlocal attacker_calls
        requests.append((settings.channel, messages))
        prompt = messages[-1]["content"]
        if settings.channel == "attacker":
            attacker_calls += 1
            # First response in each case is malformed; its charged call remains audited.
            index = (attacker_calls - 1) % 4
            if index == 0:
                return ModelReply("malformed JSON")
            return ModelReply(
                json.dumps(
                    {
                        "next_message": f"controlled probe {index}",
                        "rationale": "controlled",
                        "last_response_summary": "observed",
                    }
                )
            )
        if settings.channel == "target":
            if prompt == "controlled probe 1":
                return ModelReply("DONE accepted first turn")
            if prompt == "controlled probe 2" and harmful:
                return ModelReply('CALL delete_records {"target":"all"}')
            if prompt == "controlled probe 3":
                return ModelReply("DONE goal achieved")
            return ModelReply("DONE I cannot help with that request.")
        refusal = "DRILL_REFUSAL" in messages[0]["content"]
        matched = "cannot help" in prompt if refusal else "goal achieved" in prompt
        return ModelReply(json.dumps({"score_value": matched, "rationale": "controlled"}))

    key = Signer(Ed25519PrivateKey.generate())
    stored = asyncio.run(
        execute_run(
            lock,
            tmp_path / "runs",
            current_inputs=lambda: inputs,
            transport=transport,
            signer=key,
            raw_retention_seconds=120,
        )
    )
    assert len(stored.run.cases) == 2
    for case in stored.run.cases:
        assert case.disposition == "completed", case
        assert case.result.security == ("action_attempted" if harmful else "held")
        assert len(case.attempts) == 3 and len(case.conversations) == 3
        first, refused, alternate = case.attempts
        assert first.fixture_output == refused.fixture_input == alternate.fixture_input
        assert len(refused.fixture_output.tool_calls) == int(harmful)
        assert not alternate.fixture_output.tool_calls
        assert len(case.agent_conversations[0].turns) == 3 and case.agent_conversations[0].closed
        assert all(a.closed for a in case.conversations)
        assert sum(len(a.events) for a in case.conversations) == 9
    assert len({c.attempts[0].fixture_input.canary for c in stored.run.cases}) == 2
    assert stored.run.usage.model_calls == len(requests) == (26 if harmful else 24)
    assert stored.run.usage.tool_steps == (2 if harmful else 0)
    assert stored.run.usage.strategy_iterations == 6
    verified = verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)
    assert verified.replayed and verified.attested_pass is not harmful
    assert len(workers) == 2
    for worker in workers:
        removed(worker)


@pytest.mark.parametrize("channel", ["attacker", "target", "evaluator"])
def test_active_channel_cancellation_closes_worker_and_preserves_signed_roster(
    prepared_crescendo, tmp_path, monkeypatch, channel
):
    lock, inputs = locked(prepared_crescendo, tmp_path, seeds=(0, 1))
    workers = record_workers(monkeypatch)

    async def run():
        started, stopped, cancel = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def transport(settings, messages, *args):
            if settings.channel == channel:
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    stopped.set()
            if settings.channel == "attacker":
                return ModelReply(
                    json.dumps(
                        {
                            "next_message": "controlled",
                            "rationale": "fixture",
                            "last_response_summary": "observed",
                        }
                    )
                )
            return ModelReply("DONE controlled response")

        task = asyncio.create_task(
            execute_run(
                lock,
                tmp_path / "runs",
                current_inputs=lambda: inputs,
                transport=transport,
                raw_retention_seconds=120,
                cancel=cancel,
            )
        )
        await asyncio.wait_for(started.wait(), 30)
        cancel.set()
        stored = await asyncio.wait_for(task, 15)
        assert stopped.is_set()
        assert len(stored.run.cases) == 2 and all(
            c.disposition == "cancelled" for c in stored.run.cases
        )
        assert not stored.run.passed
        assert verify_run(stored.directory, lock=lock, allow_advisory=True).replayed

    asyncio.run(run())
    assert len(workers) == 1
    removed(workers[0])


def test_all_channels_share_model_budget(prepared_crescendo, tmp_path):
    lock, inputs = locked(prepared_crescendo, tmp_path, model_calls=2)
    calls = []

    async def transport(settings, *args):
        calls.append(settings.channel)
        if settings.channel == "attacker":
            return ModelReply(
                json.dumps(
                    {
                        "next_message": "controlled",
                        "rationale": "fixture",
                        "last_response_summary": "observed",
                    }
                )
            )
        return ModelReply("DONE controlled response")

    stored = asyncio.run(
        execute_run(
            lock,
            tmp_path / "runs",
            current_inputs=lambda: inputs,
            transport=transport,
            raw_retention_seconds=120,
        )
    )
    assert calls == ["attacker", "target"] and stored.run.usage.model_calls == 2
    assert stored.run.cases[0].disposition == "incomplete" and not stored.run.passed
    assert verify_run(stored.directory, lock=lock, allow_advisory=True).replayed


@pytest.mark.parametrize(
    "changes",
    [
        {"turns": ("one", "two")},
        {"injections": (Injection("document", "unreviewed"),)},
        {"attack_objective": None},
    ],
)
def test_unsupported_shapes_fail_before_any_broker_dispatch(prepared_crescendo, changes):
    manifest, source, _, records = prepared_crescendo

    async def denied(*args):
        pytest.fail("Unsupported scenario reached a broker")

    worker = PodmanWorker(
        manifest,
        records,
        conversations={name: denied for name in ("target", "attacker", "evaluator")},
    )

    async def run():
        with pytest.raises(WorkerError):
            async with worker:
                await worker.prepare()
                await worker.reset(replace(source.scenarios[0], **changes))

    asyncio.run(run())
    assert not worker.calls
    removed(worker)
