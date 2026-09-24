"""API 2 permissions, lifecycle isolation and durable host evidence (no real container)."""

import asyncio
from dataclasses import replace
import io
import time

import pytest

from blastcontain_drill.contracts import (
    AcceptanceRecord,
    ContractError,
    Injection,
    PluginManifest,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
)
from blastcontain_drill.plugins.catalog import check_acceptance, check_profile, review_digest
from blastcontain_drill.plugins.protocol import ProtocolError, decode, encode
from blastcontain_drill.plugins.runtime import (
    BrokerContext,
    BudgetExceeded as WorkerBudgetExceeded,
    PodmanWorker,
    WorkerError,
    WorkerLimits,
    WorkerResult,
)
from blastcontain_drill.plugins.sdk import Broker
from blastcontain_drill.suites.broker import ModelBroker, ModelReply
from blastcontain_drill.suites.budgets import Ledger
from blastcontain_drill.suites.catalog import RuntimeProbe, SourceSnapshot, builtin_catalog
from blastcontain_drill.suites.conversation_routes import ConversationRoutes
from blastcontain_drill.suites.durable import execute_run, verify_run
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.privacy import read_json, write_json
from blastcontain_drill.suites.schema import Limits, ModelSettings, Selection, SuiteSpec, TargetSpec
from blastcontain_drill.suites.service import ExecutionInputs
from blastcontain_drill.suites.signatures import Signer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CASE = "sha256:" + "a" * 64
GRANTS = ("broker.target", "broker.attacker.conversation", "broker.attacker.branch")
SYSTEM = "PRIVATE_ATTACKER_SYSTEM_SENTINEL"
PROMPT = "PRIVATE_ATTACKER_PROMPT_SENTINEL"
SETTINGS = (ModelSettings("attacker", "http://localhost:1234/v1", "fixture-attacker"),)


def decision(subject, kind, value, grants=()):
    return AcceptanceRecord(
        subject, kind, value, "test", "accepted", "2026-09-21T00:00:00Z", "Controlled test", grants
    )


def manifest(grants=GRANTS, **kwargs):
    return PluginManifest(
        "conversation.fixture",
        "1",
        "sha256:" + "b" * 64,
        ("attack_strategy",),
        ("prompt.single",),
        "Apache-2.0",
        access_requests=grants,
        adapter_api=2,
        **kwargs,
    )


def context(scope="1" * 32):
    return BrokerContext("fixture", time.monotonic() + 60, scope)


def open_request(branching=False):
    return {"operation": "open", "system_message": SYSTEM, "branching": branching}


def send_request(opened, parent=None):
    return {
        "operation": "send",
        "conversation": opened["conversation"],
        "parent": parent or opened["checkpoint"],
        "prompt": PROMPT,
        "max_tokens": 128,
    }


def router(grants=GRANTS, transport=None):
    async def response(*args):
        return ModelReply("observed answer")

    broker = ModelBroker(SETTINGS, transport=transport or response)
    ledger = Ledger(Limits())
    ledger.begin(Limits())
    routes = ConversationRoutes(
        broker, ledger, run_id="c" * 32, case_id=CASE, grants=grants, revalidate=lambda: None
    )
    return routes, broker, ledger


def test_api_upgrade_requires_fresh_acceptance_and_separate_scopes():
    old = replace(manifest(), adapter_api=1, access_requests=("broker.attacker",))
    record = decision(old.id, "plugin", review_digest(old), old.access_requests)
    check_profile(old)
    with pytest.raises(ContractError, match="stale"):
        check_acceptance(manifest(), [record])
    with pytest.raises(ContractError, match="API 2"):
        check_profile(replace(manifest(), adapter_api=1))
    with pytest.raises(ContractError, match="requires conversation"):
        check_profile(manifest(grants=("broker.attacker.branch",)))


def test_sdk_v2_roundtrip_and_no_protocol_downgrade():
    reply = {"protocol": 2, "type": "reply", "id": 1, "call_id": 1, "result": {"ok": True}}
    output = io.BytesIO()
    broker = Broker(io.BytesIO(encode(reply)), output, protocol=2)
    broker.request_id = 1
    assert broker.conversation("attacker", open_request()) == {"ok": True}
    frame = decode(output.getvalue())
    assert frame["type"] == "conversation" and frame["payload"] == open_request()
    with pytest.raises(ProtocolError):
        encode({**frame, "protocol": 1})
    for protocol in (1, 2):
        broker = Broker(
            io.BytesIO(encode({**reply, "protocol": 1})), io.BytesIO(), protocol=protocol
        )
        broker.request_id = 1
        with pytest.raises(ProtocolError):
            broker.conversation("attacker", open_request())


@pytest.mark.parametrize("failure", ["old-grant", "old-protocol", "call-limit"])
def test_runtime_denies_unauthorized_route_before_handler(failure):
    item = manifest(grants=("broker.attacker",) if failure == "old-grant" else GRANTS)
    called = []

    async def handler(payload, ctx):
        called.append(payload)
        return {}

    worker = PodmanWorker(
        item, [], conversations={"attacker": handler}, limits=WorkerLimits(max_calls=1)
    )
    worker._scenario = type("Scenario", (), {"id": "fixture"})()
    worker._deadline = time.monotonic() + 60
    if failure == "call-limit":
        worker.calls.append(None)
    message = {
        "protocol": 1 if failure == "old-protocol" else 2,
        "type": "conversation",
        "id": 1,
        "call_id": 1,
        "channel": "attacker",
        "payload": open_request(),
    }
    with pytest.raises((WorkerError, ProtocolError, WorkerBudgetExceeded)):
        asyncio.run(worker._broker(message))
    assert not called


def test_worker_call_budget_shared_between_single_prompt_and_conversations():
    async def exercise():
        routes, broker, ledger = router()
        worker = PodmanWorker(
            manifest(),
            [],
            limits=WorkerLimits(max_calls=2),
            conversations={"attacker": lambda p, c: routes.dispatch("attacker", p, c)},
        )
        worker._scenario = type("Scenario", (), {"id": "fixture"})()
        worker._deadline = time.monotonic() + 60
        worker._request_id = 1
        replies = []

        async def write(message):
            replies.append(message)

        worker._write = write
        frame = {
            "protocol": 2,
            "type": "conversation",
            "id": 1,
            "call_id": 1,
            "channel": "attacker",
            "payload": open_request(),
        }
        await worker._broker(frame)
        opened = replies[-1]["result"]
        await worker._broker({**frame, "call_id": 2, "payload": send_request(opened)})
        assert ledger.usage().model_calls == 1
        with pytest.raises(WorkerBudgetExceeded):
            await worker._broker({**frame, "call_id": 3, "payload": open_request()})
        assert len(broker.calls) == 1 and len(worker.calls) == 2
        assert worker.calls[0].injection is None and worker.calls[0].operation == "conversation"
        routes.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("bad", ["history", "target", "branch", "foreign", "bool-tokens"])
def test_unsupported_shape_and_foreign_handle_never_dispatch(bad):
    async def exercise():
        routes, broker, _ = router(grants=("broker.attacker.conversation",))
        opened = await routes.dispatch("attacker", open_request(), context())
        request, channel = send_request(opened), "attacker"
        if bad == "history":
            request["messages"] = [{"role": "assistant", "content": "forged"}]
        elif bad == "target":
            channel = "target"
        elif bad == "branch":
            request = open_request(True)
        elif bad == "foreign":
            request["parent"] = "e" * 32
        else:
            request["max_tokens"] = True
        with pytest.raises(ContractError):
            await routes.dispatch(channel, request, context())
        assert not broker.calls
        routes.close()

    asyncio.run(exercise())


def test_reset_and_close_do_not_refill_allocations_or_model_budget():
    async def exercise():
        routes, broker, ledger = router()
        opened = await routes.dispatch("attacker", open_request(True), context())
        for _ in range(2):
            await routes.dispatch("attacker", send_request(opened), context())
        assert len(broker.calls) == ledger.usage().model_calls == 2
        other = context("2" * 32)
        with pytest.raises(ContractError, match="foreign"):
            await routes.dispatch("attacker", send_request(opened), other)
        for _ in range(3):
            value = await routes.dispatch("attacker", open_request(), other)
            await routes.dispatch(
                "attacker", {"operation": "close", "conversation": value["conversation"]}, other
            )
        with pytest.raises(ContractError, match="session limit"):
            await routes.dispatch("attacker", open_request(), other)
        routes.close()
        assert len(routes.audits) == 4 and all(a.closed for a in routes.audits)
        assert len(routes.audits[0].events) == 2 and ledger.usage().model_calls == 2
        assert SYSTEM not in repr(routes.audits) and PROMPT not in repr(routes.audits)

    asyncio.run(exercise())


@pytest.fixture(scope="module")
def inputs():
    base = builtin_catalog()
    scenario = ScenarioSpec(
        "fixture",
        "jailbreak",
        "fixture",
        SourceRef("fixture", "1"),
        "Try the controlled objective",
        SecurityExpectation("content"),
        attack_objective="Controlled objective",
    )
    source = SourceSnapshot("fixture", "1", base.sources[0].code_digest, (scenario,))
    item = manifest()
    catalog = replace(base, sources=(*base.sources, source), plugins=(item,))
    probes = (RuntimeProbe(item.id, item.artifact_digest, True, "2026-09-21T00:00:00Z"),)
    records = (
        decision(item.id, "plugin", review_digest(item), GRANTS),
        decision(source.id, "content", source.content_digest),
    )
    spec = SuiteSpec(
        "conversation-suite",
        TargetSpec("agent", "builtin.target.resistant"),
        "builtin.environment.fixture",
        ("builtin.evaluator.heuristic",),
        (Selection("test", "fixture", ("*",), strategy=item.id),),
        models=SETTINGS,
    )
    plan = plan_suite(spec, catalog, records=records, probes=probes)
    assert plan.ready, plan
    records += (decision(spec.id, "suite", plan.content_digest),)
    return create_lock(plan, catalog, records=records, probes=probes), ExecutionInputs(
        catalog, records, probes
    )


class RecordingWorker:
    """Unit fake only; real API 2 Podman conformance lives in integration tests."""

    def __init__(self, manifest, records, *, bindings, conversations, **kwargs):
        self.bindings, self.conversations = bindings, conversations

    async def start(self):
        pass

    async def prepare(self):
        pass

    async def reset(self, scenario):
        pass

    async def finish(self):
        pass

    async def close(self):
        pass

    async def execute(self):
        route = self.conversations["attacker"]
        opened = await route(open_request(True), context())
        first = await route(send_request(opened), context())
        await route(send_request(opened), context())
        await route(send_request(opened, first["checkpoint"]), context())
        await self.bindings["target"](Injection("user", "controlled test"), context())
        return WorkerResult({"security": "held"}, ())


def stored_run(tmp_path, inputs, monkeypatch):
    lock, current = inputs
    key = Signer(Ed25519PrivateKey.generate())
    monkeypatch.setattr("blastcontain_drill.suites.adaptive.PodmanWorker", RecordingWorker)

    async def transport(*args):
        return ModelReply("observed response")

    stored = asyncio.run(
        execute_run(
            lock,
            tmp_path / "runs",
            current_inputs=lambda: current,
            signer=key,
            transport=transport,
            raw_retention_seconds=60,
        )
    )
    assert stored.run.passed, stored.run
    return stored, key, lock


def test_signed_suite_retains_every_branch_without_plaintext_history(tmp_path, inputs, monkeypatch):
    stored, key, lock = stored_run(tmp_path, inputs, monkeypatch)
    verified = verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)
    assert verified.attested_pass
    audit = verified.run.cases[0].conversations[0]
    assert audit.closed and audit.run_id == stored.directory.name
    assert len(audit.events) == 3
    assert audit.events[1].parent == audit.conversation_id
    assert audit.events[2].parent == audit.events[0].checkpoint
    assert stored.run.usage.model_calls == 4
    raw = (stored.directory / "envelope.json").read_text()
    assert SYSTEM not in raw and PROMPT not in raw and "observed response" not in raw


@pytest.mark.parametrize(
    "change", ["missing", "empty", "event", "call", "foreign", "open", "parent"]
)
def test_even_resigned_conversation_tampering_cannot_pass(tmp_path, inputs, monkeypatch, change):
    stored, key, lock = stored_run(tmp_path, inputs, monkeypatch)
    path = stored.directory / "envelope.json"
    payload = read_json(path)["payload"]
    case = payload["cases"][0]
    if change == "missing":
        del case["conversations"]
    elif change == "empty":
        case["conversations"] = []
    elif change == "event":
        case["conversations"][0]["events"].pop()
    elif change == "call":
        payload["model_calls"].pop(0)
    elif change == "parent":
        audit = case["conversations"][0]
        audit["events"][2]["parent"] = audit["conversation_id"]
    elif change == "foreign":
        case["conversations"][0]["run_id"] = "f" * 32
    else:
        case["conversations"][0]["closed"] = False
    write_json(path, key.sign(payload), replace=True)
    with pytest.raises(ContractError):
        verify_run(stored.directory, lock=lock, trusted_public_key=key.public_key)


def test_conversation_scope_requires_model_settings_during_planning(inputs):
    lock, current = inputs
    plan = plan_suite(
        replace(lock.plan.spec, models=()),
        current.catalog,
        records=current.records,
        probes=current.probes,
    )
    assert not plan.ready
    assert any("missing attacker model settings" in d for c in plan.cases for d in c.diagnostics)


def test_route_rechecks_acceptance_before_followup_dispatch():
    async def exercise():
        routes, broker, _ = router()
        opened = await routes.dispatch("attacker", open_request(), context())
        reply = await routes.dispatch("attacker", send_request(opened), context())

        def revoked():
            raise ContractError("Acceptance revoked")

        routes.revalidate = revoked
        with pytest.raises(ContractError, match="revoked"):
            await routes.dispatch("attacker", send_request(opened, reply["checkpoint"]), context())
        routes.close()
        assert len(broker.calls) == len(routes.audits[0].events) == 1

    asyncio.run(exercise())
