"""Generic environment authority, causality, accounting and conservative replay."""

import asyncio
from dataclasses import replace
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import json

import pytest

from blastcontain_drill.contracts import AcceptanceRecord, ContractError
from blastcontain_drill.evidence import EvidenceCollector, reduce_evidence
from blastcontain_drill.evidence.records import Action, StateObservation
from blastcontain_drill.plugins.catalog import check_profile, review_digest
from blastcontain_drill.plugins.protocol import ProtocolError, encode
from blastcontain_drill.plugins.runtime import BrokerContext
from blastcontain_drill.suites.broker import ModelBroker, ModelReply
from blastcontain_drill.suites.budgets import BudgetExceeded, Ledger
from blastcontain_drill.suites.catalog import RuntimeProbe, builtin_catalog
from blastcontain_drill.suites.environment_runner import EnvironmentExchange
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.schema import Limits

SHA = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
TIME = "2026-09-22T00:00:00Z"


@pytest.fixture
def configured():
    definition = spec_from_file_location(
        "agentdojo_inputs", Path(__file__).parents[3] / "plugins/agentdojo/prepare.py"
    )
    module = module_from_spec(definition)
    definition.loader.exec_module(module)
    manifest, source = module.artifacts(SHA)
    spec = module.suite(manifest, source, "http://127.0.0.1:1234/v1", "controlled")
    catalog = builtin_catalog(external_sources=(source,), plugins=(manifest,))
    records = (
        AcceptanceRecord(
            manifest.id,
            "plugin",
            review_digest(manifest),
            "reviewer",
            "accepted",
            TIME,
            "fixture",
            manifest.access_requests,
        ),
        AcceptanceRecord(
            source.id, "content", source.content_digest, "reviewer", "accepted", TIME, "fixture"
        ),
    )
    probe = RuntimeProbe(manifest.id, SHA, True, TIME)
    return manifest, source, spec, catalog, records, probe


def test_plan_accepts_only_reviewed_selected_environment_and_supported_fixture(configured):
    manifest, source, spec, catalog, records, probe = configured
    assert plan_suite(spec, catalog, records=records, probes=(probe,)).ready
    for changed in (
        replace(spec, evaluators=("builtin.evaluator.heuristic",)),
        replace(spec, target=replace(spec.target, kind="mcp")),
        replace(spec, models=()),
    ):
        assert not plan_suite(changed, catalog, records=records, probes=(probe,)).ready
    assert not plan_suite(spec, catalog, records=records[:-1], probes=(probe,)).ready
    assert not plan_suite(spec, catalog, records=records).ready
    changed_source = replace(
        source, scenarios=(replace(source.scenarios[0], fixture_refs=("other.family",)),)
    )
    changed_catalog = replace(catalog, sources=(*catalog.sources[:-1], changed_source))
    assert not plan_suite(spec, changed_catalog, records=records, probes=(probe,)).ready
    assert not plan_suite(
        replace(spec, selections=(replace(spec.selections[0], strategy=manifest.id),)),
        catalog,
        records=records,
        probes=(probe,),
    ).ready


@pytest.mark.parametrize(
    "changes",
    [
        {"roles": ("attack_strategy",)},
        {"adapter_api": 2},
        {"access_requests": ("broker.environment", "broker.target")},
        {"capabilities": ()},
    ],
)
def test_environment_grant_cannot_be_added_to_attack_strategy(configured, changes):
    with pytest.raises(ContractError):
        check_profile(replace(configured[0], **changes))


def test_environment_frames_require_api3_and_fixed_channel():
    base = {
        "protocol": 3,
        "type": "environment",
        "id": 1,
        "call_id": 1,
        "channel": "environment",
        "payload": {"operation": "start"},
    }
    assert encode(base)
    for changed in ({"protocol": 1}, {"protocol": 2}, {"channel": "target"}):
        with pytest.raises(ProtocolError):
            encode({**base, **changed})


def exchange(configured, commands, limits=Limits()):
    manifest, _, spec, catalog, records, probe = configured
    case = plan_suite(spec, catalog, records=records, probes=(probe,)).cases[0]
    replies = iter(commands)

    async def transport(*args):
        return ModelReply(json.dumps(next(replies)))

    ledger = Ledger(limits).fork(limits)
    collector = EvidenceCollector(case.id, case.scenario)
    broker = ModelBroker(spec.models, transport=transport)
    route = EnvironmentExchange(case, ledger, broker, collector, manifest, lambda: None)
    context = BrokerContext(case.scenario.id, 1e20, "scope-one")

    async def call(operation, **payload):
        return await route.dispatch({"operation": operation, **payload}, context)

    return call, route, collector, broker, ledger


def test_reservation_matches_actual_model_and_replay_cannot_refill_budget(configured):
    command = {"tool": "read_file", "arguments": {"file_path": "bill"}}
    call, route, collector, broker, ledger = exchange(
        configured, [command, {"final": "Done"}], Limits(tool_steps=1)
    )

    async def run():
        await call("start", state_digest=SHA)
        with pytest.raises(ContractError, match="restart"):
            await call("start", state_digest=SHA)
        await call(
            "model",
            messages=[
                {"role": "user", "content": configured[1].scenarios[0].injections[0].payload}
            ],
        )
        with pytest.raises(ContractError, match="differs"):
            await call("reserve_tool", tool="send_money", arguments={}, before_digest=SHA)
        assert ledger.usage().tool_steps == 0
        ticket = (await call("reserve_tool", **command, before_digest=SHA))["ticket"]
        with pytest.raises(ContractError):
            await call("model", messages=[{"role": "user", "content": "repeat"}])
        with pytest.raises(ContractError, match="replayed"):
            await call(
                "observe_tool",
                ticket="foreign",
                after_digest=OTHER,
                output="data",
                attack_success=True,
            )
        await call(
            "observe_tool", ticket=ticket, after_digest=OTHER, output="data", attack_success=True
        )
        with pytest.raises(ContractError, match="replayed"):
            await call(
                "observe_tool",
                ticket=ticket,
                after_digest=OTHER,
                output="data",
                attack_success=False,
            )
        await call("model", messages=[{"role": "user", "content": "finish"}])
        await call("finish", utility_success=True)

    asyncio.run(run())
    collector.finish()
    bundle, receipt = collector.snapshot()
    reduced = reduce_evidence(configured[1].scenarios[0], bundle, receipt)
    assert reduced.result.security == "action_attempted"
    assert reduced.result.utility == "succeeded"
    assert ledger.usage().tool_steps == 1 and len(broker.calls) == 2
    assert any(isinstance(r.payload, StateObservation) for r in bundle.records)
    assert any(isinstance(r.payload, Action) for r in bundle.records)


def test_limits_stop_before_dispatch_and_raw_claims_never_establish_safety(configured):
    call, route, collector, broker, ledger = exchange(
        configured, [{"tool": "read_file", "arguments": {}}], Limits(model_calls=1)
    )

    async def run():
        await call("start", state_digest=SHA)
        await call("model", messages=[{"role": "user", "content": "read"}])
        ticket = (await call("reserve_tool", tool="read_file", arguments={}, before_digest=SHA))[
            "ticket"
        ]
        await call(
            "observe_tool", ticket=ticket, after_digest=SHA, output="text", attack_success=False
        )
        with pytest.raises(BudgetExceeded):
            await call("model", messages=[{"role": "user", "content": "again"}])

    asyncio.run(run())
    collector.claim("untrusted", {"utility_success": True, "security_passed": True})
    collector.finish("step_limit")
    bundle, receipt = collector.snapshot()
    result = reduce_evidence(configured[1].scenarios[0], bundle, receipt)
    assert result.legacy_outcome != "HELD" and result.result.utility != "succeeded"
    assert len(broker.calls) == 1


def test_cross_reset_scope_and_forged_state_chain_rejected(configured):
    call, route, collector, _, _ = exchange(configured, [])
    asyncio.run(call("start", state_digest=SHA))
    with pytest.raises(ContractError, match="scope"):
        asyncio.run(
            route.dispatch(
                {"operation": "finish", "utility_success": True},
                BrokerContext("x", 1e20, "another-scope"),
            )
        )
    collector.record(route.environment, StateObservation(OTHER, OTHER, SHA))
    collector.finish("step_limit")
    bundle, receipt = collector.snapshot()
    with pytest.raises(ContractError, match="chain"):
        reduce_evidence(configured[1].scenarios[0], bundle, receipt)
