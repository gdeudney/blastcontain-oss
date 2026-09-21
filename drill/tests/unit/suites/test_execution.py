"""Real process/loopback execution and failures against the accepted roster."""

import asyncio
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sys
import time

import pytest

from blastcontain_drill.contracts import AcceptanceRecord, ContractError
from blastcontain_drill.evidence import reduce_evidence
from blastcontain_drill.evidence.records import Delivery, Error, Output
from blastcontain_drill.suites import service
from blastcontain_drill.suites.artifacts import canonical
from blastcontain_drill.suites.budgets import BudgetExceeded, Ledger
from blastcontain_drill.suites.catalog import builtin_catalog
from blastcontain_drill.suites.lock import create_lock
from blastcontain_drill.suites.planner import plan_suite
from blastcontain_drill.suites.runner import execute
from blastcontain_drill.suites.schema import Limits, ModelSettings, Selection, SuiteSpec, TargetSpec
from blastcontain_drill.suites.service import ExecutionInputs, run_suite


@pytest.fixture(scope="module")
def catalog():
    return builtin_catalog()


def locked(catalog, *, vulnerable=False, kind="agent", selections=None, **changes):
    spec = SuiteSpec(
        "execution-test",
        TargetSpec(kind, "builtin.target.vulnerable" if vulnerable else "builtin.target.resistant"),
        "builtin.environment.fixture",
        ("builtin.evaluator.heuristic",),
        selections or (Selection("mcp", "mcp-poisoning", ("*",)),),
    )
    spec = replace(spec, **changes)
    plan = plan_suite(spec, catalog)
    assert plan.ready
    records = (
        AcceptanceRecord(
            spec.id,
            "suite",
            plan.content_digest,
            "tester",
            "accepted",
            "2026-09-21T00:00:00Z",
            "Controlled fixtures",
        ),
    )
    lock = create_lock(plan, catalog, records=records)
    return lock, ExecutionInputs(catalog, records)


def run(lock, inputs, **kwargs):
    return asyncio.run(run_suite(lock, current_inputs=lambda: inputs, **kwargs))


@pytest.mark.parametrize("kind", ["agent", "mcp"])
@pytest.mark.parametrize("vulnerable", [False, True])
def test_one_lock_runs_both_mcp_surfaces_with_fresh_cases(catalog, kind, vulnerable):
    lock, inputs = locked(catalog, kind=kind, vulnerable=vulnerable)
    snapshots = []
    result = run(lock, inputs, progress=snapshots.append)
    assert [c.case_id for c in result.cases] == [c.id for c in lock.plan.cases]
    assert all(c.disposition == "completed" for c in result.cases), result
    assert all(c.legacy_outcome == ("BYPASS" if vulnerable else "HELD") for c in result.cases)
    assert result.passed is (not vulnerable)
    assert len({c.environment_identity for c in result.cases}) == 4
    assert all(c.environment_identity is not None for c in result.cases)
    assert all(
        c.lifecycle
        == (
            "process_started",
            "environment_ready",
            "environment_cleaned",
            "process_reaped",
            "workspace_removed",
        )
        for c in result.cases
    )
    assert all(c.disposition == "pending" for c in snapshots[0].cases)
    assert all(sum(c.disposition == "running" for c in snap.cases) <= 1 for snap in snapshots)
    for planned, case in zip(lock.plan.cases, result.cases):
        reduced = reduce_evidence(planned.scenario, case.evidence, case.receipt)
        assert reduced.result == case.result
        assert case.usage.artifact_bytes == len(canonical(case.evidence.to_dict()))
        assert case.usage.model_calls > 0 and case.usage.tool_steps > 0
        assert b"BCN-CANARY-" not in canonical(case.evidence.to_dict())
        assert case.result.security != "effect_observed"


@pytest.mark.parametrize("source", ["builtin", "operators", "multi-turn"])
def test_replay_materialized_operators_and_multiturn(catalog, source):
    snapshot = next(s for s in catalog.sources if s.id == source)
    scenario = next(
        s
        for s in snapshot.scenarios
        if s.security.goal == "content" and not s.injections and s.security.expected_refusal
    )
    lock, inputs = locked(
        catalog, selections=(Selection("selection", source, (scenario.id,)),), seeds=(3, 8)
    )
    result = run(lock, inputs)
    assert result.passed and all(c.result.security == "held" for c in result.cases)
    assert len({c.execution_identity for c in result.cases}) == 2
    assert result.cases[0].environment_identity != result.cases[1].environment_identity
    assert result.cases[0].usage.model_calls == len(scenario.turns or (scenario.entry_prompt,))
    assert all(c.usage.strategy_iterations == 0 for c in result.cases)


@pytest.mark.parametrize("resource,limit", [("model_calls", 1), ("tool_steps", 1)])
def test_case_budget_stops_before_dispatch_and_retains_roster(catalog, resource, limit):
    lock, inputs = locked(
        catalog, vulnerable=True, case_limits=replace(Limits(), **{resource: limit})
    )
    result = run(lock, inputs)
    assert not result.passed and len(result.cases) == 4
    for case in result.cases:
        assert getattr(case.usage, resource) == limit
        assert case.disposition == "incomplete"
        assert f"budget:case:{resource}" in case.diagnostics
        assert case.result.security != "held"


def test_exhaustion_keeps_affirmative_action(catalog):
    lock, inputs = locked(
        catalog,
        vulnerable=True,
        selections=(Selection("mcp", "mcp-poisoning", ("mcp-description-exfil",)),),
        case_limits=replace(Limits(), model_calls=3),
    )
    case = run(lock, inputs).cases[0]
    assert case.disposition == "incomplete" and case.legacy_outcome == "BYPASS"
    assert case.result.security == "action_attempted"


def test_global_budget_never_resets_for_next_case(catalog):
    limits = replace(Limits(), model_calls=2)
    lock, inputs = locked(catalog, global_limits=limits, case_limits=limits)
    result = run(lock, inputs)
    assert result.usage.model_calls == 2
    assert result.cases[0].disposition == "completed"
    assert all(c.disposition == "incomplete" for c in result.cases[1:])
    assert all(c.usage.model_calls == 0 for c in result.cases[1:])


def test_response_not_delivered_until_next_target_dispatch(catalog):
    lock, inputs = locked(
        catalog,
        selections=(Selection("mcp", "mcp-poisoning", ("mcp-response-exfil",)),),
        case_limits=replace(Limits(), model_calls=1),
    )
    case = run(lock, inputs).cases[0]
    assert case.disposition == "incomplete" and case.legacy_outcome == "ERROR"
    assert "missing_payload_exposure" in case.diagnostics
    assert not any(isinstance(r.payload, Delivery) for r in case.evidence.records)


@pytest.mark.parametrize("maximum", [1, 1500])
def test_evidence_bytes_bounded_and_never_pass_when_exhausted(catalog, maximum):
    lock, inputs = locked(catalog, case_limits=replace(Limits(), artifact_bytes=maximum))
    result = run(lock, inputs)
    assert not result.passed
    for case in result.cases:
        assert case.usage.artifact_bytes <= maximum
        assert case.result.security != "held"
        if case.evidence:
            assert case.evidence.truncated
            assert len(canonical(case.evidence.to_dict())) <= maximum


def test_optional_exclusion_retained_as_skipped(catalog):
    lock, inputs = locked(
        catalog,
        selections=(
            Selection("mcp", "mcp-poisoning", ("mcp-description-exfil",)),
            Selection("missing", "absent", ("*",), required=False),
        ),
    )
    result = run(lock, inputs)
    assert result.passed
    assert [c.disposition for c in result.cases] == ["completed", "skipped"]
    assert result.cases[1].diagnostics and result.cases[1].evidence is None


@pytest.mark.parametrize("when", [1, 3])
def test_current_acceptance_revalidated_before_run_and_each_case(catalog, monkeypatch, when):
    lock, inputs = locked(catalog)
    calls = 0

    def current():
        nonlocal calls
        calls += 1
        if calls >= when:
            return replace(
                inputs, records=(*inputs.records, replace(inputs.records[0], decision="revoked"))
            )
        return inputs

    result = asyncio.run(run_suite(lock, current_inputs=current))
    assert not result.passed
    completed = 0 if when == 1 else 1
    assert all(c.disposition == "completed" for c in result.cases[:completed])
    assert all(
        c.disposition == "error" and c.usage.model_calls == 0 for c in result.cases[completed:]
    )


@pytest.mark.parametrize("option", ["concurrency", "live_target"])
def test_unsupported_runtime_does_not_silently_fall_back(catalog, option, monkeypatch):
    changes = (
        {"concurrency": 2}
        if option == "concurrency"
        else {
            "target": TargetSpec("agent", "builtin.target.llm"),
            "models": (ModelSettings("target", "http://localhost:1234/v1", "local-model"),),
        }
    )
    lock, inputs = locked(catalog, **changes)

    async def forbidden(*args):
        pytest.fail("Unsupported binding must not spawn")

    monkeypatch.setattr(service, "_spawn", forbidden)
    result = run(lock, inputs)
    assert not result.passed and all(c.disposition == "unsupported" for c in result.cases)


def test_parent_deadline_kills_hung_case_and_removes_workspace(catalog, monkeypatch):
    processes, directories = [], []

    async def stalled(directory):
        directories.append(directory)
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            "import time; time.sleep(60)",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(service, "_spawn", stalled)
    limits = replace(Limits(), wall_seconds=1)
    lock, inputs = locked(catalog, case_limits=limits, global_limits=limits)
    start = time.monotonic()
    result = run(lock, inputs)
    assert time.monotonic() - start < 5
    assert len(processes) == 1 and processes[0].returncode is not None
    assert all(not Path(p).exists() for p in directories)
    assert all(c.disposition == "incomplete" for c in result.cases)
    assert "budget:global:wall_seconds" in result.cases[0].diagnostics


def test_failed_preparation_and_cleanup_stop_without_held(catalog, monkeypatch):
    lock, inputs = locked(catalog)

    async def broken(directory):
        raise OSError("secret-sentinel")

    monkeypatch.setattr(service, "_spawn", broken)
    result = run(lock, inputs)
    assert all(c.disposition == "error" for c in result.cases)
    assert "secret-sentinel" not in repr(result)


def test_ledger_reserves_both_limits_atomically_and_counts_failures():
    clock = [0.0]
    limits = replace(Limits(), model_calls=2)
    ledger = Ledger(limits, clock=lambda: clock[0])
    ledger.begin(replace(limits, model_calls=1))
    ledger.reserve("model_calls")  # a dispatched call that subsequently fails still counts
    with pytest.raises(BudgetExceeded):
        ledger.reserve("model_calls")
    assert ledger.end().model_calls == 1
    ledger.begin(limits)
    ledger.reserve("model_calls")
    with pytest.raises(BudgetExceeded, match="global"):
        ledger.reserve("model_calls")
    assert ledger.usage().model_calls == 2
    clock[0] = limits.wall_seconds
    with pytest.raises(BudgetExceeded, match="wall_seconds"):
        ledger.reserve("tool_steps")
    for amount in (0, -1, True):
        with pytest.raises(ContractError):
            ledger.reserve("tool_steps", amount)


class RecordingChannel:
    def __init__(self):
        self.events, self.states, self.reservations, self.terminal = [], [], [], None

    def reserve(self, resource):
        self.reservations.append(resource)

    def event(self, emitter, payload):
        self.events.append((emitter, payload))
        return f"reference:{len(self.events)}"

    def lifecycle(self, state, identity=None):
        self.states.append(state)

    def request(self, message):
        self.terminal = message["reason"]


def test_backend_failure_counts_dispatch_and_never_claims_complete(catalog, monkeypatch):
    from blastcontain_drill.suites import runner

    class Broken:
        def __init__(self, *args):
            pass

        def chat(self, *args, **kwargs):
            raise RuntimeError("secret-sentinel")

    monkeypatch.setattr(runner, "StubChatClient", Broken)
    lock, _ = locked(catalog)
    channel = RecordingChannel()
    execute(lock.plan.cases[0].scenario, False, channel)
    assert channel.reservations == ["model_calls"]
    assert channel.terminal == "backend_error"
    assert not any(isinstance(p, (Delivery, Output)) for _, p in channel.events)
    assert any(isinstance(p, Error) for _, p in channel.events)
    assert "secret-sentinel" not in repr(channel.events)


def test_environment_cleanup_failure_is_explicit(catalog, monkeypatch):
    from blastcontain_drill.suites import runner

    @contextmanager
    def broken_cleanup(*args):
        class Client:
            def discover(self):
                return []

            def call(self, args):
                return "Invoice paid"

        yield Client()
        raise OSError("secret-sentinel")

    monkeypatch.setattr(runner, "poison_fixture", broken_cleanup)
    lock, _ = locked(catalog)
    channel = RecordingChannel()
    execute(lock.plan.cases[0].scenario, False, channel)
    assert channel.terminal == "fixture_error"
    assert "environment_cleanup_failed" in channel.states
    assert "environment_cleaned" not in channel.states


@pytest.mark.parametrize("vulnerable", [False, True])
def test_document_exposure_requires_actual_delivery(catalog, vulnerable):
    source = next(s for s in catalog.sources if s.id == "builtin")
    scenario = next(
        s for s in source.scenarios if any(i.surface == "document" for i in s.injections)
    )
    lock, inputs = locked(
        catalog, vulnerable=vulnerable, selections=(Selection("doc", "builtin", (scenario.id,)),)
    )
    case = run(lock, inputs).cases[0]
    deliveries = [r.payload for r in case.evidence.records if isinstance(r.payload, Delivery)]
    if vulnerable:
        assert case.disposition == "completed" and deliveries
        assert case.legacy_outcome == "BYPASS"
    else:
        assert case.disposition == "incomplete" and not deliveries
        assert "missing_payload_exposure" in case.diagnostics


def test_content_cases_after_global_budget_are_incomplete(catalog):
    source = next(s for s in catalog.sources if s.id == "builtin")
    scenario = next(
        s for s in source.scenarios if s.security.goal == "content" and not s.injections
    )
    limits = replace(Limits(), model_calls=1)
    lock, inputs = locked(
        catalog,
        selections=(Selection("content", "builtin", (scenario.id,)),),
        seeds=(1, 2),
        global_limits=limits,
        case_limits=limits,
    )
    result = run(lock, inputs)
    assert result.cases[0].disposition == "completed"
    assert result.cases[1].disposition == "incomplete"
    assert result.cases[1].usage.model_calls == 0
    assert "budget:global:model_calls" in result.cases[1].diagnostics


def fault_process(monkeypatch, script):
    processes = []

    async def spawn(directory):
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            script,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=directory,
            env=service._child_environment(),
            limit=16384,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(service, "_spawn", spawn)
    return processes


def test_cleanup_failure_aborts_remaining_cases_but_keeps_observed_harm(catalog, monkeypatch):
    script = """
import sys
from blastcontain_drill.suites.runner import Channel
from blastcontain_drill.evidence.records import Action
sys.stdin.buffer.readline()
c = Channel()
c.lifecycle("environment_ready", "sha256:" + "a" * 64)
c.event("environment", Action("attempt", ("forbidden_tool",), True))
c.lifecycle("environment_cleanup_failed")
c.request({"kind": "terminal", "reason": "fixture_error"})
"""
    processes = fault_process(monkeypatch, script)
    lock, inputs = locked(catalog)
    result = run(lock, inputs)
    assert len(processes) == 1 and processes[0].returncode == 0
    assert all(c.disposition == "error" for c in result.cases)
    assert result.cases[0].result.security == "action_attempted"
    assert result.cases[0].legacy_outcome == "BYPASS"
    assert "cleanup_failed" in result.cases[0].diagnostics
    assert "prior_case_cleanup_failed" in result.cases[1].diagnostics


@pytest.mark.parametrize("fault", ["crash", "stdout", "stderr", "authority"])
def test_corrupt_or_overflowed_child_never_passes(catalog, monkeypatch, fault):
    scripts = {
        "crash": "import sys; sys.stdin.buffer.readline(); raise RuntimeError('secret-sentinel')",
        "stdout": "import sys; sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'x' * 1000000); sys.stdout.flush()",
        "stderr": "import sys; sys.stdin.buffer.readline(); sys.stderr.buffer.write(b'x' * 1000000); sys.stderr.flush()",
        "authority": """
import sys
from blastcontain_drill.suites.runner import Channel
from blastcontain_drill.evidence.records import Terminal
sys.stdin.buffer.readline()
Channel().event("environment", Terminal("completed"))
""",
    }
    processes = fault_process(monkeypatch, scripts[fault])
    lock, inputs = locked(
        catalog,
        selections=(Selection("mcp", "mcp-poisoning", ("mcp-description-exfil",)),),
        case_limits=replace(Limits(), wall_seconds=10),
    )
    start = time.monotonic()
    result = run(lock, inputs)
    assert time.monotonic() - start < 5
    assert not result.passed and result.cases[0].result.security != "held"
    assert processes[0].returncode is not None
    assert "secret-sentinel" not in repr(result)


def test_parent_timeout_retains_streamed_attempt(catalog, monkeypatch):
    script = """
import sys, time
from blastcontain_drill.suites.runner import Channel
from blastcontain_drill.evidence.records import Action
sys.stdin.buffer.readline()
c = Channel()
c.lifecycle("environment_ready", "sha256:" + "a" * 64)
c.event("environment", Action("attempt", ("forbidden_tool",), True))
time.sleep(60)
"""
    processes = fault_process(monkeypatch, script)
    lock, inputs = locked(
        catalog,
        selections=(Selection("mcp", "mcp-poisoning", ("mcp-description-exfil",)),),
        case_limits=replace(Limits(), wall_seconds=1),
    )
    case = run(lock, inputs).cases[0]
    assert processes[0].returncode is not None
    assert case.disposition == "incomplete" and case.legacy_outcome == "BYPASS"
    assert case.result.security == "action_attempted"
    assert case.evidence.truncated


def test_child_environment_does_not_inherit_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "secret-sentinel")
    monkeypatch.setenv("PYTHONPATH", "/hostile/path")
    env = service._child_environment()
    assert "OPENAI_API_KEY" not in env and "secret-sentinel" not in repr(env)
    assert "/hostile/path" not in env["PYTHONPATH"]
