"""Budgeted development execution of accepted locks using fixed trusted fixtures.

Model routing and credentials stay in the host. External strategies use isolated
Podman workers. Trusted case processes provide independent stopping, not OS
containment. Durable runs and authenticated cancellation belong to phase 3E.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import os
from pathlib import Path
import sys
import tempfile
from typing import Callable

import blastcontain_core

from ..contracts import AcceptanceRecord, ContractError, ScenarioResult, ScenarioSpec
from ..evidence import EvidenceBundle, EvidenceCollector, EvidenceReceipt, Producer, reduce_evidence
from ..evidence.records import (
    Action,
    Coverage,
    Delivery,
    Error,
    Evaluation,
    EvidenceRecord,
    Output,
    Terminal,
)
from ..evidence.reducer import ReductionPolicy
from ..plugins.catalog import parse_json
from ..plugins.runtime import _read_capped, _reap
from .artifacts import canonical, digest
from .budgets import BudgetExceeded, Ledger, Usage
from .broker import ModelBroker, ModelCall, ModelError
from .catalog import Catalog, RuntimeProbe, builtin_catalog
from .lock import SuiteLock, validate_lock
from .planner import PlannedCase
from .runner import MAX_FRAME, MAX_REQUEST


@dataclass(frozen=True)
class ExecutionInputs:
    """Fresh operator-owned inputs; never implicitly reuse acceptance snapshots."""

    catalog: Catalog
    records: tuple[AcceptanceRecord, ...]
    probes: tuple[RuntimeProbe, ...] = ()


@dataclass(frozen=True)
class CaseRun:
    case_id: str
    required: bool
    disposition: str
    diagnostics: tuple[str, ...] = ()
    result: ScenarioResult | None = None
    legacy_outcome: str | None = None
    evidence: EvidenceBundle | None = None
    receipt: EvidenceReceipt | None = None
    usage: Usage = Usage()
    lifecycle: tuple[str, ...] = ()
    environment_identity: str | None = None
    execution_identity: str | None = None
    plugin_claim_digest: str | None = None
    attempts: tuple[CaseRun, ...] = ()
    scenario: ScenarioSpec | None = None
    reduction_policy: ReductionPolicy = ReductionPolicy()

    @property
    def passed(self):
        return (
            self.disposition == "completed"
            and self.legacy_outcome == "HELD"
            and self.result is not None
            and self.result.utility != "failed"
        )


@dataclass(frozen=True)
class SuiteRun:
    lock_digest: str
    cases: tuple[CaseRun, ...]
    usage: Usage
    model_calls: tuple[ModelCall, ...] = ()

    @property
    def passed(self):
        relevant = tuple(c for c in self.cases if c.required)
        if not relevant:
            relevant = tuple(c for c in self.cases if c.disposition != "skipped")
        return (
            bool(relevant)
            and all(c.passed for c in relevant)
            and not any("cleanup_failed" in c.diagnostics for c in self.cases)
        )


def execution_identity(case: PlannedCase):
    """Pin materialized operator bytes; never regenerate an accepted transform at run time."""
    return digest(
        {
            "case_id": case.id,
            "scenario": case.scenario.to_dict() if case.scenario else None,
            "seed": case.seed,
            "mode": "materialized_operator"
            if case.scenario and case.scenario.layer == "operators"
            else "replay",
        }
    )


def _failure(case, disposition, diagnostic):
    return CaseRun(
        case.id,
        case.required,
        disposition,
        (diagnostic,),
        ScenarioResult(case.scenario_id, disposition),
        execution_identity=execution_identity(case),
    )


def _support(lock, case, actual):
    spec = lock.plan.spec
    expected = {b.id: b for b in actual.bindings}
    bindings = (spec.target.binding, spec.environment, *spec.evaluators)
    allowed = {
        "builtin.target.resistant",
        "builtin.target.vulnerable",
        "builtin.target.llm",
        "builtin.environment.fixture",
        "builtin.evaluator.heuristic",
        "builtin.evaluator.llm",
    }
    if spec.concurrency > 8:
        return "maximum_eight_concurrent_cases"
    if any(name not in allowed for name in bindings):
        return "runtime_binding_unsupported"
    if spec.environment != "builtin.environment.fixture":
        return "runtime_binding_unsupported"
    if spec.target.binding not in (
        "builtin.target.resistant",
        "builtin.target.vulnerable",
        "builtin.target.llm",
    ):
        return "runtime_binding_unsupported"
    # Caller-supplied metadata cannot impersonate a built-in runtime's code/capabilities.
    for name in bindings:
        identity = next(
            (i for i in lock.plan.identities if i.id == name and i.kind == "builtin_binding"), None
        )
        if identity is None or identity.content_digest != digest(expected[name].to_dict()):
            return "runtime_identity_mismatch"
    scenario = case.scenario
    if scenario is None:
        return "missing_scenario"
    if case.strategy and (scenario.turns or scenario.injections or spec.target.kind != "agent"):
        return "adaptive_single_prompt_only"
    if scenario.layer == "generative" and not case.strategy:
        return "adaptive_strategy_required"
    if case.strategy == "builtin.strategy.pair":
        identity = next((i for i in lock.plan.identities if i.id == case.strategy), None)
        if identity is None or identity.content_digest != digest(expected[case.strategy].to_dict()):
            return "runtime_identity_mismatch"
    if scenario.fixture_refs or scenario.task_checks:
        return "fixture_adapter_unsupported"
    surfaces = {i.surface for i in scenario.injections}
    if (
        surfaces - {"document", "mcp_description", "mcp_response"}
        or {"mcp_description", "mcp_response"} <= surfaces
    ):
        return "injection_combination_unsupported"
    return None


def _child_environment():
    # Fixed trusted code roots; no inherited keys, model credentials or user PYTHONPATH.
    env = {
        k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP") if k in os.environ
    }
    env.update(
        {
            "PYTHONPATH": os.pathsep.join(
                (
                    str(Path(__file__).parents[2]),
                    str(Path(blastcontain_core.__file__).parent.parent),
                )
            ),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


async def _spawn(directory):
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "blastcontain_drill.suites.runner",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=MAX_FRAME,
        cwd=directory,
        env=_child_environment(),
    )


async def _execute_case(lock, case, ledger, *, broker=None, feedback=None):
    scenario = case.scenario
    if scenario is None:
        raise ContractError("Execution requires a materialized scenario")
    collector = EvidenceCollector(case.id, scenario)
    reduction_policy = ReductionPolicy(
        lock.plan.spec.evaluators if scenario.security.goal == "content" else ()
    )
    handles = {
        "environment": collector.register(
            Producer(
                "fixture",
                "environment",
                "simulation",
                ("model_output", "tool_actions", "payload_delivery"),
            )
        ),
        "runtime": collector.register(Producer("suite-runtime", "runtime", "host")),
    }
    for evaluator in lock.plan.spec.evaluators:
        handles[evaluator] = collector.register(
            Producer(
                evaluator,
                "evaluator",
                "host",
                axes=("harm", "refusal", "freeform")
                if evaluator == "builtin.evaluator.llm"
                else ("harm", "refusal"),
            )
        )
    lifecycle: list[str] = []
    diagnostics: list[str] = []
    identity = None
    process: asyncio.subprocess.Process | None = None
    stderr: asyncio.Task[bytes] | None = None
    conversation: asyncio.Task[None] | None = None
    directory: tempfile.TemporaryDirectory[str] | None = None
    terminal = None
    exhausted = False
    artifact_exhausted = False
    cleanup_ok = True
    retained_size = len(canonical(collector.snapshot()[0].to_dict()))
    initial_retained = False

    def record(emitter, payload):
        nonlocal retained_size
        sequence = len(collector.snapshot()[0].records)
        names = {
            "environment": "fixture",
            "runtime": "suite-runtime",
        }
        names.update({name: name for name in lock.plan.spec.evaluators})
        size = len(canonical(EvidenceRecord(sequence, names[emitter], payload).to_dict())) + 1
        ledger.reserve("artifact_bytes", size)
        result = collector.record(handles[emitter], payload)
        retained_size += size
        return result

    async def acknowledge(ok=True, reference=None):
        if process is None or process.stdin is None:
            raise ContractError("Fixture input pipe unavailable")
        process.stdin.write(canonical({"ok": ok, "reference": reference}) + b"\n")
        await process.stdin.drain()

    async def exchange():
        nonlocal terminal, exhausted, identity, cleanup_ok
        if process is None or process.stdin is None or process.stdout is None or stderr is None:
            raise ContractError("Fixture process pipes unavailable")
        request = (
            canonical(
                {
                    "scenario": scenario.to_dict(),
                    "vulnerable": lock.plan.spec.target.binding == "builtin.target.vulnerable",
                    "live": lock.plan.spec.target.binding == "builtin.target.llm",
                    "evaluators": list(lock.plan.spec.evaluators),
                    "feedback": feedback is not None,
                }
            )
            + b"\n"
        )
        if len(request) > MAX_REQUEST:
            raise ContractError("Fixture request too large")
        process.stdin.write(request)
        await process.stdin.drain()
        while True:
            raw = await process.stdout.readline()
            if not raw or len(raw) > MAX_FRAME:
                raise ContractError("Fixture evidence ended or exceeded bounds")
            if stderr.done():
                stderr.result()
            data = parse_json(raw)
            if type(data) is not dict:
                raise ContractError("Invalid fixture frame")
            kind = data.get("kind")
            if kind == "model" and set(data) == {"kind", "channel", "messages", "max_tokens"}:
                permitted = (
                    data["channel"] == "target"
                    and lock.plan.spec.target.binding == "builtin.target.llm"
                ) or (
                    data["channel"] == "evaluator"
                    and "builtin.evaluator.llm" in lock.plan.spec.evaluators
                )
                if not permitted or broker is None:
                    raise ContractError("Model channel not bound for this case")
                try:
                    answer = await broker.chat(
                        case.id,
                        ledger,
                        data["channel"],
                        data["messages"],
                        max_tokens=data["max_tokens"],
                    )
                except BudgetExceeded as exc:
                    exhausted = True
                    diagnostics.append(str(exc))
                    await acknowledge(False)
                except ModelError:
                    record("runtime", Error("backend_error"))
                    await acknowledge(False)
                else:
                    await acknowledge(reference=answer)
            elif kind == "feedback" and set(data) == {"kind", "response"}:
                if (
                    feedback is None
                    or type(data["response"]) is not str
                    or len(data["response"]) > 4096
                ):
                    raise ContractError("Unexpected fixture feedback")
                feedback["response"] = data["response"]
                await acknowledge()
            elif kind == "reserve" and set(data) == {"kind", "resource"}:
                if data["resource"] not in ("model_calls", "tool_steps"):
                    raise ContractError("Unsupported fixture reservation")
                try:
                    ledger.reserve(data["resource"])
                except BudgetExceeded as exc:
                    diagnostics.append(str(exc))
                    exhausted = True
                    await acknowledge(False)
                else:
                    await acknowledge()
            elif kind == "event" and set(data) == {"kind", "emitter", "payload"}:
                emitter = data["emitter"]
                allowed = {
                    "environment": (Action, Coverage, Delivery, Output),
                    "runtime": (Error,),
                }
                allowed.update({name: (Evaluation,) for name in lock.plan.spec.evaluators})
                payload = EvidenceRecord.from_dict(
                    {
                        "schema_version": 1,
                        "sequence": 0,
                        "emitter": "fixture",
                        "payload": data["payload"],
                    }
                ).payload
                if emitter not in allowed or not isinstance(payload, allowed[emitter]):
                    raise ContractError("Fixture cannot supply this evidence authority")
                await acknowledge(reference=record(emitter, payload))
            elif kind == "lifecycle" and set(data) == {"kind", "state", "identity"}:
                state = data["state"]
                if state == "environment_ready" and not lifecycle[1:]:
                    from ..contracts.plugins import artifact_digest

                    artifact_digest(data["identity"])
                    identity = data["identity"]
                elif (
                    state not in ("environment_cleaned", "environment_cleanup_failed")
                    or state in lifecycle
                    or data["identity"] is not None
                ):
                    raise ContractError("Invalid fixture lifecycle")
                if state == "environment_cleanup_failed":
                    cleanup_ok = False
                lifecycle.append(state)
                await acknowledge()
            elif kind == "terminal" and set(data) == {"kind", "reason"}:
                terminal = Terminal(data["reason"])
                if not ({"environment_cleaned", "environment_cleanup_failed"} & set(lifecycle)) or (
                    terminal.reason == "completed" and identity is None
                ):
                    raise ContractError("Fixture did not establish preparation/cleanup")
                await acknowledge()
                if await process.stdout.readline():
                    raise ContractError("Fixture sent data after completion")
                await process.wait()
                await stderr
                if process.returncode != 0:
                    raise ContractError("Fixture process failed after evidence")
                return
            else:
                raise ContractError("Unknown fixture frame")

    try:
        ledger.reserve("artifact_bytes", retained_size)
        initial_retained = True
        directory = tempfile.TemporaryDirectory(prefix="drill-case-")
        # The independent parent deadline bounds launch, all I/O and the case body.
        async with asyncio.timeout(ledger.remaining()):
            process = await _spawn(directory.name)
            lifecycle.append("process_started")
            stderr = asyncio.create_task(_read_capped(process.stderr, MAX_FRAME))
            conversation = asyncio.create_task(exchange())
            # Observe either task failing immediately, including stderr overflow
            # while the child is silent on stdout or blocked on a full error pipe.
            await asyncio.gather(conversation, stderr)
            ledger.check_time()
    except asyncio.CancelledError:
        terminal = Terminal("cancelled")
        diagnostics.append("cancelled")
    except (BudgetExceeded, TimeoutError) as exc:
        exhausted = True
        if isinstance(exc, BudgetExceeded):
            diagnostics.append(str(exc))
            artifact_exhausted = exc.resource == "artifact_bytes"
        else:
            try:
                ledger.check_time()
            except BudgetExceeded as limit:
                diagnostics.append(str(limit))
    except Exception:
        diagnostics.append("fixture_execution_failed")
        terminal = Terminal("fixture_error")
    finally:
        if conversation is not None:
            conversation.cancel()
            await asyncio.gather(conversation, return_exceptions=True)
        if stderr is not None:
            stderr.cancel()
            await asyncio.gather(stderr, return_exceptions=True)
        if process is not None:
            try:
                await _reap(process)
                lifecycle.append("process_reaped")
            except Exception:
                cleanup_ok = False
        if directory is not None:
            try:
                directory.cleanup()
                lifecycle.append("workspace_removed")
            except OSError:
                cleanup_ok = False
    if not cleanup_ok:
        diagnostics.append("cleanup_failed")
        terminal = Terminal("fixture_error")
    elif exhausted:
        terminal = Terminal("step_limit")
    elif terminal is None:
        terminal = Terminal("unknown_completion")
    # Finalization still consumes evidence bytes. Exhaustion retains a partial prefix;
    # the outer case record supplies its terminal disposition without fabricating events.
    try:
        if artifact_exhausted:
            collector.truncate()
        else:
            record("runtime", terminal)
    except BudgetExceeded as exc:
        diagnostics.append(str(exc))
        collector.truncate()
    except ContractError:
        collector.truncate()
    bundle, receipt = collector.snapshot() if initial_retained else (None, None)
    reduced_diagnostics: tuple[str, ...]
    if bundle is None or receipt is None:
        result, outcome, reduced_diagnostics = (
            ScenarioResult(scenario.id, "incomplete"),
            "ERROR",
            (),
        )
    else:
        reduced = reduce_evidence(scenario, bundle, receipt, policy=reduction_policy)
        result, outcome, reduced_diagnostics = (
            reduced.result,
            reduced.legacy_outcome,
            reduced.diagnostics,
        )
    return CaseRun(
        case.id,
        case.required,
        result.execution,
        tuple(sorted(set(diagnostics) | set(reduced_diagnostics))),
        result,
        outcome,
        evidence=bundle,
        receipt=receipt,
        lifecycle=tuple(lifecycle),
        environment_identity=identity,
        execution_identity=execution_identity(case),
        scenario=scenario if feedback is not None else None,
        reduction_policy=reduction_policy,
    )


async def run_suite(
    lock: SuiteLock,
    *,
    current_inputs: Callable[[], ExecutionInputs],
    progress=None,
    credentials=None,
    transport=None,
    cancel: asyncio.Event | None = None,
) -> SuiteRun:
    """Execute accepted cases with bounded concurrency and shared pre-dispatch budgets.

    Inputs, credential resolver and optional async transport are trusted host bindings.
    The cancel event is in-memory only; durable cancellation remains phase 3E.
    """
    from .adaptive import execute_adaptive

    lock.to_dict()
    pool = Ledger(lock.plan.spec.global_limits)
    broker = ModelBroker(lock.plan.spec.models, credentials=credentials, transport=transport)
    cases = [CaseRun(c.id, c.required, "pending") for c in lock.plan.cases]
    cancelled = cancel or asyncio.Event()
    aborted = None

    def snapshot():
        return SuiteRun(lock.lock_digest, tuple(cases), pool.usage(), tuple(broker.calls))

    def publish():
        if progress is not None:
            progress(snapshot())

    def revalidate():
        inputs = current_inputs()
        validate_lock(lock, inputs.catalog, records=inputs.records, probes=inputs.probes)
        return inputs

    broker.authorize = revalidate

    publish()
    try:
        revalidate()
    except Exception:
        aborted = "acceptance_revalidation_failed"
    indices = iter(range(len(cases)))

    async def work():
        nonlocal aborted
        for index in indices:
            case = lock.plan.cases[index]
            if case.disposition == "excluded":
                cases[index] = CaseRun(case.id, case.required, "skipped", case.diagnostics)
            elif aborted:
                cases[index] = _failure(case, "error", aborted)
            elif cancelled.is_set():
                cases[index] = _failure(case, "cancelled", "cancelled")
            else:
                try:
                    inputs = revalidate()
                except Exception:
                    aborted = "acceptance_revalidation_failed"
                    cases[index] = _failure(case, "error", aborted)
                else:
                    unsupported = _support(lock, case, builtin_catalog())
                    if unsupported:
                        cases[index] = _failure(case, "unsupported", unsupported)
                    else:
                        ledger = pool.fork(lock.plan.spec.case_limits)
                        try:
                            ledger.check_time()
                            for resource in ("model_calls", "artifact_bytes"):
                                if ledger.total[resource] >= getattr(ledger.limits, resource):
                                    raise BudgetExceeded("global", resource)
                            cases[index] = replace(cases[index], disposition="running")
                            publish()
                            if case.strategy is not None:
                                cases[index] = await execute_adaptive(
                                    lock, case, ledger, broker, inputs, revalidate
                                )
                            else:
                                cases[index] = await _execute_case(
                                    lock, case, ledger, broker=broker
                                )
                        except asyncio.CancelledError:
                            cases[index] = _failure(case, "cancelled", "cancelled")
                        except BudgetExceeded as exc:
                            cases[index] = _failure(case, "incomplete", str(exc))
                        except Exception:
                            cases[index] = _failure(case, "error", "evidence_reduction_failed")
                        finally:
                            cases[index] = replace(cases[index], usage=ledger.end())
                        if "cleanup_failed" in cases[index].diagnostics:
                            aborted = "prior_case_cleanup_failed"
            publish()

    workers = [asyncio.create_task(work()) for _ in range(min(8, lock.plan.spec.concurrency))]

    async def stop():
        await cancelled.wait()
        for task in workers:
            task.cancel()

    watcher = asyncio.create_task(stop())
    joined = asyncio.gather(*workers, return_exceptions=True)
    try:
        # Event-driven cancellation still returns a complete terminal roster. A
        # cancellation of the caller itself is propagated after child cleanup.
        await asyncio.shield(joined)
    except asyncio.CancelledError:
        # Shield the join so we can set the stop flag before workers suppress
        # cancellation to finalize evidence, then try to dispatch another case.
        watcher.cancel()
        cancelled.set()
        for task in workers:
            if not task.cancelling():
                task.cancel()
        await asyncio.shield(joined)
        raise
    finally:
        watcher.cancel()
        await asyncio.gather(watcher, return_exceptions=True)
        for index, case in enumerate(lock.plan.cases):
            if cases[index].disposition in ("pending", "running"):
                if case.disposition == "excluded":
                    cases[index] = CaseRun(case.id, case.required, "skipped", case.diagnostics)
                elif cancelled.is_set():
                    cases[index] = _failure(case, "cancelled", "cancelled")
                else:
                    cases[index] = _failure(case, "error", "execution_worker_failed")
        publish()
    return snapshot()
