"""Reviewed simulation worker; host budgets, model calls, provenance and stopping.

The selected environment is a trusted simulation observer, not independent proof
of real-world effects. Attack-strategy claims never enter these observer routes.
"""

import asyncio
import hashlib
import uuid

from ..contracts import ContractError
from ..contracts.plugins import artifact_digest
from ..evidence import EvidenceCollector, Producer, reduce_evidence
from ..evidence.records import Action, Coverage, Delivery, StateObservation, TaskCheck
from ..plugins.catalog import parse_json
from ..plugins.runtime import (
    PodmanWorker,
    WorkerLimits,
    WorkerError,
    BudgetExceeded as WorkerBudgetExceeded,
)
from .artifacts import canonical, digest
from .budgets import BudgetExceeded
from .broker import ModelError
from .environment_profile import validate_environment
from .service import CaseRun, execution_identity


class EnvironmentExchange:
    def __init__(self, case, ledger, broker, collector, manifest, revalidate):
        self.case, self.ledger, self.broker = case, ledger, broker
        self.collector, self.revalidate = collector, revalidate
        self.environment = collector.register(
            Producer(
                manifest.id,
                "environment",
                "simulation",
                ("model_output", "tool_actions", "payload_delivery"),
            )
        )
        self.evaluator = collector.register(
            Producer("oracle:" + manifest.id, "evaluator", "simulation", task_checks=("utility",))
        )
        self.state = self.state_ref = self.output_ref = self.pending = self.command = None
        self.started = self.finished = False
        self.scope = None
        self.delivered = set()

    def record(self, handle, payload):
        # Charge before retaining, shared with all model and tool attempts.
        self.ledger.reserve("artifact_bytes", len(canonical(payload.to_dict())) + 256)
        return self.collector.record(handle, payload)

    async def dispatch(self, payload, context):
        self.revalidate()
        self.ledger.check_time()
        if self.scope is None:
            self.scope = context.scope_id
        if self.scope != context.scope_id or self.finished or type(payload) is not dict:
            raise ContractError("Environment scope is closed or changed")
        operation = payload.get("operation")
        fields = {
            "start": {"operation", "state_digest"},
            "model": {"operation", "messages"},
            "reserve_tool": {"operation", "tool", "arguments", "before_digest"},
            "observe_tool": {"operation", "ticket", "after_digest", "output", "attack_success"},
            "finish": {"operation", "utility_success"},
        }
        if (
            type(operation) is not str
            or operation not in fields
            or set(payload) != fields[operation]
        ):
            raise ContractError("Invalid environment operation or fields")
        if operation == "start":
            if self.started:
                raise ContractError("Environment cannot restart or refill its budget")
            artifact_digest(payload["state_digest"])
            self.state = payload["state_digest"]
            self.state_ref = self.record(
                self.environment,
                StateObservation(self.state, self.state, digest(self.case.scenario.fixture_refs)),
            )
            self.started = True
            return {"started": True}
        if not self.started:
            raise ContractError("Environment must start before model or tools")
        if operation == "model":
            if self.pending or self.command is not None:
                raise ContractError("Complete the previous model action before another call")
            messages = payload["messages"]
            text = await self.broker.chat(
                self.case.id,
                self.ledger,
                "target",
                messages,
                max_tokens=self.broker.settings["target"].max_output_tokens,
            )
            self.ledger.reserve("artifact_bytes", 512)
            self.output_ref = self.collector.output(self.environment, text)
            for injection in self.case.scenario.injections:
                if injection.payload in "\n".join(m["content"] for m in messages):
                    sha = "sha256:" + hashlib.sha256(injection.payload.encode()).hexdigest()
                    if sha not in self.delivered:
                        self.record(self.environment, Delivery(injection.surface, sha, True))
                        self.delivered.add(sha)
            command = parse_json(text.encode())
            if type(command) is not dict or not (
                (set(command) == {"final"} and type(command["final"]) is str)
                or (
                    set(command) == {"tool", "arguments"}
                    and type(command["tool"]) is str
                    and command["tool"]
                    and type(command["arguments"]) is dict
                )
            ):
                raise ContractError("Model must return one tool/arguments action or final text")
            self.command = command
            return {"response_text": text}
        if operation == "reserve_tool":
            command = {"tool": payload["tool"], "arguments": payload["arguments"]}
            if self.pending or self.command != command or self.state != payload["before_digest"]:
                raise ContractError("Tool action differs from the observed model or current state")
            self.ledger.reserve("tool_steps")
            self.ledger.reserve("artifact_bytes", 2048)
            self.pending = (uuid.uuid4().hex, digest(command))
            return {"ticket": self.pending[0]}
        if operation == "observe_tool":
            if not self.pending or payload["ticket"] != self.pending[0]:
                raise ContractError("Unknown or replayed tool reservation")
            if (
                type(payload["attack_success"]) is not bool
                or type(payload["output"]) is not str
                or len(payload["output"].encode()) > 32768
            ):
                raise ContractError("Invalid tool observation")
            artifact_digest(payload["after_digest"])
            if self.state is None:
                raise ContractError("Missing initial state observation")
            self.state_ref = self.collector.record(
                self.environment,
                StateObservation(
                    self.state,
                    payload["after_digest"],
                    digest({"action": self.pending[1], "output": digest(payload["output"])}),
                ),
            )
            if payload["attack_success"]:
                self.collector.record(
                    self.environment, Action(self.pending[0], ("state_violation",), None)
                )
            self.state = payload["after_digest"]
            self.pending = self.command = None
            return {"observed": True}
        if (
            self.pending
            or not self.command
            or set(self.command) != {"final"}
            or type(payload["utility_success"]) is not bool
        ):
            raise ContractError(
                "Finish requires a final model response and completed tool observations"
            )
        if self.state_ref is None or self.output_ref is None:
            raise ContractError("Missing state or final model observation")
        self.record(
            self.evaluator,
            TaskCheck("utility", payload["utility_success"], (self.state_ref, self.output_ref)),
        )
        self.record(
            self.environment, Coverage(("model_output", "tool_actions", "payload_delivery"), True)
        )
        self.finished = True
        return {"finished": True}


async def execute_environment(lock, case, ledger, broker, inputs, revalidate):
    manifest = validate_environment(lock.plan.spec, case, inputs.catalog.plugins)
    ledger.reserve("artifact_bytes", 2048)
    collector = EvidenceCollector(case.id, case.scenario)
    exchange = EnvironmentExchange(case, ledger, broker, collector, manifest, revalidate)
    worker = PodmanWorker(
        manifest,
        inputs.records,
        bindings={"environment": exchange.dispatch},
        limits=WorkerLimits(
            wall_seconds=min(300, ledger.remaining()), max_calls=1000, max_messages=4096
        ),
    )
    lifecycle, diagnostics = [], []
    reason = "completed"
    claims = None
    try:
        await worker.start()
        lifecycle.append("container_started")
        await worker.prepare()
        await worker.reset(case.scenario)
        lifecycle.append("environment_ready")
        result = await worker.execute()
        if not exchange.finished:
            raise ContractError("Environment omitted its final observation")
        claims = digest(result.claims)
        ledger.reserve("artifact_bytes", len(canonical(result.claims)) + 512)
        collector.claim(manifest.id, result.claims)
        await worker.finish()
    except asyncio.CancelledError:
        reason = "cancelled"
    except (BudgetExceeded, WorkerBudgetExceeded) as error:
        reason = "step_limit"
        diagnostics.append(str(error))
    except (WorkerError, ModelError, ContractError):
        reason = "backend_error"
        diagnostics.append("environment_execution_failed")
    except Exception:
        # Preserve previously observed harm even if an adapter unexpectedly fails.
        reason = "backend_error"
        diagnostics.append("environment_execution_failed")
    finally:
        try:
            await worker.close()
            lifecycle.append("container_removed")
        except Exception:
            reason = "backend_error"
            diagnostics.append("cleanup_failed")
    try:
        ledger.reserve("artifact_bytes", 512)
        collector.finish(reason)
    except (BudgetExceeded, ContractError):
        collector.truncate()
    evidence, receipt = collector.snapshot()
    reduced = reduce_evidence(case.scenario, evidence, receipt)
    return CaseRun(
        case.id,
        case.required,
        reduced.result.execution,
        tuple(dict.fromkeys((*diagnostics, *reduced.diagnostics))),
        reduced.result,
        reduced.legacy_outcome,
        evidence,
        receipt,
        lifecycle=tuple(lifecycle),
        environment_identity=digest(worker.name),
        execution_identity=execution_identity(case),
        plugin_claim_digest=claims,
    )
