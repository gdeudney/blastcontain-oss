"""Versioned, private, bounded run snapshots and content-addressed evidence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
from pathlib import Path
import re
import secrets
import time
from typing import Literal
import uuid

from ..contracts import ContractError, ScenarioResult
from ..contracts.plugins import artifact_digest
from ..contracts.wire import WireRecord, unique
from ..evidence.reducer import ReductionPolicy
from .artifacts import canonical, digest
from .budgets import Usage
from .catalog import build_digest
from .privacy import (
    MAX_FILE,
    lease,
    mkdir_private,
    private,
    read_json,
    read_private,
    write_json,
    write_private,
)

REDUCER: Literal["drill-evidence-v1/suite-aggregate-v1"] = "drill-evidence-v1/suite-aggregate-v1"


def run_id(value):
    if not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ContractError("Invalid run ID")


@dataclass(frozen=True)
class Blob(WireRecord):
    digest: str
    size: int
    kind: Literal["evidence", "raw_lock", "raw_scenario", "raw_trace"]

    def validate(self):
        artifact_digest(self.digest)
        if not 1 <= self.size <= MAX_FILE:
            raise ContractError("Invalid run artifact size")


@dataclass(frozen=True)
class SavedCall(WireRecord):
    case_id: str
    channel: Literal["target", "attacker", "evaluator"]
    request_digest: str
    response_digest: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    status: Literal["pending", "completed", "error", "cancelled", "timeout"] = "pending"

    def validate(self):
        for value in (self.case_id, self.request_digest, self.response_digest):
            if value is not None:
                artifact_digest(value)
        for count in (self.input_tokens, self.output_tokens):
            if count is not None and not 0 <= count <= 10**12:
                raise ContractError("Invalid reported token count")


@dataclass(frozen=True)
class SavedCase(WireRecord):
    case_id: str
    required: bool
    disposition: Literal[
        "pending",
        "running",
        "completed",
        "incomplete",
        "cancelled",
        "unsupported",
        "skipped",
        "error",
    ]
    result: ScenarioResult | None
    legacy_outcome: Literal["HELD", "BYPASS", "OVER_REFUSAL", "ERROR"] | None
    diagnostics: tuple[str, ...]
    usage: Usage
    evidence: Blob | None = None
    bundle_digest: str | None = None
    scenario_digest: str | None = None
    raw_scenario: Blob | None = None
    reduction_policy: ReductionPolicy = ReductionPolicy()
    attempts: tuple[SavedCase, ...] = ()
    environment_identity: str | None = None
    execution_identity: str | None = None
    plugin_claim_digest: str | None = None

    def validate(self):
        for value in (
            self.case_id,
            self.bundle_digest,
            self.scenario_digest,
            self.environment_identity,
            self.execution_identity,
            self.plugin_claim_digest,
        ):
            if value is not None:
                artifact_digest(value)
        if self.result and self.result.scenario_id != self.case_id:
            raise ContractError("Saved result must use its opaque case identity")
        if bool(self.evidence) != bool(self.bundle_digest):
            raise ContractError("Evidence requires its signed receipt anchor")
        if self.evidence and self.evidence.kind != "evidence":
            raise ContractError("Invalid evidence artifact role")
        if self.raw_scenario and self.raw_scenario.kind != "raw_scenario":
            raise ContractError("Invalid scenario artifact role")
        if any(a.attempts for a in self.attempts):
            raise ContractError("Nested adaptive strategies are unsupported")
        unique(tuple(a.case_id for a in self.attempts), "attempt IDs")


@dataclass(frozen=True)
class RunDocument(WireRecord):
    run_id: str
    lock_digest: str
    runtime_digest: str
    reducer: Literal["drill-evidence-v1/suite-aggregate-v1"]
    created_at: float
    finished_at: float | None
    status: Literal["running", "finished", "cancelled"]
    signing: Literal["advisory", "configured"]
    key_id: str
    require_signing: bool
    cases: tuple[SavedCase, ...]
    usage: Usage
    model_calls: tuple[SavedCall, ...]
    reported_security_passed: bool
    files: tuple[Blob, ...]
    raw_expires_at: float | None
    lock_ref: Blob | None
    storage_limit: int
    parent_run_id: str | None = None
    parent_envelope_digest: str | None = None
    schema_version: Literal[1] = 1

    def validate(self):
        run_id(self.run_id)
        for value in (
            self.lock_digest,
            self.runtime_digest,
            self.key_id,
            self.parent_envelope_digest,
        ):
            if value is not None:
                artifact_digest(value)
        if (self.parent_run_id is None) != (self.parent_envelope_digest is None):
            raise ContractError("Rerun must bind its parent envelope")
        if self.parent_run_id:
            run_id(self.parent_run_id)
        unique(tuple(c.case_id for c in self.cases), "run case IDs")
        unique(tuple((b.kind, b.digest) for b in self.files), "run artifacts")
        if not self.cases or not 1024 <= self.storage_limit <= 1024**3:
            raise ContractError("Invalid run roster or storage limit")
        if self.require_signing and self.signing != "configured":
            raise ContractError("Required signing cannot use an advisory key")
        if (self.status == "running") != (self.finished_at is None):
            raise ContractError("Inconsistent run completion")
        if self.status != "running" and any(
            c.disposition in ("running", "pending") for c in self.cases
        ):
            raise ContractError("A finished run must finalize its full roster")
        if self.reported_security_passed and self.status != "finished":
            raise ContractError("Unfinished runs cannot pass")
        if self.status != "running" and (self.status == "cancelled") != any(
            c.disposition == "cancelled" for c in self.cases
        ):
            raise ContractError("Cancellation status differs from the case roster")
        if self.created_at < 0 or (
            self.finished_at is not None and self.finished_at < self.created_at
        ):
            raise ContractError("Invalid run timestamps")
        if self.raw_expires_at is not None and not (
            self.created_at < self.raw_expires_at <= self.created_at + 31 * 86400
        ):
            raise ContractError("Invalid raw retention timestamps")
        if self.lock_ref and (self.lock_ref.kind != "raw_lock" or self.raw_expires_at is None):
            raise ContractError("Raw lock requires an explicit retention period")


# Keep known runtime codes useful while hashing free-text planning/plugin diagnostics.
SAFE_DIAGNOSTICS = frozenset(
    (
        "cancelled cleanup_failed prior_case_cleanup_failed acceptance_revalidation_failed "
        "runtime_binding_unsupported runtime_identity_mismatch missing_scenario "
        "adaptive_single_prompt_only adaptive_strategy_required fixture_adapter_unsupported "
        "injection_combination_unsupported maximum_eight_concurrent_cases fixture_execution_failed "
        "evidence_reduction_failed execution_worker_failed strategy_produced_no_target_evidence "
        "adaptive_execution_failed adaptive_deadline_exhausted plugin_budget_exhausted "
        "missing_terminal missing_model_output missing_payload_exposure partial_observation_channel "
        "evidence_truncated missing_required_evaluator contradictory_evaluations "
        "missing_definite_evaluation indefinite_evaluation completion_has_errors "
        "rubric_reports_error missing_or_contradictory_task_check effect_contradicts_blocked_action "
        "completed step_limit backend_error fixture_error tool_error collector_error unsupported "
        "unknown_completion unexercised"
    ).split()
)


def diagnostic(value):
    if value in SAFE_DIAGNOSTICS or re.fullmatch(
        r"budget:(case|global):(model_calls|tool_steps|strategy_iterations|artifact_bytes|wall_seconds)",
        value,
    ):
        return value
    return "redacted:" + digest(value)


def normalized_result(result, case_id):
    return replace(result, scenario_id=case_id, upstream_verdict={}) if result else None


class RunStore:
    def __init__(self, directory, *, clock=time.time):
        self.directory = Path(directory).absolute()
        private(self.directory, directory=True)
        run_id(self.directory.name)
        self.clock = clock
        self.files: dict[tuple[str, str], Blob] = {}
        self.written: dict[str, int] = {}
        self._document: RunDocument | None = None

    @property
    def document(self) -> RunDocument:
        if self._document is None:
            raise ContractError("Load run metadata before accessing its artifacts")
        return self._document

    @document.setter
    def document(self, value: RunDocument):
        self._document = value

    @classmethod
    def create(
        cls,
        root,
        lock,
        signer,
        *,
        require_signing=False,
        signing="configured",
        raw_retention_seconds=None,
        storage_limit=64 * 1024**2,
        parent=None,
        clock=time.time,
    ):
        root = Path(root).absolute()
        if not root.exists():
            mkdir_private(root)
        private(root, directory=True)
        if type(storage_limit) is not int or not 1024 <= storage_limit <= 1024**3:
            raise ContractError("Invalid retained storage limit")
        if raw_retention_seconds is not None and (
            type(raw_retention_seconds) is not int or not 1 <= raw_retention_seconds <= 31 * 86400
        ):
            raise ContractError("Raw retention must be explicitly bounded to 1 second–31 days")
        directory = root / uuid.uuid4().hex
        mkdir_private(directory)
        store = cls(directory, clock=clock)
        for name in ("evidence", "raw"):
            mkdir_private(directory / name)
        now = float(clock())
        store.document = RunDocument(
            directory.name,
            lock.lock_digest,
            build_digest(),
            REDUCER,
            now,
            None,
            "running",
            signing,
            signer.key_id,
            require_signing,
            tuple(
                SavedCase(c.id, c.required, "pending", None, None, (), Usage())
                for c in lock.plan.cases
            ),
            Usage(),
            (),
            False,
            (),
            now + raw_retention_seconds if raw_retention_seconds is not None else None,
            None,
            storage_limit,
            parent.get("run_id") if parent else None,
            parent.get("envelope_digest") if parent else None,
        )
        if raw_retention_seconds is not None:
            ref = store.put(lock.to_dict(), "raw_lock")
            store.document = replace(
                store.document, lock_ref=ref, files=tuple(store.files.values())
            )
        store.write("initial.json", signer.sign(store.document.to_dict()))
        store.write("state.json", store.document.to_dict())
        # Owner-only capability; never contains model/provider credentials or a PID.
        store.write(
            "control.json",
            {
                "run_id": directory.name,
                "nonce": secrets.token_hex(32),
                "key": secrets.token_hex(32),
            },
        )
        return store

    def write(self, name, data, *, replace=False):
        parts = Path(name).parts
        if not (
            len(parts) == 1
            and name in {"initial.json", "state.json", "control.json", "envelope.json"}
            or len(parts) == 2
            and parts[0] in ("evidence", "raw")
            and re.fullmatch(r"[a-f0-9]{64}\.json", parts[1])
        ):
            raise ContractError("Invalid run artifact path")
        encoded = canonical(data) + b"\n"
        retained = sum(self.written.values()) - self.written.get(name, 0) + len(encoded)
        if retained > self.document.storage_limit:
            raise ContractError("Run storage limit exhausted")
        write_private(self.directory / name, encoded, replace=replace)
        self.written[name] = len(encoded)

    def path(self, ref):
        ref.to_dict()
        return (
            self.directory
            / ("evidence" if ref.kind == "evidence" else "raw")
            / (ref.digest[7:] + ".json")
        )

    def put(self, data, kind):
        if kind != "evidence" and (
            self.document.raw_expires_at is None or self.clock() >= self.document.raw_expires_at
        ):
            return None
        encoded = canonical({"kind": kind, "data": data}) + b"\n"
        ref = Blob("sha256:" + hashlib.sha256(encoded).hexdigest(), len(encoded), kind)
        key = (kind, ref.digest)
        if key not in self.files:
            self.write(
                str(self.path(ref).relative_to(self.directory)), {"kind": kind, "data": data}
            )
            self.files[key] = ref
        return ref

    def read(self, ref):
        if ref.kind != "evidence" and (
            self.document is None
            or self.document.raw_expires_at is None
            or self.clock() >= self.document.raw_expires_at
        ):
            raise ContractError("Raw evidence retention has expired")
        raw = read_private(self.path(ref))
        if len(raw) != ref.size or "sha256:" + hashlib.sha256(raw).hexdigest() != ref.digest:
            raise ContractError("Run artifact size/digest mismatch")
        from ..plugins.catalog import parse_json

        value = parse_json(raw)
        if type(value) is not dict or set(value) != {"kind", "data"} or value["kind"] != ref.kind:
            raise ContractError("Invalid run artifact role")
        return value["data"]

    def save_case(self, case, planned):
        evidence, anchor = None, None
        scenario = case.scenario or planned.scenario
        scenario_digest = digest(scenario.to_dict()) if scenario else None
        if case.evidence:
            if case.evidence.artifacts:
                raise ContractError("This execution profile does not retain external proof stores")
            evidence = self.put(case.evidence.to_dict(), "evidence")
            anchor = case.receipt.bundle_digest
        raw_scenario = self.put(case.scenario.to_dict(), "raw_scenario") if case.scenario else None
        return SavedCase(
            case.case_id,
            case.required,
            case.disposition,
            normalized_result(case.result, case.case_id),
            case.legacy_outcome,
            tuple(diagnostic(d) for d in case.diagnostics),
            case.usage,
            evidence,
            anchor,
            scenario_digest,
            raw_scenario,
            case.reduction_policy,
            tuple(self.save_case(a, planned) for a in case.attempts),
            case.environment_identity,
            case.execution_identity,
            case.plugin_claim_digest,
        )

    def snapshot(self, run, lock, *, terminal=False):
        self.document = replace(
            self.document,
            cases=tuple(
                self.save_case(c, p) for c, p in zip(run.cases, lock.plan.cases, strict=True)
            ),
            usage=run.usage,
            model_calls=tuple(SavedCall(**asdict(c)) for c in run.model_calls),
            status=(
                "cancelled" if any(c.disposition == "cancelled" for c in run.cases) else "finished"
            )
            if terminal
            else "running",
            finished_at=float(self.clock()) if terminal else None,
            reported_security_passed=terminal and run.passed,
            files=tuple(sorted(self.files.values(), key=lambda b: (b.kind, b.digest))),
        )
        # save_case can add files while evaluating the arguments above.
        self.document = replace(
            self.document,
            files=tuple(sorted(self.files.values(), key=lambda b: (b.kind, b.digest))),
        )
        self.write("state.json", self.document.to_dict(), replace=True)


def _control(store):
    value = read_json(store.directory / "control.json", 1024)
    if (
        type(value) is not dict
        or set(value) != {"run_id", "nonce", "key"}
        or value["run_id"] != store.directory.name
    ):
        raise ContractError("Invalid run control capability")
    if any(
        type(value[k]) is not str or not re.fullmatch(r"[a-f0-9]{64}", value[k])
        for k in ("nonce", "key")
    ):
        raise ContractError("Invalid run control capability")
    return value


def cancel_message(control):
    payload = {"run_id": control["run_id"], "nonce": control["nonce"], "action": "cancel"}
    return {
        **payload,
        "mac": hmac.new(
            bytes.fromhex(control["key"]), canonical(payload), hashlib.sha256
        ).hexdigest(),
    }


def request_cancel(directory):
    store = RunStore(directory)
    with lease(store.directory / "lease.lock") as acquired:
        if acquired:
            return False
    control = _control(store)
    path = store.directory / "cancel.json"
    write_json(path, cancel_message(control), replace=True)
    return True


def cancellation_requested(store, control):
    try:
        actual = read_json(store.directory / "cancel.json", 1024)
        expected = cancel_message(control)
        return (
            type(actual) is dict
            and set(actual) == set(expected)
            and all(
                type(actual[k]) is str and hmac.compare_digest(actual[k], expected[k])
                for k in expected
            )
        )
    except (OSError, ContractError):
        return False
