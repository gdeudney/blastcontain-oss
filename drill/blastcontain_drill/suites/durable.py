"""Run lifecycle services shared by future CLI/UI clients, with explicit trust."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from pathlib import Path
import hashlib
import re
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..contracts import ContractError, ScenarioSpec
from ..evidence import EvidenceBundle, EvidenceReceipt, reduce_evidence
from ..evidence.reducer import ReductionPolicy
from .adaptive import aggregate
from .artifacts import digest
from .budgets import RESOURCES
from .lock import SuiteLock, validate_lock
from .privacy import lease, read_json, read_private, private
from .run_store import (
    RunDocument,
    RunStore,
    _control,
    cancellation_requested,
    normalized_result,
)
from .service import CaseRun, SuiteRun, execution_identity, run_suite
from .signatures import Signer, verify_signature


@dataclass(frozen=True)
class StoredRun:
    directory: Path
    run: SuiteRun = field(repr=False)


@dataclass(frozen=True)
class Verification:
    run_id: str
    envelope_digest: str
    trusted: bool
    replayed: bool
    reported_security_passed: bool
    security_passed: bool
    run: SuiteRun | None = field(default=None, repr=False)

    @property
    def attested_pass(self):
        return self.trusted and self.replayed and self.security_passed


async def execute_run(
    lock,
    root,
    *,
    current_inputs,
    signer=None,
    require_signing=False,
    raw_retention_seconds=None,
    storage_limit=64 * 1024**2,
    credentials=None,
    transport=None,
    cancel=None,
    on_created=None,
    progress=None,
    parent=None,
    clock=time.time,
):
    """Persist the full roster before dispatch. Required signing never falls back."""
    if require_signing and signer is None:
        raise ContractError("Required signing needs an explicit Ed25519 key")
    lock.to_dict()
    inputs = current_inputs()
    validate_lock(lock, inputs.catalog, records=inputs.records, probes=inputs.probes)
    signing = "configured" if signer is not None else "advisory"
    signer = signer or Signer(Ed25519PrivateKey.generate())
    store = RunStore.create(
        root,
        lock,
        signer,
        signing=signing,
        require_signing=require_signing,
        raw_retention_seconds=raw_retention_seconds,
        storage_limit=storage_limit,
        parent=parent,
        clock=clock,
    )
    cancellation = cancel or asyncio.Event()
    last, storage_failed = None, False

    def save(snapshot):
        nonlocal last, storage_failed
        last = snapshot
        if storage_failed:
            return
        try:
            store.snapshot(snapshot, lock)
            if progress is not None:
                progress(snapshot)
        except Exception:
            storage_failed = True
            cancellation.set()

    def save_trace(trace):
        nonlocal storage_failed
        if storage_failed:
            return
        try:
            store.put(trace, "raw_trace")
        except Exception:
            storage_failed = True
            cancellation.set()

    with lease(store.directory / "lease.lock") as acquired:
        if not acquired:
            raise ContractError("Run already has an active controller")
        control = _control(store)
        if on_created is not None:
            on_created(store.directory)

        async def watch():
            while True:
                if cancellation_requested(store, control):
                    cancellation.set()
                    return
                await asyncio.sleep(0.1)

        watcher = asyncio.create_task(watch())
        interrupted = False
        try:
            try:
                last = await run_suite(
                    lock,
                    current_inputs=current_inputs,
                    credentials=credentials,
                    transport=transport,
                    cancel=cancellation,
                    progress=save,
                    model_trace=save_trace if raw_retention_seconds is not None else None,
                )
            except asyncio.CancelledError:
                interrupted = True
            if storage_failed or last is None:
                raise ContractError("Run persistence failed; no completed envelope was published")
            store.snapshot(last, lock, terminal=True)
            envelope = signer.sign(store.document.to_dict())
            # Detect a misconfigured signer before publishing a completion marker.
            verify_signature(envelope, trusted_public_key=signer.public_key, allow_advisory=True)
            store.write("envelope.json", envelope)
        finally:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
        if interrupted:
            raise asyncio.CancelledError
    return StoredRun(store.directory, last)


def _load_final(store, *, trusted_public_key=None, allow_advisory=False):
    initial = read_json(store.directory / "initial.json")
    envelope = read_json(store.directory / "envelope.json")
    trusted = verify_signature(
        envelope, trusted_public_key=trusted_public_key, allow_advisory=allow_advisory
    )
    verify_signature(initial, trusted_public_key=trusted_public_key, allow_advisory=allow_advisory)
    if envelope["signature"]["public_key"] != initial["signature"]["public_key"]:
        raise ContractError("Run signing identity changed")
    document = RunDocument.from_dict(envelope["payload"])
    start = RunDocument.from_dict(initial["payload"])
    immutable = (
        "run_id",
        "lock_digest",
        "runtime_digest",
        "reducer",
        "created_at",
        "signing",
        "key_id",
        "require_signing",
        "raw_expires_at",
        "lock_ref",
        "storage_limit",
        "parent_run_id",
        "parent_envelope_digest",
    )
    if any(getattr(start, k) != getattr(document, k) for k in immutable):
        raise ContractError("Run identity/policy changed after creation")

    def roster(document):
        return tuple((c.case_id, c.required) for c in document.cases)

    if (
        document.run_id != store.directory.name
        or start.status != "running"
        or document.status == "running"
        or roster(start) != roster(document)
    ):
        raise ContractError("Run completion or roster mismatch")
    store.document = document
    refs = set()

    def collect(case):
        for ref in (case.evidence, case.raw_scenario):
            if ref:
                refs.add(ref)
        for attempt in case.attempts:
            collect(attempt)

    for case in document.cases:
        collect(case)
    if document.lock_ref:
        refs.add(document.lock_ref)
    refs.update(ref for ref in document.files if ref.kind == "raw_trace")
    if refs != set(document.files):
        raise ContractError("Run artifact inventory mismatch")
    if sum(b.size for b in document.files) > document.storage_limit:
        raise ContractError("Run artifact inventory exceeds storage policy")
    for ref in document.files:
        if (
            ref.kind == "evidence"
            or document.raw_expires_at is not None
            and store.clock() < document.raw_expires_at
        ):
            store.read(ref)
    return document, envelope, trusted


def _restore_case(store, saved, planned, lock, scenarios, *, trial=False, parent=None, index=None):
    scenario = planned.scenario
    if trial:
        scenario = scenarios.get(saved.case_id)
        if (
            scenario is None
            and saved.raw_scenario
            and store.clock() < store.document.raw_expires_at
        ):
            scenario = ScenarioSpec.from_dict(store.read(saved.raw_scenario))
        if scenario is None:
            return None
        expected = replace(planned.scenario, entry_prompt=scenario.entry_prompt, layer="replay")
        expected_id = digest({"parent": parent, "attempt": index, "scenario": scenario.to_dict()})
        if expected != scenario or saved.case_id != expected_id:
            raise ContractError("Adaptive attempt differs from its accepted scope")
        planned = replace(planned, id=saved.case_id, scenario=scenario, strategy=None)
    if saved.case_id != planned.id or saved.required != planned.required:
        raise ContractError("Case does not match the locked roster")
    if saved.execution_identity and saved.execution_identity != execution_identity(planned):
        raise ContractError("Case execution identity mismatch")
    if scenario and saved.scenario_digest != digest(scenario.to_dict()):
        raise ContractError("Case scenario identity mismatch")
    if any(
        getattr(saved.usage, resource) > getattr(lock.plan.spec.case_limits, resource)
        for resource in RESOURCES
    ):
        raise ContractError("Recorded case usage exceeds its accepted limits")
    evidence, receipt, attempts = None, None, []
    result = replace(saved.result, scenario_id=planned.scenario_id) if saved.result else None
    if saved.attempts:
        if not planned.strategy or saved.evidence:
            raise ContractError("Unexpected adaptive evidence structure")
        for i, item in enumerate(saved.attempts):
            attempt = _restore_case(
                store, item, planned, lock, scenarios, trial=True, parent=saved.case_id, index=i
            )
            if attempt is None:
                return None
            attempts.append(attempt)
        computed = aggregate(
            planned, attempts, saved.disposition, list(saved.diagnostics), saved.plugin_claim_digest
        )
        if (
            normalized_result(computed.result, saved.case_id) != saved.result
            or computed.legacy_outcome != saved.legacy_outcome
            or computed.disposition != saved.disposition
        ):
            raise ContractError("Adaptive result does not follow from retained evidence")
        if (
            planned.strategy == "builtin.strategy.pair"
            and saved.disposition == "completed"
            and computed.legacy_outcome != "BYPASS"
        ):
            raise ContractError("A bounded PAIR search cannot claim a completed held result")
        for resource in RESOURCES:
            if sum(getattr(a.usage, resource) for a in attempts) > getattr(saved.usage, resource):
                raise ContractError("Attempt usage exceeds its parent case")
        result = computed.result
    elif saved.evidence:
        if scenario is None or planned.strategy:
            raise ContractError("Evidence has no supported scenario binding")
        expected_policy = ReductionPolicy(
            lock.plan.spec.evaluators if scenario.security.goal == "content" else ()
        )
        if saved.reduction_policy != expected_policy:
            raise ContractError("Evidence reduction policy differs from the lock")
        evidence = EvidenceBundle.from_dict(store.read(saved.evidence))
        receipt = EvidenceReceipt(saved.case_id, saved.scenario_digest, saved.bundle_digest)
        reduced = reduce_evidence(scenario, evidence, receipt, policy=saved.reduction_policy)
        if (
            normalized_result(reduced.result, saved.case_id) != saved.result
            or reduced.legacy_outcome != saved.legacy_outcome
            or reduced.result.execution != saved.disposition
        ):
            raise ContractError("Saved result differs from offline evidence reduction")
        result = reduced.result
    elif (
        saved.disposition == "completed"
        or saved.legacy_outcome in ("HELD", "BYPASS", "OVER_REFUSAL")
        or result
        and result.security != "unknown"
    ):
        raise ContractError("A result without evidence cannot claim completion or security")
    if planned.disposition == "excluded" and saved.disposition != "skipped":
        raise ContractError("Excluded case was executed")
    if planned.disposition != "excluded" and saved.disposition == "skipped":
        raise ContractError("Required execution was silently skipped")
    return CaseRun(
        saved.case_id,
        saved.required,
        saved.disposition,
        saved.diagnostics,
        result,
        saved.legacy_outcome,
        evidence,
        receipt,
        saved.usage,
        environment_identity=saved.environment_identity,
        execution_identity=saved.execution_identity,
        plugin_claim_digest=saved.plugin_claim_digest,
        attempts=tuple(attempts),
        scenario=scenario if trial else None,
        reduction_policy=saved.reduction_policy,
    )


def verify_run(
    directory,
    *,
    trusted_public_key=None,
    allow_advisory=False,
    lock=None,
    scenarios=None,
    clock=time.time,
):
    """Check signed bytes; only replayed conclusions can pass the security gate.

    Default storage omits source prompts. Supply the original lock and, for adaptive
    cases, materialized attempt scenarios unless protected retained inputs are available.
    """
    store = RunStore(directory, clock=clock)
    document, envelope, trusted = _load_final(
        store, trusted_public_key=trusted_public_key, allow_advisory=allow_advisory
    )
    if lock is None and document.lock_ref and store.clock() < document.raw_expires_at:
        lock = SuiteLock.from_dict(store.read(document.lock_ref))
    if lock is None:
        return Verification(
            document.run_id,
            digest(envelope),
            trusted,
            False,
            document.reported_security_passed,
            False,
        )
    lock.to_dict()
    if lock.lock_digest != document.lock_digest:
        raise ContractError("Provided lock does not match the signed run")
    if len(lock.plan.cases) != len(document.cases):
        raise ContractError("Run roster differs from the lock")
    runtime = next(
        i.artifact_digest for i in lock.plan.identities if i.id == lock.plan.spec.target.binding
    )
    if document.runtime_digest != runtime:
        raise ContractError("Recorded runtime differs from the lock")
    cases = []
    for saved, planned in zip(document.cases, lock.plan.cases, strict=True):
        case = _restore_case(store, saved, planned, lock, scenarios or {})
        if case is None:
            return Verification(
                document.run_id,
                digest(envelope),
                trusted,
                False,
                document.reported_security_passed,
                False,
            )
        cases.append(case)
    for resource in RESOURCES:
        total = getattr(document.usage, resource)
        if sum(getattr(c.usage, resource) for c in cases) != total or total > getattr(
            lock.plan.spec.global_limits, resource
        ):
            raise ContractError("Global usage differs from cases or exceeds its accepted limit")
    valid_ids = {c.case_id for c in cases} | {a.case_id for c in cases for a in c.attempts}
    if len(document.model_calls) > document.usage.model_calls or any(
        c.case_id not in valid_ids or c.status == "pending" for c in document.model_calls
    ):
        raise ContractError("Model call accounting is incomplete or incorrectly scoped")
    run = SuiteRun(document.lock_digest, tuple(cases), document.usage)
    if run.passed != document.reported_security_passed:
        raise ContractError("Signed gate differs from reconstructed case results")
    return Verification(
        document.run_id,
        digest(envelope),
        trusted,
        True,
        document.reported_security_passed,
        run.passed,
        run,
    )


def inspect_run(directory, *, clock=time.time):
    """Sanitized inspection; an unfinished snapshot is never a completed result."""
    store = RunStore(directory, clock=clock)
    if (store.directory / "envelope.json").exists():
        document, _, _ = _load_final(store, allow_advisory=True)
        return {
            "run_id": document.run_id,
            "status": document.status,
            "lock_digest": document.lock_digest,
            "signing": document.signing,
            "trusted": False,
            "reported_security_passed": document.reported_security_passed,
            "cases": [
                {
                    "case_id": c.case_id,
                    "disposition": c.disposition,
                    "security": c.result.security if c.result else "unknown",
                }
                for c in document.cases
            ],
        }
    initial = read_json(store.directory / "initial.json")
    verify_signature(initial, allow_advisory=True)
    document = RunDocument.from_dict(initial["payload"])
    if document.run_id != store.directory.name:
        raise ContractError("Run directory identity mismatch")
    with lease(store.directory / "lease.lock") as acquired:
        status = "interrupted" if acquired else "running"
    return {
        "run_id": document.run_id,
        "status": status,
        "lock_digest": document.lock_digest,
        "trusted": False,
        "reported_security_passed": False,
        "cases": [
            {
                "case_id": c.case_id,
                "disposition": "incomplete" if acquired else "pending",
                "security": "unknown",
            }
            for c in document.cases
        ],
    }


async def rerun_run(
    directory,
    root,
    *,
    lock,
    current_inputs,
    trusted_public_key=None,
    allow_advisory=False,
    **kwargs,
):
    old = verify_run(
        directory, trusted_public_key=trusted_public_key, allow_advisory=allow_advisory, lock=lock
    )
    # Explicit rerun: a new ID, new workers and fresh acceptance. Never resume a trace.
    return await execute_run(
        lock,
        root,
        current_inputs=current_inputs,
        parent={"run_id": old.run_id, "envelope_digest": old.envelope_digest},
        **kwargs,
    )


def purge_expired_raw(directory, *, clock=time.time):
    store = RunStore(directory, clock=clock)
    with lease(store.directory / "lease.lock") as acquired:
        if not acquired:
            raise ContractError("Cannot purge an active run")
        if (store.directory / "envelope.json").exists():
            document, _, _ = _load_final(store, allow_advisory=True)
        else:
            initial = read_json(store.directory / "initial.json")
            verify_signature(initial, allow_advisory=True)
            document = RunDocument.from_dict(initial["payload"])
            if document.run_id != store.directory.name or document.status != "running":
                raise ContractError("Invalid interrupted-run identity")
        if document.raw_expires_at is None or clock() < document.raw_expires_at:
            return 0
        # A crash can leave raw blobs newer than the signed initial inventory.
        # Only remove validated content-addressed raw files inside this private run.
        from ..plugins.catalog import parse_json

        raw = store.directory / "raw"
        private(raw, directory=True)
        paths = []
        for path in raw.iterdir():
            if not re.fullmatch(r"[a-f0-9]{64}\.json", path.name):
                continue
            data = read_private(path)
            value = parse_json(data)
            if (
                hashlib.sha256(data).hexdigest() != path.stem
                or type(value) is not dict
                or set(value) != {"kind", "data"}
                or value["kind"] not in ("raw_lock", "raw_scenario", "raw_trace")
            ):
                raise ContractError("Unexpected raw artifact; purge refused")
            paths.append(path)
        for path in paths:
            path.unlink()
        return len(paths)


def legacy_projection(directory, **verify_options):
    """Explicit unsigned, sanitized, lossy DrillReport projection for old readers."""
    from blastcontain_core.models import (
        DrillFinding,
        DrillOutcome,
        DrillReport,
        DrillStatus,
        Severity,
    )

    verified = verify_run(directory, **verify_options)
    if not verified.replayed:
        raise ContractError("Legacy export requires verified replay inputs")
    run = verified.run
    report = DrillReport(
        run.lock_digest, "suite-fixture", "suite-native-v1", corpus_sources=["suite"]
    )
    report.drill_id = verified.run_id
    report.warnings.append(
        "Unsigned legacy projection; verify the original suite envelope: "
        + verified.envelope_digest
    )
    for case in run.cases:
        outcome = DrillOutcome(case.legacy_outcome or "ERROR")
        report.findings.append(
            DrillFinding(
                case.case_id,
                "Suite case",
                outcome,
                severity=Severity.HIGH if outcome == DrillOutcome.BYPASS else None,
                evidence="Retained suite evidence; attempted actions are not proof of performed effects.",
            )
        )
    report.status = report.derive_status() if run.passed or report.bypasses else DrillStatus.ERROR
    return report.as_dict()
