"""Content-bound acceptance snapshots. A lock is neither a signature nor a run permit."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..contracts import AcceptanceRecord, ContractError
from ..contracts.plugins import artifact_digest
from ..contracts.wire import WireRecord, unique
from .artifacts import digest
from .catalog import Catalog, RuntimeProbe
from .planner import ResolvedPlan, accepted, latest, plan_suite


def _payload(plan, acceptances, probes):
    return {
        "schema_version": 1,
        "plan": plan.to_dict(),
        "content_digest": plan.content_digest,
        "acceptances": [r.to_dict() for r in acceptances],
        "probes": [p.to_dict() for p in probes],
    }


@dataclass(frozen=True)
class SuiteLock(WireRecord):
    plan: ResolvedPlan
    content_digest: str
    acceptances: tuple[AcceptanceRecord, ...]
    probes: tuple[RuntimeProbe, ...]
    lock_digest: str
    schema_version: Literal[1] = 1

    def validate(self):
        artifact_digest(self.content_digest)
        artifact_digest(self.lock_digest)
        unique(tuple((r.kind, r.subject_id) for r in self.acceptances), "acceptance snapshots")
        unique(tuple(p.plugin_id for p in self.probes), "probe snapshots")
        if not self.plan.ready:
            raise ContractError("Cannot lock a blocked or entirely excluded plan")
        if self.content_digest != self.plan.content_digest:
            raise ContractError("Plan content digest mismatch")
        accepted(self.acceptances, "suite", self.plan.spec.id, self.content_digest)
        if self.lock_digest != digest(_payload(self.plan, self.acceptances, self.probes)):
            raise ContractError("Lock digest mismatch")


def create_lock(plan: ResolvedPlan, catalog: Catalog, *, records=(), probes=()) -> SuiteLock:
    """Replan against supplied current inputs before binding an accepted plan."""
    records, probes = tuple(records), tuple(probes)
    fresh = plan_suite(plan.spec, catalog, records=records, probes=probes)
    if fresh != plan:
        raise ContractError("Plan changed; review the newly resolved plan")
    if not plan.ready:
        raise ContractError("Cannot lock a blocked or entirely excluded plan")
    suite_record = accepted(records, "suite", plan.spec.id, plan.content_digest)
    snapshots = [suite_record]
    for identity in plan.identities:
        kind = {"external_source": "content", "plugin": "plugin"}.get(identity.kind)
        if kind is not None:
            record = latest(records, kind, identity.id)
            if record is not None:
                snapshots.append(record)
    ordered_snapshots = tuple(sorted(snapshots, key=lambda r: (r.kind, r.subject_id)))
    plugin_ids = {i.id for i in plan.identities if i.kind == "plugin"}
    selected_probes = tuple(
        sorted((p for p in probes if p.plugin_id in plugin_ids), key=lambda p: p.plugin_id)
    )
    return SuiteLock(
        plan,
        plan.content_digest,
        ordered_snapshots,
        selected_probes,
        digest(_payload(plan, ordered_snapshots, selected_probes)),
    )


def validate_lock(lock: SuiteLock, catalog: Catalog, *, records=(), probes=()) -> None:
    """Require current decisions and data, not the historical acceptance/probe snapshots.

    Execution calls this at run start and before each case, and separately binds
    actual runtime code. Future external workers must reprobe isolation too.
    Reading a self-consistent JSON lock is insufficient.
    """
    lock.to_dict()  # Recheck wire integrity, including nested records.
    create_lock(lock.plan, catalog, records=records, probes=probes)
