"""Explicit local decisions on reviewed bytes; no organizational policy inference."""

from datetime import datetime, timezone

from ..contracts import AcceptanceRecord, ContractError, PluginManifest
from ..plugins.catalog import MAX_METADATA_BYTES, review_digest
from .artifacts import canonical
from .catalog import SourceSnapshot
from .planner import ResolvedPlan, plan_suite


def record_decision(
    artifact,
    *,
    kind,
    expected_digest,
    actor,
    rationale,
    decision="accepted",
    grants=(),
    current_inputs,
):
    """Return new history; the caller publishes it to a new file without overwriting."""
    inputs = current_inputs()
    if kind == "suite":
        if type(artifact) is not dict or set(artifact) != {
            "schema_version",
            "content_digest",
            "ready",
            "plan",
        }:
            raise ContractError("Expected a saved suite plan")
        plan = ResolvedPlan.from_dict(artifact["plan"])
        if (
            type(artifact["schema_version"]) is not int
            or artifact["schema_version"] != 1
            or type(artifact["ready"]) is not bool
            or artifact["ready"] != plan.ready
            or artifact["content_digest"] != plan.content_digest
        ):
            raise ContractError("Plan wrapper differs from its contents")
        fresh = plan_suite(plan.spec, inputs.catalog, records=inputs.records, probes=inputs.probes)
        if decision == "accepted" and (fresh != plan or not plan.ready):
            raise ContractError("Plan changed or is blocked; review a new plan")
        subject, content_digest, scope = plan.spec.id, plan.content_digest, ()
    elif kind == "content":
        source = SourceSnapshot.from_dict(artifact)
        subject, content_digest, scope = source.id, source.content_digest, ()
    elif kind == "plugin":
        manifest = PluginManifest.from_dict(artifact)
        subject, content_digest, scope = (
            manifest.id,
            review_digest(manifest),
            manifest.access_requests,
        )
    else:
        raise ContractError("Unsupported acceptance kind")
    if content_digest != expected_digest:
        raise ContractError("Reviewed digest does not match the supplied artifact")
    if set(grants) != set(scope) or len(grants) != len(set(grants)):
        raise ContractError("Granted access must exactly match the reviewed scope")
    record = AcceptanceRecord(
        subject,
        kind,
        content_digest,
        actor,
        decision,
        datetime.now(timezone.utc).isoformat(),
        rationale,
        tuple(sorted(grants)),
    )
    history = {"schema_version": 1, "records": [r.to_dict() for r in (*inputs.records, record)]}
    if len(canonical(history)) + 1 > MAX_METADATA_BYTES:
        raise ContractError("Acceptance history exceeds the supported 64 KiB metadata limit")
    return history
