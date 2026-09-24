"""
The Audit Packet generator (roadmap P2) — the regulatory artifact.

One signed document that answers "show me this agent's governance": charter
identity + version history, a compliance grade with its rationale, the MPL
exposure summary, finding + approval (HITL) history, drift, exceptions,
remediation proofs, and the operations (decision-rights) log. Decommission
emits a **final** packet — the closing record (charter-spec §7.5).

The grade is deterministic and explains itself; an auditor should never have
to guess why a B is a B.
"""
from __future__ import annotations

GRADES = ("A", "B", "C", "D", "F")
PACKET_TYPE = "blastcontain.audit_packet/v1"


def compliance_grade(
    charter: dict | None,
    latest_scan: dict | None,
    open_critical_types: list[str],
    hitl: dict,
    state: str,
    tombstone_findings: int = 0,
    advisory_signed: bool = False,
) -> tuple[str, list[str]]:
    """Deterministic grade + the rationale that justifies it."""
    rationale: list[str] = []

    scan_status = (latest_scan or {}).get("status", "NO_SCAN")
    summary = (latest_scan or {}).get("summary", {})
    highs = int(summary.get("high", 0) or 0)

    # F — governance has failed or been bypassed
    if tombstone_findings:
        rationale.append(f"{tombstone_findings} decision(s) arrived for a retired agent "
                         "(tombstone traffic)")
        return "F", rationale
    if open_critical_types and state == "active":
        rationale.append("CRITICAL findings open while the agent runs un-quarantined: "
                         + ", ".join(open_critical_types))
        return "F", rationale
    if scan_status == "REJECTED" and state == "active":
        rationale.append("latest Verify scan REJECTED but the agent is active")
        return "F", rationale

    # D — known-bad, but governance reacted
    if state == "quarantined":
        rationale.append("agent is quarantined pending recertification")
        return "D", rationale
    if open_critical_types:
        rationale.append("CRITICAL findings open: " + ", ".join(open_critical_types))
        return "D", rationale

    # C — material weaknesses
    if charter is None:
        rationale.append("no signed Charter — the agent is ungoverned")
        return "C", rationale
    if advisory_signed:
        rationale.append("Charter signed with the dev default key (advisory — "
                         "integrity only, not attestation)")
        return "C", rationale
    if hitl.get("rubber_stamp_risk"):
        rationale.append("approval gate shows rubber-stamp pattern "
                         "(near-total approval at near-zero latency)")
        return "C", rationale
    if highs:
        rationale.append(f"{highs} HIGH finding(s) open")
        return "C", rationale

    # B — governed, minor gaps
    if scan_status in ("NO_SCAN", "UNKNOWN"):
        rationale.append("no Verify scan on record")
        return "B", rationale
    if not hitl.get("events_total"):
        rationale.append("no runtime decision evidence yet")
        return "B", rationale

    rationale.append("scan passed, signed Charter active, no open CRITICAL/HIGH, "
                     "approval gate healthy")
    return "A", rationale


def build_audit_packet(
    agent_id: str,
    environment: str,
    generated_at: str,
    kind: str,                              # periodic | final
    charter_document: dict | None,
    charter_state: str,
    versions: list[dict],
    latest_scan: dict | None,
    open_critical_types: list[str],
    mpl_summary: dict,
    hitl: dict,
    drift: dict,
    operations: list[dict],
    exceptions: list[dict],
    tombstone_findings: int = 0,
    advisory_signed: bool = False,
) -> dict:
    """Assemble the (unsigned) Audit Packet payload; the caller signs it."""
    grade, rationale = compliance_grade(
        charter_document, latest_scan, open_critical_types, hitl,
        charter_state, tombstone_findings, advisory_signed,
    )
    charter_section = None
    if charter_document:
        charter_section = {
            "version": charter_document.get("version"),
            "state": charter_state,
            "trust_tier": charter_document.get("trust_tier"),
            "autonomy_mode": charter_document.get("autonomy_mode"),
            "signed_at": charter_document.get("signed_at"),
            "signed_by": charter_document.get("signed_by"),
            "objectives": [o.get("id") for o in charter_document.get("objectives") or []],
            "permitted_tools": charter_document.get("permitted_tools") or [],
            "remediation_proofs": charter_document.get("remediation_proofs") or [],
            "owner": charter_document.get("owner"),
        }
    return {
        "packet_type": PACKET_TYPE,
        "kind": kind,
        "agent_id": agent_id,
        "environment": environment,
        "generated_at": generated_at,
        "compliance": {"grade": grade, "rationale": rationale},
        "charter": charter_section,
        "versions": versions,
        "scan": {
            "status": (latest_scan or {}).get("status", "NO_SCAN"),
            "scanned_at": (latest_scan or {}).get("scanned_at"),
            "summary": (latest_scan or {}).get("summary", {}),
            "open_critical_types": open_critical_types,
        },
        "mpl": mpl_summary,
        "hitl": hitl,
        "drift": drift,
        "exceptions": exceptions,
        "operations": operations,
    }
