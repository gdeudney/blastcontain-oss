"""
blastcontain_core.models — finding and scan-result data types.

These are the shared output types every BlastContain tool produces.
The platform consumes them via the same dataclasses (or equivalent JSON).
"""
from __future__ import annotations

import datetime
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScanStatus(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    QUARANTINED = "QUARANTINED"
    ERROR = "ERROR"


def _utc_now_iso() -> str:
    # datetime.utcnow() is deprecated in 3.12+; use timezone-aware now()
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class InfraFinding:
    check_id: str
    finding_type: str
    severity: Severity
    title: str
    detail: str
    remediation: str
    references: list[str] = field(default_factory=list)
    evidence: Optional[str] = None
    mit_domain: Optional[str] = None
    mit_causal_id: Optional[str] = None
    mit_causal_label: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "finding_type": self.finding_type,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "references": self.references,
            "evidence": self.evidence,
            "mit_domain": self.mit_domain,
            "mit_causal_id": self.mit_causal_id,
            "mit_causal_label": self.mit_causal_label,
        }


@dataclass
class ScanResult:
    agent_id: str
    environment: str
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scanned_at: str = field(default_factory=_utc_now_iso)
    status: ScanStatus = ScanStatus.APPROVED
    findings: list[InfraFinding] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)
    augmentation: dict = field(default_factory=dict)
    blast_radius_factor: float = 1.0
    max_tier: int = 0

    @property
    def criticals(self) -> list[InfraFinding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def highs(self) -> list[InfraFinding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def mediums(self) -> list[InfraFinding]:
        return [f for f in self.findings if f.severity == Severity.MEDIUM]

    def derive_status(self) -> ScanStatus:
        if self.criticals:
            return ScanStatus.QUARANTINED
        if self.highs or self.mediums:
            return ScanStatus.REJECTED
        return ScanStatus.APPROVED

    def as_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "agent_id": self.agent_id,
            "environment": self.environment,
            "scanned_at": self.scanned_at,
            "status": self.status.value,
            "blast_radius_factor": self.blast_radius_factor,
            "max_tier": self.max_tier,
            "augmentation": self.augmentation,
            "summary": {
                "critical": len(self.criticals),
                "high": len(self.highs),
                "medium": len(self.mediums),
                "passed": len(self.passed),
                "skipped": len(self.skipped),
            },
            "findings": [f.as_dict() for f in self.findings],
            "passed": self.passed,
            "skipped": self.skipped,
        }


# ── Drill (adversarial red-team) types ────────────────────────────────────────
# These mirror the InfraFinding / ScanResult shape so the platform Ledger
# ingests Verify and Drill output through the same dataclasses. Where Verify's
# InfraFinding records a static misconfiguration, a Drill DrillFinding records
# what the agent *did* when attacked — scored on two planes (content + action).


class DrillOutcome(str, Enum):
    HELD = "HELD"                  # the attack was contained — a defence held
    BYPASS = "BYPASS"              # the attack got through — a control was bypassed
    OVER_REFUSAL = "OVER_REFUSAL"  # the agent refused a BENIGN request — a false positive
    ERROR = "ERROR"                # the scenario could not execute


class DrillStatus(str, Enum):
    PASSED = "PASSED"    # no bypasses
    PARTIAL = "PARTIAL"  # at least one non-critical bypass
    FAILED = "FAILED"    # at least one CRITICAL bypass — blocks prod promotion
    ERROR = "ERROR"      # the drill could not run to completion


@dataclass
class DrillFinding:
    """One attack scenario's result, scored on the content and action planes."""

    scenario_id: str
    scenario_name: str
    outcome: DrillOutcome
    severity: Optional[Severity] = None

    # Corpus provenance — for reproducibility (drill-spec §7)
    attack_id: Optional[str] = None
    technique: Optional[str] = None         # e.g. "direct-injection", "many-shot"
    layer: Optional[str] = None             # "replay" | "operators" | "generative"
    vector: Optional[str] = None            # "direct" | "indirect"

    # Scoring — two planes (drill-spec §5)
    detection_latency_ms: Optional[float] = None
    blocked_by: Optional[str] = None        # which control held (None on bypass)
    bypass_description: Optional[str] = None
    evidence: Optional[str] = None
    content_verdict: Optional[dict] = None  # content-plane scorer output
    action_verdict: Optional[dict] = None   # action-plane probe output (cage ground truth)
    scorer_errors: Optional[list] = None    # scorers that crashed on this attack (not silently dropped)

    # Taxonomy — ATLAS primary, plus MIT + OWASP (drill-spec §6)
    atlas_id: Optional[str] = None
    atlas_name: Optional[str] = None
    mit_domain: Optional[str] = None
    mit_causal_id: Optional[str] = None
    mit_causal_label: Optional[str] = None
    owasp_id: Optional[str] = None
    owasp_label: Optional[str] = None

    def as_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "outcome": self.outcome.value,
            "severity": self.severity.value if self.severity else None,
            "attack_id": self.attack_id,
            "technique": self.technique,
            "layer": self.layer,
            "vector": self.vector,
            "detection_latency_ms": self.detection_latency_ms,
            "blocked_by": self.blocked_by,
            "bypass_description": self.bypass_description,
            "evidence": self.evidence,
            "content_verdict": self.content_verdict,
            "action_verdict": self.action_verdict,
            "scorer_errors": self.scorer_errors,
            "atlas_id": self.atlas_id,
            "atlas_name": self.atlas_name,
            "mit_domain": self.mit_domain,
            "mit_causal_id": self.mit_causal_id,
            "mit_causal_label": self.mit_causal_label,
            "owasp_id": self.owasp_id,
            "owasp_label": self.owasp_label,
        }


@dataclass
class DrillReport:
    """A full drill run — the signed Audit-Packet payload Drill produces."""

    agent_id: str
    environment: str
    corpus_version: str                     # pinned corpus the run was tested against
    corpus_sources: list[str] = field(default_factory=list)  # which sources contributed
    agent_url: Optional[str] = None
    drill_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    drilled_at: str = field(default_factory=_utc_now_iso)
    status: DrillStatus = DrillStatus.PASSED
    findings: list[DrillFinding] = field(default_factory=list)

    # Bench provenance — what attacked, what judged (drill-spec §3, §7)
    target_model: Optional[str] = None
    judge_model: Optional[str] = None
    guard_model: Optional[str] = None
    attacker_model: Optional[str] = None    # generative-layer attacker (abliterated model)
    cage: Optional[str] = None              # "podman" | "inprocess"
    target_temperature: Optional[float] = None  # target sampling temperature (reproducibility)
    scorers: dict = field(default_factory=dict)  # scorer availability flags
    warnings: list = field(default_factory=list)  # run-level issues (broken source/scorer) — not silent

    @property
    def bypasses(self) -> list[DrillFinding]:
        return [f for f in self.findings if f.outcome == DrillOutcome.BYPASS]

    @property
    def held(self) -> list[DrillFinding]:
        return [f for f in self.findings if f.outcome == DrillOutcome.HELD]

    @property
    def errors(self) -> list[DrillFinding]:
        return [f for f in self.findings if f.outcome == DrillOutcome.ERROR]

    @property
    def over_refusals(self) -> list[DrillFinding]:
        """Benign requests the agent wrongly refused — false positives, not bypasses."""
        return [f for f in self.findings if f.outcome == DrillOutcome.OVER_REFUSAL]

    @property
    def critical_bypasses(self) -> list[DrillFinding]:
        return [f for f in self.bypasses if f.severity == Severity.CRITICAL]

    def derive_status(self) -> DrillStatus:
        if self.critical_bypasses:
            return DrillStatus.FAILED
        if self.bypasses:
            return DrillStatus.PARTIAL
        if self.findings and all(f.outcome == DrillOutcome.ERROR for f in self.findings):
            return DrillStatus.ERROR
        return DrillStatus.PASSED

    def as_dict(self) -> dict:
        return {
            "drill_id": self.drill_id,
            "agent_id": self.agent_id,
            "environment": self.environment,
            "agent_url": self.agent_url,
            "drilled_at": self.drilled_at,
            "corpus_version": self.corpus_version,
            "corpus_sources": self.corpus_sources,
            "status": self.status.value,
            "warnings": self.warnings,
            "bench": {
                "target_model": self.target_model,
                "judge_model": self.judge_model,
                "guard_model": self.guard_model,
                "attacker_model": self.attacker_model,
                "cage": self.cage,
                "target_temperature": self.target_temperature,
                "scorers": self.scorers,
            },
            "summary": {
                "scenarios_run": len(self.findings),
                "held": len(self.held),
                "bypasses": len(self.bypasses),
                "critical_bypasses": len(self.critical_bypasses),
                "over_refusals": len(self.over_refusals),
                "errors": len(self.errors),
            },
            "findings": [f.as_dict() for f in self.findings],
        }
