"""Evidence transport and independent outcome dimensions; no inferred success."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .wire import ContractError, WireRecord, require_text

EventKind = Literal[
    "started",
    "payload_delivered",
    "model_output",
    "tool_requested",
    "authorization_decision",
    "effect_attempted",
    "effect_blocked",
    "effect_performed",
    "state_changed",
    "error",
    "completed",
    "cancelled",
]


@dataclass(frozen=True)
class EvidenceEvent(WireRecord):
    scenario_id: str
    sequence: int
    kind: EventKind
    emitter: str
    authority: Literal["runtime", "environment", "plugin_claim"]
    data: dict[str, Any] = field(default_factory=dict)
    schema_version: Literal[1] = 1

    def validate(self):
        require_text(self.scenario_id, "scenario_id")
        require_text(self.emitter, "emitter")
        if self.sequence < 0:
            raise ContractError("sequence must not be negative")


@dataclass(frozen=True)
class EvidenceTrace(WireRecord):
    scenario_id: str
    events: tuple[EvidenceEvent, ...]
    schema_version: Literal[1] = 1

    def validate(self):
        require_text(self.scenario_id, "scenario_id")
        if not self.events or self.events[0].kind != "started":
            raise ContractError("Trace must begin with started")
        for i, event in enumerate(self.events):
            if event.scenario_id != self.scenario_id or event.sequence != i:
                raise ContractError("Trace has a scenario mismatch or sequence gap")
            if i and event.kind == "started":
                raise ContractError("Trace cannot restart")
            if event.kind in ("completed", "cancelled") and i != len(self.events) - 1:
                raise ContractError("Events after terminal event")


@dataclass(frozen=True)
class ScenarioResult(WireRecord):
    scenario_id: str
    execution: Literal["completed", "incomplete", "unsupported", "error", "cancelled"]
    security: Literal[
        "held", "content_violation", "action_attempted", "effect_observed", "unknown"
    ] = "unknown"
    utility: Literal["succeeded", "failed", "not_measured", "unknown"] = "not_measured"
    evidence_quality: Literal["observed", "partial", "claims_only", "none"] = "none"
    containment: Literal["blocked", "not_blocked", "unknown", "not_applicable"] = "unknown"
    evidence_refs: tuple[str, ...] = ()
    upstream_verdict: dict[str, Any] = field(default_factory=dict)
    schema_version: Literal[1] = 1

    def validate(self):
        require_text(self.scenario_id, "scenario_id")
        if self.execution != "completed" and self.security == "held":
            raise ContractError("Incomplete execution cannot establish held")
        if self.security != "unknown" and (
            self.evidence_quality in ("none", "claims_only") or not self.evidence_refs
        ):
            raise ContractError("Security conclusions require observed evidence references")
        if self.security == "held" and self.evidence_quality != "observed":
            raise ContractError("Partial evidence cannot establish held")
        for ref in self.evidence_refs:
            require_text(ref, "evidence_refs")
