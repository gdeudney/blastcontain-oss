"""Typed collector records. Legacy EvidenceEvent/Trace v1 transports remain unchanged."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..contracts import ContractError
from ..contracts.plugins import artifact_digest
from ..contracts.wire import WireRecord, require_text, unique
from ..suites.artifacts import digest

Channel = Literal["model_output", "tool_actions", "payload_delivery"]
Axis = Literal["harm", "refusal", "freeform"]
DeliverySurface = Literal["document", "mcp_description", "mcp_response", "memory"]
Reason = Literal[
    "completed",
    "step_limit",
    "backend_error",
    "fixture_error",
    "tool_error",
    "unknown_completion",
    "unexercised",
    "cancelled",
    "unsupported",
    "collector_error",
]
Violation = Literal["canary_exfil", "forbidden_tool", "egress_attempt"]


@dataclass(frozen=True)
class Producer(WireRecord):
    id: str
    role: Literal["runtime", "environment", "evaluator", "plugin"]
    scope: Literal["host", "simulation", "container", "independent", "claim"]
    observations: tuple[Channel, ...] = ()
    axes: tuple[Axis, ...] = ()
    task_checks: tuple[str, ...] = ()

    def validate(self):
        require_text(self.id, "producer ID")
        if len(self.id) > 128:
            raise ContractError("Producer ID exceeds 128 characters")
        for name in ("observations", "axes", "task_checks"):
            unique(getattr(self, name), name)
        if self.role != "environment" and self.observations:
            raise ContractError("Only environment producers supply observation coverage")
        if self.role != "evaluator" and (self.axes or self.task_checks):
            raise ContractError("Only evaluator producers supply assessments")
        if (self.role == "plugin") != (self.scope == "claim"):
            raise ContractError("Plugins have claim scope only")
        if self.scope == "independent" and self.role != "environment":
            raise ContractError("Independent effects require an environment observer")


@dataclass(frozen=True)
class Started(WireRecord):
    kind: Literal["started"] = "started"


@dataclass(frozen=True)
class Output(WireRecord):
    text_digest: str
    characters: int
    kind: Literal["output"] = "output"

    def validate(self):
        artifact_digest(self.text_digest)
        if self.characters < 0:
            raise ContractError("Negative output size")


@dataclass(frozen=True)
class Delivery(WireRecord):
    surface: DeliverySurface
    payload_digest: str
    delivered: bool
    kind: Literal["delivery"] = "delivery"

    def validate(self):
        artifact_digest(self.payload_digest)


@dataclass(frozen=True)
class Coverage(WireRecord):
    channels: tuple[Channel, ...]
    complete: bool
    kind: Literal["coverage"] = "coverage"

    def validate(self):
        if not self.channels:
            raise ContractError("Coverage must identify an observation channel")
        unique(self.channels, "coverage channels")


@dataclass(frozen=True)
class Action(WireRecord):
    action_id: str
    violations: tuple[Violation, ...]
    blocked: bool | None = None
    kind: Literal["action"] = "action"

    def validate(self):
        require_text(self.action_id, "action ID")
        if not self.violations:
            raise ContractError("Action requires a policy violation")
        unique(self.violations, "violations")


@dataclass(frozen=True)
class Effect(WireRecord):
    action_ref: str
    artifact_refs: tuple[str, ...]
    kind: Literal["effect"] = "effect"

    def validate(self):
        require_text(self.action_ref, "action reference")
        if not self.artifact_refs:
            raise ContractError("Independent effect requires retained proof artifacts")
        unique(self.artifact_refs, "artifact references")


@dataclass(frozen=True)
class Evaluation(WireRecord):
    axis: Axis
    matched: bool | None
    output_refs: tuple[str, ...]
    kind: Literal["evaluation"] = "evaluation"

    def validate(self):
        if not self.output_refs:
            raise ContractError("Evaluation requires observed output references")
        unique(self.output_refs, "output references")


@dataclass(frozen=True)
class TaskCheck(WireRecord):
    check_id: str
    passed: bool | None
    evidence_refs: tuple[str, ...]
    kind: Literal["task_check"] = "task_check"

    def validate(self):
        require_text(self.check_id, "task check")
        if not self.evidence_refs:
            raise ContractError("Task check requires observed evidence")
        unique(self.evidence_refs, "task evidence")


@dataclass(frozen=True)
class Error(WireRecord):
    reason: Literal["backend_error", "fixture_error", "tool_error", "collector_error"]
    kind: Literal["error"] = "error"


@dataclass(frozen=True)
class Terminal(WireRecord):
    reason: Reason
    kind: Literal["terminal"] = "terminal"


@dataclass(frozen=True)
class Claim(WireRecord):
    content_digest: str
    size_bytes: int
    kind: Literal["claim"] = "claim"

    def validate(self):
        artifact_digest(self.content_digest)
        if self.size_bytes < 0:
            raise ContractError("Negative claim size")


Payload = (
    Started
    | Output
    | Delivery
    | Coverage
    | Action
    | Effect
    | Evaluation
    | TaskCheck
    | Error
    | Terminal
    | Claim
)


@dataclass(frozen=True)
class EvidenceRecord(WireRecord):
    sequence: int
    emitter: str
    payload: Payload
    schema_version: Literal[1] = 1

    def validate(self):
        require_text(self.emitter, "emitter")
        if self.sequence < 0:
            raise ContractError("Negative sequence")


@dataclass(frozen=True)
class ArtifactRef(WireRecord):
    digest: str
    case_id: str
    scenario_digest: str
    emitter: str
    size_bytes: int

    def validate(self):
        artifact_digest(self.digest)
        artifact_digest(self.scenario_digest)
        for name in ("case_id", "emitter"):
            require_text(getattr(self, name), name)
        if self.size_bytes < 0:
            raise ContractError("Negative artifact size")


@dataclass(frozen=True)
class EvidenceBundle(WireRecord):
    case_id: str
    scenario_digest: str
    producers: tuple[Producer, ...]
    records: tuple[EvidenceRecord, ...]
    artifacts: tuple[ArtifactRef, ...] = ()
    truncated: bool = False
    schema_version: Literal[1] = 1

    def validate(self):
        require_text(self.case_id, "case ID")
        artifact_digest(self.scenario_digest)
        if len(self.producers) > 128 or len(self.records) > 10000:
            raise ContractError("Evidence bundle exceeds record/producer limits")
        unique(tuple(p.id for p in self.producers), "producer IDs")
        unique(tuple(a.digest for a in self.artifacts), "artifact digests")
        for a in self.artifacts:
            if (a.case_id, a.scenario_digest) != (self.case_id, self.scenario_digest):
                raise ContractError("Artifact belongs to another case/scenario")

    def reference(self, sequence: int) -> str:
        scope = digest({"case": self.case_id, "scenario": self.scenario_digest})[7:]
        return f"evidence:{scope}:{sequence}"


@dataclass(frozen=True)
class EvidenceReceipt:
    """Trusted host anchor, supplied separately for replay; never read from a plugin bundle.

    Persistence/authentication of receipts belongs to the later signed run envelope.
    Whoever can replace this anchor controls trust; a hash supplied alongside an
    untrusted bundle does not authenticate that bundle.
    """

    case_id: str
    scenario_digest: str
    bundle_digest: str

    def __post_init__(self):
        require_text(self.case_id, "case ID")
        artifact_digest(self.scenario_digest)
        artifact_digest(self.bundle_digest)
