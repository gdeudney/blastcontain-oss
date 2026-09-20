"""Plugin and acceptance metadata, not a discovery or execution mechanism."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol

from .scenario import Injection, ScenarioSpec, StrategyContext
from .evidence import EvidenceTrace, ScenarioResult
from .wire import ContractError, WireRecord, require_text, unique

Role = Literal["scenario_source", "attack_strategy", "target", "environment", "evaluator"]


def artifact_digest(value):
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ContractError("Expected a pinned sha256 artifact digest")


@dataclass(frozen=True)
class PluginManifest(WireRecord):
    id: str
    version: str
    artifact_digest: str
    roles: tuple[Role, ...]
    capabilities: tuple[str, ...]
    license: str
    access_requests: tuple[str, ...] = ()
    notices: tuple[str, ...] = ()
    config_schema: dict[str, Any] = field(default_factory=dict)
    upstream: str | None = None
    adapter_api: Literal[1] = 1
    schema_version: Literal[1] = 1

    def validate(self):
        for name in ("id", "version", "license"):
            require_text(getattr(self, name), name)
        artifact_digest(self.artifact_digest)
        if not self.roles:
            raise ContractError("Plugin must declare at least one role")
        for name in ("roles", "capabilities", "access_requests", "notices"):
            values = getattr(self, name)
            unique(values, name)
            for value in values:
                require_text(value, name)


@dataclass(frozen=True)
class AcceptanceRecord(WireRecord):
    subject_id: str
    kind: Literal["plugin", "content", "suite"]
    artifact_digest: str
    actor: str
    decision: Literal["accepted", "rejected", "revoked"]
    recorded_at: str
    rationale: str
    granted_access: tuple[str, ...] = ()
    schema_version: Literal[1] = 1

    def validate(self):
        artifact_digest(self.artifact_digest)
        for name in ("subject_id", "actor", "rationale"):
            require_text(getattr(self, name), name)
        try:
            timestamp = datetime.fromisoformat(self.recorded_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError("Acceptance time must be ISO 8601") from exc
        if timestamp.tzinfo is None:
            raise ContractError("Acceptance time requires a timezone")
        unique(self.granted_access, "granted_access")
        for grant in self.granted_access:
            require_text(grant, "granted_access")


class Lifecycle(Protocol):
    """Future workers implement these hooks; declaring them grants no isolation."""

    def prepare(self, config: dict) -> None: ...
    def reset(self, scenario: ScenarioSpec) -> None: ...
    def cancel(self) -> None: ...
    def collect_evidence(self) -> EvidenceTrace: ...
    def close(self) -> None: ...


class ScenarioSource(Protocol):
    def scenarios(self, categories=None, limit=None) -> list[ScenarioSpec]: ...


class AttackStrategy(Protocol):
    def propose(self, context: StrategyContext) -> Injection: ...


class Target(Protocol):
    def send(self, injection: Injection) -> EvidenceTrace: ...


class Environment(Lifecycle, Protocol):
    def execute(self, scenario: ScenarioSpec) -> EvidenceTrace: ...


class Evaluator(Protocol):
    def evaluate(self, scenario: ScenarioSpec, evidence: EvidenceTrace) -> ScenarioResult: ...
