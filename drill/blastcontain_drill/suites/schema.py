"""Strict, versioned suite inputs; no arbitrary configuration or credential values."""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
import re
from typing import Literal
from urllib.parse import urlsplit

from ..contracts import ContractError
from ..contracts.plugins import artifact_digest
from ..contracts.wire import WireRecord, unique


def reference(value: str) -> None:
    # References are labels resolved by future trusted bindings, never URLs or paths.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise ContractError(
            "Expected a symbolic reference (letters, digits, dot, dash, underscore)"
        )


def positive(value: int, name: str, maximum: int = 1_000_000_000) -> None:
    if not 1 <= value <= maximum:
        raise ContractError(f"{name} must be between 1 and {maximum}")


@dataclass(frozen=True)
class Limits(WireRecord):
    model_calls: int = 20
    tool_steps: int = 40
    strategy_iterations: int = 4
    wall_seconds: int = 120
    artifact_bytes: int = 1_048_576

    def validate(self):
        for field in fields(self):
            positive(getattr(self, field.name), field.name)


@dataclass(frozen=True)
class ModelSettings(WireRecord):
    channel: Literal["target", "attacker", "evaluator"]
    endpoint_url: str
    model_ref: str
    # Alias means live responses are not reproducible even with a fixed seed.
    identity: Literal["alias", "pinned"] = "alias"
    model_digest: str | None = None
    credential_ref: str | None = None
    temperature: float = 0.0
    max_output_tokens: int = 512

    @classmethod
    def from_dict(cls, data):
        # JSON has one number type; browsers serialize 0.0 as 0. Normalize only
        # this numeric field, preserving strict integer budgets and boolean rejection.
        if type(data) is dict and type(data.get("temperature")) is int:
            if not 0 <= data["temperature"] <= 2:
                raise ContractError("temperature must be in [0, 2]")
            data = {**data, "temperature": float(data["temperature"])}
        return super().from_dict(data)

    def validate(self):
        # Provider model IDs commonly include organization/name and tag suffixes.
        # They are JSON values, never paths or command arguments. Credential aliases
        # remain symbolic references resolved only by the host.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}", self.model_ref):
            raise ContractError("Expected a provider model ID of at most 256 safe characters")
        if self.credential_ref is not None:
            reference(self.credential_ref)
        try:
            endpoint = urlsplit(self.endpoint_url)
            if (
                endpoint.scheme not in ("http", "https")
                or not endpoint.hostname
                or endpoint.username is not None
                or endpoint.password is not None
                or endpoint.query
                or endpoint.fragment
                or "?" in self.endpoint_url
                or "#" in self.endpoint_url
                or not endpoint.netloc
                or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in self.endpoint_url)
                or "\\" in self.endpoint_url
                or "%" in self.endpoint_url
            ):
                raise ValueError
            _ = endpoint.port
        except ValueError as exc:
            # Do not echo a rejected URL that might contain credentials.
            raise ContractError(
                "Expected HTTP(S) endpoint without credentials, query or fragment"
            ) from exc
        if self.identity == "pinned":
            if self.model_digest is None:
                raise ContractError("Pinned model identity requires a digest")
            artifact_digest(self.model_digest)
        elif self.model_digest is not None:
            raise ContractError("An alias cannot claim a pinned model digest")
        if not 0 <= self.temperature <= 2:
            raise ContractError("temperature must be in [0, 2]")
        positive(self.max_output_tokens, "max_output_tokens", 1_000_000)


@dataclass(frozen=True)
class TargetSpec(WireRecord):
    kind: Literal["agent", "mcp"]
    binding: str

    def validate(self):
        reference(self.binding)


@dataclass(frozen=True)
class Selection(WireRecord):
    id: str
    source: str
    # Explicit IDs or exactly ["*"]. Never infer a successful empty selection.
    scenarios: tuple[str, ...]
    required: bool = True
    strategy: str | None = None

    def validate(self):
        reference(self.id)
        reference(self.source)
        if not self.scenarios:
            raise ContractError("Selection must name scenarios or '*'")
        unique(self.scenarios, "scenario selectors")
        if "*" in self.scenarios and self.scenarios != ("*",):
            raise ContractError("Wildcard must be the only selector")
        for value in self.scenarios:
            if not value.strip() or len(value) > 256:
                raise ContractError("Scenario selector must be nonempty and at most 256 characters")
        if self.strategy is not None:
            reference(self.strategy)


@dataclass(frozen=True)
class SuiteSpec(WireRecord):
    id: str
    target: TargetSpec
    environment: str
    evaluators: tuple[str, ...]
    selections: tuple[Selection, ...]
    models: tuple[ModelSettings, ...] = ()
    seeds: tuple[int, ...] = (0,)
    concurrency: int = 1
    global_limits: Limits = Limits(200, 400, 40, 1200, 10_485_760)
    case_limits: Limits = Limits()
    schema_version: Literal[1] = 1

    def validate(self):
        reference(self.id)
        reference(self.environment)
        if not self.evaluators or not self.selections or not self.seeds:
            raise ContractError("Suite needs evaluators, selections and seeds")
        unique(self.evaluators, "evaluators")
        unique(tuple(s.id for s in self.selections), "selection IDs")
        unique(tuple(m.channel for m in self.models), "model channels")
        unique(self.seeds, "seeds")
        for value in self.evaluators:
            reference(value)
        for seed in self.seeds:
            if not 0 <= seed <= 2**32 - 1:
                raise ContractError("Seeds must be unsigned 32-bit integers")
        positive(self.concurrency, "concurrency", 64)
        for field in fields(Limits):
            if getattr(self.case_limits, field.name) > getattr(self.global_limits, field.name):
                raise ContractError(f"Per-case {field.name} exceeds global limit")
        if len(self.selections) > 1000 or len(self.seeds) > 1000:
            raise ContractError("At most 1000 selections and 1000 seeds are supported")


def normalized(spec: SuiteSpec) -> SuiteSpec:
    """Only set-like inputs are sorted. Prompt turns and acceptance history are ordered."""
    return replace(
        spec,
        evaluators=tuple(sorted(spec.evaluators)),
        selections=tuple(
            replace(item, scenarios=tuple(sorted(item.scenarios)))
            for item in sorted(spec.selections, key=lambda item: item.id)
        ),
        models=tuple(sorted(spec.models, key=lambda item: item.channel)),
        seeds=tuple(sorted(spec.seeds)),
    )
