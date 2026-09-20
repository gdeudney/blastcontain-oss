"""Explicit trusted built-ins and materialized external data; no plugin entry points."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Literal

from ..contracts import ContractError, PluginManifest, ScenarioSpec
from ..contracts.plugins import Role, artifact_digest
from ..contracts.wire import WireRecord, require_text, unique
from .artifacts import digest
from .schema import reference


@dataclass(frozen=True)
class SourceSnapshot(WireRecord):
    id: str
    revision: str
    code_digest: str
    scenarios: tuple[ScenarioSpec, ...]
    schema_version: Literal[1] = 1

    def validate(self):
        reference(self.id)
        require_text(self.revision, "source revision")
        artifact_digest(self.code_digest)
        unique(tuple(s.id for s in self.scenarios), "source scenario IDs")
        for scenario in self.scenarios:
            if scenario.source.name != self.id or scenario.source.revision != self.revision:
                raise ContractError("Scenario source must match its snapshot")

    def ordered(self):
        return replace(self, scenarios=tuple(sorted(self.scenarios, key=lambda s: s.id)))

    @property
    def content_digest(self):
        return digest(self.ordered().to_dict())


@dataclass(frozen=True)
class Binding(WireRecord):
    id: str
    role: Role
    artifact_digest: str
    capabilities: tuple[str, ...] = ()
    observations: tuple[str, ...] = ()
    target_kinds: tuple[Literal["agent", "mcp"], ...] = ("agent", "mcp")
    model_channel: Literal["target", "attacker", "evaluator"] | None = None

    def validate(self):
        reference(self.id)
        artifact_digest(self.artifact_digest)
        for name in ("capabilities", "observations", "target_kinds"):
            unique(getattr(self, name), name)


@dataclass(frozen=True)
class RuntimeProbe(WireRecord):
    """Operator-supplied observation, not proof of current isolation/availability."""

    plugin_id: str
    artifact_digest: str
    available: bool
    observed_at: str
    profile: Literal["linux-rootless-podman-v1"] = "linux-rootless-podman-v1"
    schema_version: Literal[1] = 1

    def validate(self):
        reference(self.plugin_id)
        artifact_digest(self.artifact_digest)
        try:
            timestamp = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError("Probe time must be ISO 8601") from exc
        if timestamp.tzinfo is None:
            raise ContractError("Probe time requires a timezone")


@dataclass(frozen=True)
class Catalog:
    sources: tuple[SourceSnapshot, ...]
    bindings: tuple[Binding, ...]
    plugins: tuple[PluginManifest, ...] = ()
    builtin_sources: frozenset[str] = frozenset()

    def __post_init__(self):
        unique(tuple(s.id for s in self.sources), "catalog source IDs")
        unique(
            tuple(b.id for b in self.bindings) + tuple(p.id for p in self.plugins),
            "catalog binding/plugin IDs",
        )
        if not self.builtin_sources <= {s.id for s in self.sources}:
            raise ContractError("Unknown trusted built-in source")


def build_digest() -> str:
    """Hash installed Drill/Core Python and vendored CSV bytes, independent of checkout path.

    This pins editable builds too; package versions alone do not identify their code.
    Exclude inert Scout proposals and bytecode. Never invoke git or a package manager.
    """
    import blastcontain_core

    roots = (Path(__file__).parents[1], Path(blastcontain_core.__file__).parent)
    files = []
    for root in roots:
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if path.suffix not in (".py", ".csv") or "contrib" in relative.parts:
                continue
            if path.is_symlink():
                raise ContractError("Built-in code cannot use symlinked artifacts")
            files.append(
                (
                    root.name + "/" + relative.as_posix(),
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                )
            )
    return digest(files)


def builtin_catalog(*, external_sources=(), plugins=()) -> Catalog:
    # Explicit model-free classes. Do not use load_corpus, discovery or is_available.
    from ..contracts.legacy import LegacySourceAdapter
    from ..corpus import (
        BuiltinReplaySource,
        JailbreakBenchSource,
        MultiTurnSource,
        OperatorsSource,
        SystemCardSource,
        MCPPoisoningSource,
    )

    code = build_digest()
    sources = tuple(
        SourceSnapshot(
            "builtin" if isinstance(source, BuiltinReplaySource) else source.name,
            source.revision,
            code,
            tuple(LegacySourceAdapter(source).scenarios()),
        ).ordered()
        for source in (
            BuiltinReplaySource(),
            JailbreakBenchSource(),
            MultiTurnSource(),
            OperatorsSource(),
            SystemCardSource(),
            MCPPoisoningSource(),
        )
    )
    prompt_caps = ("prompt.single", "prompt.multiturn")
    inject_caps = ("inject.document", "inject.mcp_description", "inject.mcp_response")
    bindings = (
        Binding("builtin.target.resistant", "target", code, prompt_caps),
        Binding("builtin.target.vulnerable", "target", code, prompt_caps),
        Binding("builtin.target.llm", "target", code, prompt_caps, model_channel="target"),
        # These are capability descriptions for future suite execution, not runtime grants.
        Binding(
            "builtin.environment.fixture",
            "environment",
            code,
            inject_caps,
            ("model_output", "tool_actions", "payload_delivery"),
        ),
        Binding(
            "builtin.evaluator.heuristic", "evaluator", code, ("rubric.harm", "rubric.refusal")
        ),
        Binding(
            "builtin.strategy.pair",
            "attack_strategy",
            code,
            ("prompt.single",),
            model_channel="attacker",
        ),
    )
    return Catalog(
        sources + tuple(external_sources),
        bindings,
        tuple(plugins),
        frozenset(s.id for s in sources),
    )
