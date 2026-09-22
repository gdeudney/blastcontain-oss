"""Pure resolution over explicit data. No probing, model calls or worker execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..contracts import AcceptanceRecord, ContractError, ScenarioSpec
from ..contracts.plugins import Role, artifact_digest
from ..contracts.wire import WireRecord, unique
from ..plugins.catalog import check_acceptance, check_profile, review_digest
from .artifacts import digest
from .catalog import Binding, Catalog, RuntimeProbe
from .schema import SuiteSpec, normalized

MAX_CASES = 10_000


def latest(records, kind, subject_id) -> AcceptanceRecord | None:
    return next(
        (r for r in reversed(tuple(records)) if r.kind == kind and r.subject_id == subject_id), None
    )


def accepted(records, kind, subject_id, content_digest) -> AcceptanceRecord:
    record = latest(records, kind, subject_id)
    if record is None or record.decision != "accepted":
        raise ContractError(f"{kind} has no current acceptance")
    if record.artifact_digest != content_digest:
        raise ContractError(f"{kind} acceptance is stale: content changed")
    if record.granted_access:
        raise ContractError(f"{kind} acceptance cannot grant plugin access")
    return record


@dataclass(frozen=True)
class Identity(WireRecord):
    id: str
    kind: Literal["builtin_source", "external_source", "builtin_binding", "plugin"]
    revision: str
    artifact_digest: str
    content_digest: str

    def validate(self):
        artifact_digest(self.artifact_digest)
        artifact_digest(self.content_digest)


@dataclass(frozen=True)
class PlannedCase(WireRecord):
    id: str
    selection_id: str
    source_id: str
    scenario_id: str
    seed: int
    required: bool
    strategy: str | None
    scenario: ScenarioSpec | None
    disposition: Literal["ready", "blocked", "excluded"]
    diagnostics: tuple[str, ...] = ()

    def validate(self):
        artifact_digest(self.id)
        if self.scenario is not None and self.scenario.id != self.scenario_id:
            raise ContractError("Case scenario ID does not match its snapshot")
        if not 0 <= self.seed <= 2**32 - 1:
            raise ContractError("Invalid case seed")
        if self.disposition == "ready" and (self.scenario is None or self.diagnostics):
            raise ContractError("Ready case must have a scenario and no blockers")
        if self.disposition != "ready" and not self.diagnostics:
            raise ContractError("Blocked/excluded cases require a reason")
        if self.disposition == "excluded" and self.required:
            raise ContractError("Required cases cannot be excluded")


@dataclass(frozen=True)
class ResolvedPlan(WireRecord):
    spec: SuiteSpec
    identities: tuple[Identity, ...]
    cases: tuple[PlannedCase, ...]
    diagnostics: tuple[str, ...] = ()
    schema_version: Literal[1] = 1

    def validate(self):
        if not self.cases or len(self.cases) > MAX_CASES:
            raise ContractError("Plan must contain 1 to 10000 cases")
        unique(tuple(c.id for c in self.cases), "case IDs")
        unique(tuple((i.kind, i.id) for i in self.identities), "identities")

    @property
    def ready(self):
        return (
            not self.diagnostics
            and any(c.disposition == "ready" for c in self.cases)
            and not any(c.disposition == "blocked" for c in self.cases)
        )

    @property
    def content_digest(self):
        return digest(self.to_dict())


def requirements(scenario: ScenarioSpec):
    # Derive intrinsic requirements even if an untrusted snapshot omits declarations.
    capabilities = set(scenario.required_capabilities)
    capabilities.add("prompt.multiturn" if scenario.turns else "prompt.single")
    capabilities.update(f"inject.{i.surface}" for i in scenario.injections)
    observations = {"model_output", *scenario.required_observations}
    if scenario.security.goal != "content":
        observations.add("tool_actions")
    if any(i.surface.startswith("mcp_") for i in scenario.injections):
        observations.add("payload_delivery")
    return capabilities, observations


def plan_suite(spec: SuiteSpec, catalog: Catalog, *, records=(), probes=()) -> ResolvedPlan:
    spec = normalized(spec)
    records = tuple(records)
    probes = tuple(probes)
    unique(tuple(p.plugin_id for p in probes), "runtime probe IDs")
    sources = {s.id: s.ordered() for s in catalog.sources}
    bindings = {b.id: b for b in catalog.bindings}
    plugins = {p.id: p for p in catalog.plugins}
    probe_map: dict[str, RuntimeProbe] = {p.plugin_id: p for p in probes}
    identities: dict[tuple[str, str], Identity] = {}
    channels = {m.channel for m in spec.models}
    config_digest = digest(spec.to_dict())

    def resolve_binding(binding_id: str, role: Role):
        errors = []
        if binding_id in bindings:
            binding = bindings[binding_id]
            identities[("binding", binding_id)] = Identity(
                binding_id,
                "builtin_binding",
                "build",
                binding.artifact_digest,
                digest(binding.to_dict()),
            )
            if binding.role != role:
                errors.append(f"{binding_id}: role mismatch (requires {role})")
            if spec.target.kind not in binding.target_kinds:
                errors.append(f"{binding_id}: unsupported target kind")
            if binding.model_channel is not None and binding.model_channel not in channels:
                errors.append(f"{binding_id}: missing {binding.model_channel} model settings")
            return binding, errors
        plugin = plugins.get(binding_id)
        if plugin is None:
            return None, [f"{binding_id}: missing binding/plugin"]
        identities[("plugin", binding_id)] = Identity(
            binding_id, "plugin", plugin.version, plugin.artifact_digest, review_digest(plugin)
        )
        if role not in plugin.roles:
            errors.append(f"{binding_id}: role mismatch (requires {role})")
        # The current worker protocol exposes propose only. Metadata cannot invent adapters.
        if role != "attack_strategy":
            errors.append(f"{binding_id}: current worker supports attack_strategy only")
        for channel in ("attacker", "evaluator"):
            if (
                any(
                    g == f"broker.{channel}" or g.startswith(f"broker.{channel}.")
                    for g in plugin.access_requests
                )
                and channel not in channels
            ):
                errors.append(f"{binding_id}: missing {channel} model settings")
        try:
            check_profile(plugin)
            check_acceptance(plugin, records)
        except ContractError as exc:
            errors.append(f"{binding_id}: {exc}")
        probe = probe_map.get(binding_id)
        if probe is None or not probe.available or probe.artifact_digest != plugin.artifact_digest:
            errors.append(f"{binding_id}: matching available runtime probe required")
        binding = Binding(plugin.id, role, plugin.artifact_digest, plugin.capabilities)
        return binding, errors

    target, common = resolve_binding(spec.target.binding, "target")
    environment, problems = resolve_binding(spec.environment, "environment")
    common += problems
    evaluators = []
    for evaluator_id in spec.evaluators:
        evaluator, problems = resolve_binding(evaluator_id, "evaluator")
        common += problems
        if evaluator is not None:
            evaluators.append(evaluator)
    capabilities = set(target.capabilities if target else ()) | set(
        environment.capabilities if environment else ()
    )
    observations = set(environment.observations if environment else ())
    evaluator_caps = {c for e in evaluators for c in e.capabilities}
    cases: list[PlannedCase] = []
    selected = set()
    for selection in spec.selections:
        errors = list(common)
        source = sources.get(selection.source)
        scenarios = {}
        if source is None:
            errors.append(f"{selection.source}: missing source snapshot")
        else:
            scenarios = {s.id: s for s in source.scenarios}
            builtin = source.id in catalog.builtin_sources
            identities[("source", source.id)] = Identity(
                source.id,
                "builtin_source" if builtin else "external_source",
                source.revision,
                source.code_digest,
                source.content_digest,
            )
            if source.revision.strip().lower() in ("unknown", "latest", "main", "head"):
                errors.append(f"{source.id}: source revision is not pinned")
            if not builtin:
                try:
                    accepted(records, "content", source.id, source.content_digest)
                except ContractError as exc:
                    errors.append(f"{source.id}: {exc}")
        strategy = None
        if selection.strategy is not None:
            strategy, problems = resolve_binding(selection.strategy, "attack_strategy")
            errors += problems
        ids = sorted(scenarios) if selection.scenarios == ("*",) else selection.scenarios
        if not ids:
            ids = ("*",)
        if len(cases) + len(ids) * len(spec.seeds) > MAX_CASES:
            raise ContractError("Suite expands beyond 10000 cases")
        for scenario_id in ids:
            key = (selection.source, scenario_id, selection.strategy)
            if key in selected:
                raise ContractError("Duplicate scenario selection; use seeds for repetitions")
            selected.add(key)
            scenario = scenarios.get(scenario_id)
            case_errors = list(errors)
            if scenario is None:
                case_errors.append(f"{selection.source}/{scenario_id}: selection has no scenario")
            else:
                required_caps, required_obs = requirements(scenario)
                if required_caps - capabilities:
                    case_errors.append(
                        f"Missing capabilities: {sorted(required_caps - capabilities)}"
                    )
                if required_obs - observations:
                    case_errors.append(
                        f"Missing observations: {sorted(required_obs - observations)}"
                    )
                mcp = any(i.surface.startswith("mcp_") for i in scenario.injections)
                if spec.target.kind == "mcp" and not mcp:
                    case_errors.append("MCP target requires a controlled MCP poisoning scenario")
                if scenario.fixture_refs or scenario.task_checks:
                    case_errors.append(
                        "Fixture/task-check adapters are not registered in this milestone"
                    )
                if scenario.security.goal == "content":
                    axis = (
                        scenario.security.rubric.axis
                        if scenario.security.rubric
                        else ("harm" if scenario.security.expected_refusal else "refusal")
                    )
                    if f"rubric.{axis}" not in evaluator_caps:
                        case_errors.append(f"No evaluator supports rubric.{axis}")
                    for evaluator in evaluators:
                        if f"rubric.{axis}" not in evaluator.capabilities:
                            case_errors.append(f"{evaluator.id}: cannot assess rubric.{axis}")
                if scenario.layer == "generative" and selection.strategy is None:
                    case_errors.append("Generative scenario requires an attack strategy")
                if strategy is not None:
                    if not scenario.attack_objective:
                        case_errors.append(
                            "Adaptive strategy requires an explicit attack objective"
                        )
                    surface = "prompt.multiturn" if scenario.turns else "prompt.single"
                    if surface not in strategy.capabilities:
                        case_errors.append(f"Strategy does not support {surface}")
            for seed in spec.seeds:
                case_id = digest(
                    {
                        "config": config_digest,
                        "selection": selection.id,
                        "scenario": scenario_id,
                        "scenario_digest": digest(scenario.to_dict()) if scenario else None,
                        "seed": seed,
                    }
                )
                cases.append(
                    PlannedCase(
                        case_id,
                        selection.id,
                        selection.source,
                        scenario_id,
                        seed,
                        selection.required,
                        selection.strategy,
                        scenario,
                        "ready"
                        if not case_errors
                        else ("blocked" if selection.required else "excluded"),
                        tuple(sorted(set(case_errors))),
                    )
                )
                if len(cases) > MAX_CASES:
                    raise ContractError("Suite expands beyond 10000 cases")
    return ResolvedPlan(
        spec, tuple(sorted(identities.values(), key=lambda i: (i.kind, i.id))), tuple(cases)
    )
