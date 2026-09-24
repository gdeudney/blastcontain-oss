"""Lossless adapters for existing code; no plugin loading or runtime-policy changes."""

from __future__ import annotations

from typing import cast

from blastcontain_core.models import DrillOutcome, Severity

from ..cage.base import Cage
from ..corpus.base import Attack, Rubric
from ..generative.attacker import Attacker, Attempt
from ..generative.goals import Goal
from ..scoring.base import Scorer
from .scenario import (
    ContentRubric,
    GoalKind,
    Injection,
    Layer,
    RubricAxis,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
    Surface,
    Vector,
)
from .wire import ContractError

_PAYLOAD_FIELDS: dict[Surface, str] = {
    "document": "poisoned_document",
    "mcp_description": "mcp_tool_description",
    "mcp_response": "mcp_tool_response",
}


def scenario_from_attack(attack: Attack, revision="unknown") -> ScenarioSpec:
    # Legacy fields are typed as str; the strict record constructors validate
    # the literal values at runtime as well as documenting them to type checkers.
    rubric = attack.rubric
    injections = tuple(
        Injection(surface, getattr(attack, field))
        for surface, field in _PAYLOAD_FIELDS.items()
        if getattr(attack, field) is not None
    )
    capabilities = ["prompt.multiturn" if attack.turns else "prompt.single"]
    capabilities += [f"inject.{injection.surface}" for injection in injections]
    observations = ["model_output"]
    if attack.goal != "content":
        observations.append("tool_actions")
    if any(i.surface.startswith("mcp_") for i in injections):
        observations.append("payload_delivery")
    return ScenarioSpec(
        id=attack.id,
        category=attack.category,
        technique=attack.technique,
        source=SourceRef(attack.source, revision or "unknown"),
        entry_prompt=attack.prompt,
        security=SecurityExpectation(
            cast(GoalKind, attack.goal),
            attack.expected_refusal,
            attack.forbidden_tool,
            ContentRubric(
                rubric.question,
                cast(RubricAxis, rubric.axis),
                rubric.on_match.value,
                rubric.severity.value,
            )
            if rubric
            else None,
        ),
        turns=tuple(attack.turns) if attack.turns is not None else None,
        injections=injections,
        layer=cast(Layer, attack.layer),
        vector=cast(Vector, attack.vector),
        required_capabilities=tuple(capabilities),
        required_observations=tuple(observations),
    )


def attack_from_scenario(scenario: ScenarioSpec) -> Attack:
    if scenario.fixture_refs or scenario.task_checks:
        raise ContractError("Legacy execution cannot enforce new fixtures or task checks")
    unknown = {i.surface for i in scenario.injections} - _PAYLOAD_FIELDS.keys()
    if unknown:
        raise ContractError(
            f"Legacy execution does not support injection surfaces: {sorted(unknown)}"
        )
    rubric = scenario.security.rubric
    return Attack(
        id=scenario.id,
        category=scenario.category,
        prompt=scenario.entry_prompt,
        technique=scenario.technique,
        layer=scenario.layer,
        vector=scenario.vector,
        goal=scenario.security.goal,
        forbidden_tool=scenario.security.forbidden_tool,
        expected_refusal=scenario.security.expected_refusal,
        source=scenario.source.name,
        rubric=Rubric(
            rubric.question, rubric.axis, DrillOutcome(rubric.on_match), Severity(rubric.severity)
        )
        if rubric
        else None,
        turns=list(scenario.turns) if scenario.turns is not None else None,
        **{_PAYLOAD_FIELDS[i.surface]: i.payload for i in scenario.injections},
    )


class LegacySourceAdapter:
    def __init__(self, source):
        self.source = source

    def is_available(self):
        return self.source.is_available()

    def scenarios(self, categories=None, limit=None):
        return [
            scenario_from_attack(a, getattr(self.source, "revision", "") or "unknown")
            for a in self.source.dataset(categories=categories, limit=limit)
        ]


class LegacyCageAdapter(Cage):
    """Caller supplies explicit capabilities; unknown cages never gain them by inference."""

    def __init__(self, cage, *, capabilities, observations):
        self.cage = cage
        self.name = cage.name
        self.capabilities = frozenset(capabilities)
        self.observations = frozenset(observations)

    def execute(self, scenario: ScenarioSpec):
        attack = attack_from_scenario(scenario)
        # A hand-authored scenario cannot hide the requirements implied by its
        # payloads, turns and goal by leaving its declarations empty.
        intrinsic = scenario_from_attack(attack)
        required = set(scenario.required_capabilities) | set(intrinsic.required_capabilities)
        observations = set(scenario.required_observations) | set(intrinsic.required_observations)
        missing = required - self.capabilities
        missing_observations = observations - self.observations
        if missing or missing_observations:
            raise ContractError(
                f"Unsupported capabilities {sorted(missing)} or observations {sorted(missing_observations)}"
            )
        return self.cage.run_attack(attack)

    def run_attack(self, attack):
        return self.execute(scenario_from_attack(attack))

    def setup(self):
        return self.cage.setup()

    def teardown(self):
        return self.cage.teardown()


class LegacyStrategyAdapter(Attacker):
    """Preserve local abliterated/other attacker backends and their feedback unchanged.

    No new budget or isolation guarantee: those belong to the future broker/worker.
    """

    def __init__(self, attacker):
        self.attacker = attacker
        self.name = attacker.name

    def is_available(self):
        return self.attacker.is_available()

    def craft(self, goal, history):
        return self.attacker.craft(goal, history)

    def propose(self, context):
        scenario = context.scenario
        goal = Goal(
            scenario.id,
            scenario.category,
            scenario.attack_objective,
            scenario.security.goal,
            scenario.security.forbidden_tool,
        )
        history = [
            Attempt(h.prompt, h.outcome, h.target_response, list(h.fired)) for h in context.history
        ]
        return Injection("user", self.craft(goal, history))


class LegacyEvaluatorAdapter(Scorer):
    def __init__(self, scorer):
        self.scorer = scorer
        self.name = scorer.name
        self.axes = scorer.axes
        self.plane = scorer.plane

    def is_available(self):
        return self.scorer.is_available()

    def evaluate(self, scenario, response_text):
        return self.scorer.score(attack_from_scenario(scenario), response_text)

    def score(self, attack, response_text):
        return self.evaluate(scenario_from_attack(attack), response_text)
