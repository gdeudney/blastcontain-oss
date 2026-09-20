"""Scenario contract: task, adversarial inputs and evidence requirements are separate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .wire import ContractError, WireRecord, require_text, unique

Surface = Literal["user", "document", "mcp_description", "mcp_response", "memory"]
GoalKind = Literal["content", "exfil_canary", "forbidden_tool", "egress"]
RubricAxis = Literal["harm", "refusal", "freeform"]
Layer = Literal["replay", "operators", "generative"]
Vector = Literal["direct", "indirect"]


@dataclass(frozen=True)
class SourceRef(WireRecord):
    name: str
    revision: str = "unknown"
    paper_ids: tuple[str, ...] = ()

    def validate(self):
        require_text(self.name, "source name")
        require_text(self.revision, "source revision")
        unique(self.paper_ids, "paper_ids")
        for paper_id in self.paper_ids:
            require_text(paper_id, "paper_ids")


@dataclass(frozen=True)
class Injection(WireRecord):
    surface: Surface
    payload: str


@dataclass(frozen=True)
class ContentRubric(WireRecord):
    question: str
    axis: RubricAxis
    on_match: Literal["BYPASS", "HELD", "OVER_REFUSAL", "ERROR"]
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def validate(self):
        require_text(self.question, "rubric question")


@dataclass(frozen=True)
class SecurityExpectation(WireRecord):
    goal: GoalKind
    expected_refusal: bool = True
    forbidden_tool: str | None = None
    rubric: ContentRubric | None = None


@dataclass(frozen=True)
class ScenarioSpec(WireRecord):
    id: str
    category: str
    technique: str
    source: SourceRef
    entry_prompt: str
    security: SecurityExpectation
    # None means the legacy case defines no independent legitimate task.
    legitimate_task: str | None = None
    attack_objective: str | None = None
    turns: tuple[str, ...] | None = None
    injections: tuple[Injection, ...] = ()
    fixture_refs: tuple[str, ...] = ()
    task_checks: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()
    required_observations: tuple[str, ...] = ()
    layer: Layer = "replay"
    vector: Vector = "direct"
    schema_version: Literal[1] = 1

    def validate(self):
        for name in ("id", "category", "technique"):
            require_text(getattr(self, name), name)
        for name in ("legitimate_task", "attack_objective"):
            if getattr(self, name) is not None:
                require_text(getattr(self, name), name)
        unique(tuple(x.surface for x in self.injections), "injection surfaces")
        for name in (
            "fixture_refs",
            "task_checks",
            "required_capabilities",
            "required_observations",
        ):
            values = getattr(self, name)
            unique(values, name)
            for value in values:
                require_text(value, name)
        if self.task_checks and not self.legitimate_task:
            raise ContractError("Task checks require a legitimate task")


@dataclass(frozen=True)
class AttackFeedback(WireRecord):
    prompt: str
    outcome: str
    target_response: str
    fired: tuple[str, ...] = ()


@dataclass(frozen=True)
class StrategyContext(WireRecord):
    scenario: ScenarioSpec
    history: tuple[AttackFeedback, ...] = ()
    schema_version: Literal[1] = 1

    def validate(self):
        if not self.scenario.attack_objective:
            raise ContractError("Adaptive strategy requires an explicit attack objective")
