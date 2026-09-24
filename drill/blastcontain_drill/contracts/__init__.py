"""Version 1 contracts for the incremental Drill suite redesign.

Data definitions only: importing this package discovers or executes no plugins.
"""

from .evidence import EvidenceEvent, EvidenceTrace, ScenarioResult
from .plugins import (
    AcceptanceRecord,
    AttackStrategy,
    Environment,
    Evaluator,
    Lifecycle,
    PluginManifest,
    ScenarioSource,
    Target,
)
from .scenario import (
    AttackFeedback,
    ContentRubric,
    Injection,
    ScenarioSpec,
    SecurityExpectation,
    SourceRef,
    StrategyContext,
)
from .wire import ContractError

__all__ = [
    "AcceptanceRecord",
    "ContentRubric",
    "ContractError",
    "EvidenceEvent",
    "EvidenceTrace",
    "Injection",
    "Lifecycle",
    "PluginManifest",
    "ScenarioResult",
    "ScenarioSpec",
    "SecurityExpectation",
    "SourceRef",
    "AttackFeedback",
    "StrategyContext",
    "AttackStrategy",
    "Environment",
    "Evaluator",
    "ScenarioSource",
    "Target",
]
