"""Serial pre-dispatch accounting shared by the suite and its current case."""

from dataclasses import dataclass
import time
from typing import Literal

from ..contracts import ContractError
from ..contracts.wire import WireRecord
from .schema import Limits

Resource = Literal["model_calls", "tool_steps", "strategy_iterations", "artifact_bytes"]
RESOURCES = ("model_calls", "tool_steps", "strategy_iterations", "artifact_bytes")


@dataclass(frozen=True)
class Usage(WireRecord):
    model_calls: int = 0
    tool_steps: int = 0
    strategy_iterations: int = 0
    artifact_bytes: int = 0

    def validate(self):
        if any(getattr(self, name) < 0 for name in RESOURCES):
            raise ContractError("Usage cannot be negative")


class BudgetExceeded(RuntimeError):
    def __init__(self, scope, resource):
        self.scope, self.resource = scope, resource
        super().__init__(f"budget:{scope}:{resource}")


class Ledger:
    """One active case, no refunds or implicit retries. Wall time includes setup/cleanup."""

    def __init__(self, limits: Limits, *, clock=time.monotonic):
        self.limits, self.clock = limits, clock
        self.deadline = clock() + limits.wall_seconds
        self.total = dict.fromkeys(RESOURCES, 0)
        self.case: dict[str, int] | None = None
        self.case_limits: Limits | None = None
        self.case_deadline = self.deadline

    def begin(self, limits: Limits):
        if self.case is not None:
            raise ContractError("Serial ledger already has an active case")
        self.case = dict.fromkeys(RESOURCES, 0)
        self.case_limits = limits
        self.case_deadline = self.clock() + limits.wall_seconds

    def check_time(self):
        now = self.clock()
        if now >= self.deadline:
            raise BudgetExceeded("global", "wall_seconds")
        if now >= self.case_deadline:
            raise BudgetExceeded("case", "wall_seconds")

    def remaining(self):
        self.check_time()
        return min(self.deadline, self.case_deadline) - self.clock()

    def reserve(self, resource: Resource, amount=1):
        if resource not in RESOURCES or type(amount) is not int or amount < 1:
            raise ContractError("Invalid budget reservation")
        if self.case is None or self.case_limits is None:
            raise ContractError("Budget reservation requires an active case")
        self.check_time()
        # Check both before mutating either; denial must not replenish or overdraw.
        if self.total[resource] + amount > getattr(self.limits, resource):
            raise BudgetExceeded("global", resource)
        if self.case[resource] + amount > getattr(self.case_limits, resource):
            raise BudgetExceeded("case", resource)
        self.total[resource] += amount
        self.case[resource] += amount

    def end(self):
        if self.case is None:
            raise ContractError("No active case")
        usage = Usage(**self.case)
        self.case = self.case_limits = None
        return usage

    def usage(self):
        return Usage(**self.total)
