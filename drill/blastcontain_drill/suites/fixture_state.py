"""Snapshots of the fixed synthetic Agent fixture, never live external resources.

Only trusted fixture code creates/imports this state. A plugin receives opaque
handles and cannot submit messages, tool logs, canaries or filesystem snapshots.
"""

from dataclasses import asdict, dataclass
from typing import Any, Literal

from ..cage.agent import Toolbox, _SYSTEM_PROMPT
from ..cage.base import EgressAttempt, ToolCall
from ..cage.inprocess import new_canary
from ..contracts import ContractError
from ..contracts.wire import WireRecord
from .artifacts import canonical, digest

MAX_STATE = 131072


@dataclass(frozen=True)
class FixtureMessage(WireRecord):
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True)
class FixtureToolCall(WireRecord):
    tool: str
    arguments: dict[str, Any]
    blocked: bool
    blocked_reason: str | None
    result: str | None


@dataclass(frozen=True)
class FixtureEgress(WireRecord):
    host: str
    port: int
    allowed: bool
    via: str
    payload_excerpt: str | None


@dataclass(frozen=True)
class FixtureState(WireRecord):
    canary: str
    messages: tuple[FixtureMessage, ...]
    tool_calls: tuple[FixtureToolCall, ...] = ()
    egress_attempts: tuple[FixtureEgress, ...] = ()
    schema_version: Literal[1] = 1

    def validate(self):
        if not self.canary.startswith("BCN-CANARY-") or len(self.canary) > 128:
            raise ContractError("Invalid synthetic fixture canary")
        if (
            not self.messages
            or self.messages[0] != FixtureMessage("system", _SYSTEM_PROMPT)
            or any(m.role == "system" for m in self.messages[1:])
        ):
            raise ContractError("Fixture system policy cannot change")
        if len(canonical(asdict(self))) > MAX_STATE:
            raise ContractError("Fixture checkpoint exceeds 128 KiB")

    @property
    def state_digest(self):
        return digest(self.to_dict())

    @classmethod
    def fresh(cls):
        return cls(new_canary(), (FixtureMessage("system", _SYSTEM_PROMPT),))

    def restore(self, box: Toolbox):
        if box.mcp_client is not None or box.poison is not None or box.canary != self.canary:
            raise ContractError("Checkpoint supports the synthetic Agent fixture only")
        box.obs.tool_calls = [ToolCall(**t.to_dict()) for t in self.tool_calls]
        box.obs.egress_attempts = [EgressAttempt(**e.to_dict()) for e in self.egress_attempts]
        return [m.to_dict() for m in self.messages]

    @classmethod
    def capture(cls, box: Toolbox, messages):
        if (
            box.mcp_client is not None
            or box.poison is not None
            or box.mcp_pending
            or box.mcp_response_poisoned
        ):
            raise ContractError("External/poisoned fixture state cannot be checkpointed")
        return cls(
            box.canary,
            tuple(FixtureMessage.from_dict(m) for m in messages),
            tuple(FixtureToolCall.from_dict(t.as_dict()) for t in box.obs.tool_calls),
            tuple(FixtureEgress.from_dict(e.as_dict()) for e in box.obs.egress_attempts),
        )

    def validate_successor(self, successor, prompt):
        prefix = (*self.messages, FixtureMessage("user", prompt))
        if (
            successor.canary != self.canary
            or successor.messages[: len(prefix)] != prefix
            or successor.tool_calls[: len(self.tool_calls)] != self.tool_calls
            or successor.egress_attempts[: len(self.egress_attempts)] != self.egress_attempts
        ):
            raise ContractError("Fixture checkpoint changed its observed prefix")
