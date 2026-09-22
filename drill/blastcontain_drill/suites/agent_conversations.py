"""Opaque checkpoints over the trusted synthetic Agent fixture, with all branches retained."""

from dataclasses import dataclass
import secrets
from typing import Literal

from ..contracts import ContractError
from ..contracts.plugins import artifact_digest
from ..contracts.wire import WireRecord
from .artifacts import digest
from .fixture_state import FixtureState
from .broker import ModelError


def handle(value):
    import re

    if type(value) is not str or not re.fullmatch(r"[a-f0-9]{32}", value):
        raise ContractError("Invalid Agent checkpoint handle")


@dataclass(frozen=True)
class AgentTurn(WireRecord):
    sequence: int
    parent: str
    input_digest: str
    prompt_digest: str
    attempt_id: str
    output_digest: str | None
    checkpoint: str | None

    def validate(self):
        if self.sequence < 1:
            raise ContractError("Invalid Agent turn sequence")
        handle(self.parent)
        if self.checkpoint is not None:
            handle(self.checkpoint)
        for value in (self.input_digest, self.prompt_digest, self.attempt_id, self.output_digest):
            if value is not None:
                artifact_digest(value)
        if (self.checkpoint is None) != (self.output_digest is None):
            raise ContractError("Agent checkpoint needs an observed output state")


@dataclass(frozen=True)
class AgentAudit(WireRecord):
    run_id: str
    case_id: str
    lock_digest: str
    worker_scope: str
    conversation_id: str
    root_state_digest: str
    branching: bool
    turns: tuple[AgentTurn, ...]
    closed: bool
    schema_version: Literal[1] = 1

    def validate(self):
        for value in (self.run_id, self.worker_scope, self.conversation_id):
            handle(value)
        for value in (self.case_id, self.lock_digest, self.root_state_digest):
            artifact_digest(value)
        if len(self.turns) > 32:
            raise ContractError("Agent conversation exceeds 32 turns")
        states, head, attempts = (
            {self.conversation_id: self.root_state_digest},
            self.conversation_id,
            set(),
        )
        for i, turn in enumerate(self.turns, 1):
            if (
                turn.sequence != i
                or states.get(turn.parent) != turn.input_digest
                or not self.branching
                and turn.parent != head
                or turn.attempt_id in attempts
            ):
                raise ContractError("Agent checkpoint graph is incomplete or incorrectly scoped")
            attempts.add(turn.attempt_id)
            if turn.checkpoint is not None and turn.output_digest is not None:
                if turn.checkpoint in states:
                    raise ContractError("Agent checkpoint was reused")
                states[turn.checkpoint] = turn.output_digest
                head = turn.checkpoint


class AgentConversation:
    """One synthetic fixture session; restarting child processes never replays a prefix."""

    def __init__(self, *, run_id, case_id, lock_digest, worker_scope, branching, run_turn, ledger):
        self.root = secrets.token_hex(16)
        self.head = self.root
        root_state = FixtureState.fresh()
        self._states = {self.root: root_state}
        self._turns: list[AgentTurn] = []
        self._identity = dict(
            run_id=run_id,
            case_id=case_id,
            lock_digest=lock_digest,
            worker_scope=worker_scope,
            conversation_id=self.root,
            root_state_digest=root_state.state_digest,
            branching=branching,
        )
        self._run_turn, self._ledger = run_turn, ledger
        self._busy = self._closed = False
        self._case_counters = ledger.case
        self.audit.to_dict()

    @property
    def audit(self):
        return AgentAudit(**self._identity, turns=tuple(self._turns), closed=self._closed)

    async def send(self, parent, prompt):
        if self._busy or self._closed or self._ledger.case is not self._case_counters:
            raise ContractError("Agent session is unavailable")
        if type(parent) is not str or parent not in self._states:
            raise ContractError("Unknown or foreign Agent checkpoint")
        if not self._identity["branching"] and parent != self.head:
            raise ContractError("Agent branching was not accepted")
        if type(prompt) is not str or not prompt.strip() or len(prompt.encode()) > 32768:
            raise ContractError("Agent prompt outside supported bounds")
        if len(self._turns) >= 32:
            raise ContractError("Agent conversation turn limit exceeded")
        state = self._states[parent]
        self._ledger.reserve("artifact_bytes", 2048)
        self._busy = True
        try:
            outcome, text = await self._run_turn(prompt, fixture_state=state)
            successor = outcome.fixture_output
            checkpoint = secrets.token_hex(16) if successor is not None else None
            self._turns.append(
                AgentTurn(
                    len(self._turns) + 1,
                    parent,
                    state.state_digest,
                    digest(prompt),
                    outcome.case_id,
                    successor.state_digest if successor is not None else None,
                    checkpoint,
                )
            )
            if outcome.disposition != "completed" or successor is None or checkpoint is None:
                raise ModelError("target_attempt_incomplete")
            state.validate_successor(successor, prompt)
            self._states[checkpoint] = successor
            self.head = checkpoint
            return {
                "checkpoint": checkpoint,
                "response_text": text,
                "outcome": outcome.legacy_outcome,
            }
        finally:
            self._busy = False

    def close(self):
        if self._busy:
            raise ContractError("Cancel the active Agent dispatch before closing")
        self._states.clear()
        self._closed = True


class AgentRoutes:
    def __init__(self, *, run_id, case_id, lock_digest, grants, run_turn, ledger, revalidate):
        self.identity = dict(run_id=run_id, case_id=case_id, lock_digest=lock_digest)
        self.grants, self.run_turn, self.ledger = frozenset(grants), run_turn, ledger
        self.revalidate = revalidate
        self.session: AgentConversation | None = None
        self.scope = None
        self.closed = False

    async def dispatch(self, payload, context):
        if self.closed or "broker.target.conversation" not in self.grants:
            raise ContractError("Agent conversation not granted or closed")
        self.revalidate()
        self.ledger.check_time()
        fields = {
            "open": {"operation", "branching"},
            "send": {"operation", "conversation", "parent", "prompt"},
            "close": {"operation", "conversation"},
        }
        operation = payload.get("operation") if type(payload) is dict else None
        if (
            type(operation) is not str
            or operation not in fields
            or set(payload) != fields[operation]
        ):
            raise ContractError("Unsupported Agent operation or fields")
        if operation == "open":
            if self.session is not None:
                raise ContractError("Only one Agent session is allowed per case")
            if type(payload["branching"]) is not bool or (
                payload["branching"] and "broker.target.branch" not in self.grants
            ):
                raise ContractError("Agent branching was not granted")
            self.ledger.reserve("artifact_bytes", 4096)
            self.scope = context.scope_id
            self.session = AgentConversation(
                **self.identity,
                worker_scope=self.scope,
                branching=payload["branching"],
                run_turn=self.run_turn,
                ledger=self.ledger,
            )
            return {"conversation": self.session.root, "checkpoint": self.session.root}
        if (
            self.session is None
            or context.scope_id != self.scope
            or payload["conversation"] != self.session.root
        ):
            raise ContractError("Unknown or foreign Agent conversation")
        if operation == "close":
            self.session.close()
            return {"closed": True}
        return await self.session.send(payload["parent"], payload["prompt"])

    @property
    def audits(self):
        return (self.session.audit,) if self.session is not None else ()

    def close(self):
        if self.session is not None:
            self.session.close()
        self.closed = True
