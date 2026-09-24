"""API 2 model conversation routes owned by one suite case and worker lifecycle."""

from __future__ import annotations

from ..contracts import ContractError
from .conversations import ConversationLimits, ModelConversation


class ConversationRoutes:
    """Fixed caps, no history import, no target state or runtime configuration route."""

    def __init__(self, broker, ledger, *, run_id, case_id, grants, revalidate):
        self.broker, self.ledger = broker, ledger
        self.run_id, self.case_id = run_id, case_id
        self.grants, self.revalidate = frozenset(grants), revalidate
        self.sessions: dict[str, ModelConversation] = {}
        self.channels: dict[str, str] = {}
        self.scope = None
        self.active: set[str] = set()
        self.closed = False

    async def dispatch(self, channel, payload, context):
        if self.closed or f"broker.{channel}.conversation" not in self.grants:
            raise ContractError("Conversation channel not granted or closed")
        if channel not in ("attacker", "evaluator") or type(payload) is not dict:
            raise ContractError("Unsupported conversation request")
        self.revalidate()
        self.ledger.check_time()
        if self.scope != context.scope_id:
            for identifier in self.active:
                self.sessions[identifier].close()
            self.active.clear()
            self.scope = context.scope_id
        operation = payload.get("operation")
        fields = {
            "open": {"operation", "system_message", "branching"},
            "send": {"operation", "conversation", "parent", "prompt", "max_tokens"},
            "close": {"operation", "conversation"},
        }
        if (
            type(operation) is not str
            or operation not in fields
            or set(payload) != fields[operation]
        ):
            raise ContractError("Unsupported conversation operation or fields")
        if operation == "open":
            if type(payload["branching"]) is not bool:
                raise ContractError("Conversation branching must be a boolean")
            if payload["branching"] and f"broker.{channel}.branch" not in self.grants:
                raise ContractError("Conversation branching not granted")
            # Cumulative cap: closing/resetting never refills the allocation.
            if len(self.sessions) >= 4:
                raise ContractError("Conversation session limit exceeded")
            conversation = ModelConversation(
                self.broker,
                self.ledger,
                run_id=self.run_id,
                case_id=self.case_id,
                channel=channel,
                system_message=payload["system_message"],
                worker_scope=context.scope_id,
                limits=ConversationLimits(allow_branching=payload["branching"]),
            )
            # Bound retained host metadata before exposing the new handle.
            self.ledger.reserve("artifact_bytes", 4096)
            identifier = conversation.root
            self.sessions[identifier] = conversation
            self.channels[identifier] = channel
            self.active.add(identifier)
            return {"conversation": identifier, "checkpoint": identifier}
        identifier = payload["conversation"]
        if (
            type(identifier) is not str
            or identifier not in self.active
            or self.channels[identifier] != channel
        ):
            raise ContractError("Unknown or foreign conversation")
        conversation = self.sessions[identifier]
        if operation == "close":
            conversation.close()
            self.active.remove(identifier)
            return {"closed": True}
        self.ledger.reserve("artifact_bytes", 2048)
        reply = await conversation.send(
            payload["parent"], payload["prompt"], max_tokens=payload["max_tokens"]
        )
        return {"checkpoint": reply.checkpoint, "response_text": reply.text}

    @property
    def audits(self):
        return tuple(session.audit for session in self.sessions.values())

    def close(self):
        for identifier in self.active:
            self.sessions[identifier].close()
        self.active.clear()
        self.closed = True
