"""Host-owned attacker/evaluator history; not an Agent/tool-state checkpoint.

Workers cannot submit assistant/system history through this interface. Only a
trusted host constructs the session and its initial system message. Runtime/wire
and durable-report integration are deliberately separate from this primitive.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import hashlib
import re
import secrets
from typing import Literal

from ..contracts import ContractError
from ..contracts.plugins import artifact_digest
from ..contracts.wire import WireRecord
from .artifacts import canonical, digest
from .broker import MAX_INPUT, ModelBroker, ModelError
from .budgets import BudgetExceeded, Ledger


@dataclass(frozen=True)
class ConversationLimits(WireRecord):
    max_attempts: int = 32
    max_history_bytes: int = 65536
    allow_branching: bool = False

    def validate(self):
        if not 1 <= self.max_attempts <= 64:
            raise ContractError("Conversation attempts must be between 1 and 64")
        if not 1024 <= self.max_history_bytes <= MAX_INPUT:
            raise ContractError("Conversation history must be between 1 and 128 KiB")


@dataclass(frozen=True)
class ConversationEvent:
    """Sanitized host audit data; no security verdict or signed-report claim."""

    sequence: int
    scope_digest: str
    parent: str
    request_digest: str
    status: str = "pending"
    checkpoint: str | None = None
    response_digest: str | None = None


@dataclass(frozen=True)
class ConversationReply:
    checkpoint: str
    text: str


class ModelConversation:
    """One bounded, non-concurrent model session sharing the caller's case ledger.

    A checkpoint is an opaque handle usable only in this session. Branching is
    opt-in, and changes only subsequent message history. Earlier calls/events and
    ledger charges remain. Closing destroys retained history without resetting
    the ledger. Target Agent/MCP state is unsupported, rather than replayed.
    """

    def __init__(
        self,
        broker: ModelBroker,
        ledger: Ledger,
        *,
        run_id: str,
        case_id: str,
        channel: Literal["attacker", "evaluator"],
        system_message: str,
        limits: ConversationLimits = ConversationLimits(),
    ):
        if type(run_id) is not str or not re.fullmatch(r"[a-f0-9]{32}", run_id):
            raise ContractError("Invalid conversation run identity")
        if type(case_id) is not str:
            raise ContractError("Invalid conversation case identity")
        artifact_digest(case_id)
        if channel not in ("attacker", "evaluator"):
            raise ContractError("Agent/MCP target conversation checkpoints are unsupported")
        if type(system_message) is not str or not system_message.strip():
            raise ContractError("A host-owned system message is required")
        if type(limits) is not ConversationLimits:
            raise ContractError("Invalid conversation limits")
        limits.to_dict()
        if channel not in broker.settings:
            raise ModelError("model_channel_unconfigured")
        if ledger.case is None:
            raise ContractError("Conversation requires an active case ledger")
        self._broker, self._ledger = broker, ledger
        self._case_counters = ledger.case
        self._case_id, self._channel, self._limits = case_id, channel, limits
        self._settings_digest = digest(broker.settings[channel].to_dict())
        self._root = secrets.token_hex(16)
        self._head = self._root
        self._scope_digest = digest(
            {
                "run_id": run_id,
                "case_id": case_id,
                "channel": channel,
                "settings_digest": self._settings_digest,
                "conversation_id": self._root,
                "limits": limits.to_dict(),
            }
        )
        self._nodes: dict[str, tuple[tuple[str, str], ...]] = {
            self._root: (("system", system_message),)
        }
        self._check_history(self._nodes[self._root])
        self._events: list[ConversationEvent] = []
        self._busy = self._closed = False

    @property
    def root(self):
        return self._root

    @property
    def head(self):
        return self._head

    @property
    def events(self):
        return tuple(self._events)

    def _check_history(self, history):
        messages = [{"role": role, "content": content} for role, content in history]
        if len(canonical(messages)) > self._limits.max_history_bytes:
            raise ContractError("Conversation history limit exceeded")
        return messages

    async def send(self, parent: str, prompt: str, *, max_tokens: int = 512):
        if self._closed or self._busy:
            raise ContractError("Conversation is closed or already dispatching")
        if self._ledger.case is not self._case_counters:
            raise ContractError("Conversation case ledger changed")
        if type(parent) is not str or parent not in self._nodes:
            raise ContractError("Unknown or foreign conversation checkpoint")
        if not self._limits.allow_branching and parent != self._head:
            raise ContractError("Conversation branching was not enabled")
        if type(prompt) is not str or not prompt.strip() or len(prompt.encode()) > 32768:
            raise ContractError("Conversation prompt outside supported bounds")
        if type(max_tokens) is not int or max_tokens < 1:
            raise ContractError("Invalid conversation output limit")
        settings = self._broker.settings.get(self._channel)
        if settings is None or digest(settings.to_dict()) != self._settings_digest:
            raise ContractError("Conversation model binding changed")
        if len(self._events) >= self._limits.max_attempts:
            raise ContractError("Conversation attempt limit exceeded")
        history = self._nodes[parent] + (("user", prompt),)
        messages = self._check_history(history)
        event = ConversationEvent(
            len(self._events) + 1,
            self._scope_digest,
            parent,
            digest(
                {
                    "scope": self._scope_digest,
                    "parent": parent,
                    "messages": messages,
                    "max_tokens": min(max_tokens, settings.max_output_tokens),
                }
            ),
        )
        index = len(self._events)
        self._events.append(event)
        self._busy = True
        try:
            text = await self._broker.chat(
                self._case_id, self._ledger, self._channel, messages, max_tokens=max_tokens
            )
            event = replace(
                event, response_digest="sha256:" + hashlib.sha256(text.encode()).hexdigest()
            )
            completed = history + (("assistant", text),)
            self._check_history(completed)
            checkpoint = secrets.token_hex(16)
            self._nodes[checkpoint] = completed
            self._head = checkpoint
            self._events[index] = replace(event, status="completed", checkpoint=checkpoint)
            return ConversationReply(checkpoint, text)
        except asyncio.CancelledError:
            self._events[index] = replace(event, status="cancelled")
            raise
        except (BudgetExceeded, TimeoutError):
            self._events[index] = replace(event, status="limited")
            raise
        except Exception:
            self._events[index] = replace(event, status="error")
            raise
        finally:
            self._busy = False

    def close(self):
        if self._busy:
            raise ContractError("Stop the active dispatch before closing its conversation")
        self._nodes.clear()
        self._closed = True
