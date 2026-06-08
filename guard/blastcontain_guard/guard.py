"""
blastcontain_guard.guard — the facade teams embed in their copilot.

    from blastcontain_guard import Guard
    from blastcontain_guard.adapters import MCPMiddleware

    guard = Guard.from_yaml("policy.yaml")     # open, standalone — the wedge
    guard.on_ask(host_ui.prompt)               # register the approval UI
    guard.attach(MCPMiddleware())              # intercept MCP tool calls

    @guard.tool                                # ...or wrap a tool directly
    def delete_record(id): ...                 # evaluated on every call

One object wires the whole flow (guard-spec §4): load policy once; on each call
build the input, evaluate to allow/ask/deny (native primary, optional AGT
behind), resolve *ask* via the host, propose learning on *allow always*, and emit
every decision as a signed-able CloudEvent. The hot path is pure + local;
telemetry fans out off-thread when a network sink is attached.
"""
from __future__ import annotations

import functools
import inspect
import time
from typing import TYPE_CHECKING, Any, Callable, Optional

from .ask import AskResolver, AsyncApprover, OnAsk
from .backends import AgtBackend, NativeBackend, combine_with_agt
from .constants import infer_action_type
from .errors import GuardDenied, GuardError
from .learning import LearningStore, ProposalSink
from .models import (
    Action,
    AskChoice,
    Decision,
    DelegationContext,
    EnforcementResult,
    EvalInput,
)
from .policy import Ruleset, load_ruleset, parse_ruleset
from .telemetry import (
    AsyncEmitter,
    Emitter,
    JsonlSink,
    LedgerSink,
    MemorySink,
    OtelSink,
    Sink,
    build_decision_event,
    build_learning_event,
)

if TYPE_CHECKING:
    from .agt_export import PushResult

__all__ = ["Guard", "GuardDenied", "GuardError"]


class Guard:
    """In-process enforcer for one agent. Construct via the ``from_*`` helpers."""

    def __init__(
        self,
        ruleset: Ruleset,
        *,
        on_ask: Optional[OnAsk] = None,
        autonomy_mode: Optional[str] = None,
        agent_id: Optional[str] = None,
        environment: Optional[str] = None,
        extra_sinks: Optional[list[Sink]] = None,
        async_telemetry: Optional[bool] = None,
        learning_sink: Optional[ProposalSink] = None,
        agt: Optional[AgtBackend] = None,
        hitl_timeout_sec: int = 300,
        escalation_contact: Optional[str] = None,
        async_approver: Optional[AsyncApprover] = None,
    ):
        self.ruleset = ruleset
        self.agent_id = agent_id or ruleset.agent_id or ""
        self.environment = environment or ruleset.environment or ""
        self.autonomy_mode = autonomy_mode or ruleset.autonomy_mode or "interactive"

        self.backend = NativeBackend()
        self.agt = agt

        # Telemetry: always buffer in memory (the signed decision log is built
        # from it); fan out to any extra sinks. Use the off-thread emitter when a
        # network sink is present so the tool-call path never blocks on I/O.
        self._buffer = MemorySink()
        sinks: list[Sink] = [self._buffer, *(extra_sinks or [])]
        if async_telemetry is None:
            async_telemetry = any(isinstance(s, (LedgerSink, OtelSink)) for s in sinks)
        self.emitter: Emitter = AsyncEmitter(sinks) if async_telemetry else Emitter(sinks)

        self.learning = LearningStore(sink=learning_sink)
        self.resolver = AskResolver(
            autonomy_mode=self.autonomy_mode,
            on_ask=on_ask,
            hitl_timeout_sec=hitl_timeout_sec,
            escalation_contact=escalation_contact,
            async_approver=async_approver,
        )
        self._adapters: list[Any] = []

    # ── constructors ────────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str, **kwargs: Any) -> "Guard":
        """Load an open ``governance.toolkit/v1`` ruleset from a local YAML file."""
        return cls(load_ruleset(path), **kwargs)

    @classmethod
    def from_dict(cls, data: dict, **kwargs: Any) -> "Guard":
        """Build from an already-parsed ruleset mapping (tests, embedding)."""
        return cls(parse_ruleset(data), **kwargs)

    @classmethod
    def from_charter_file(
        cls, path: str, autonomy_mode: str = "interactive", **kwargs: Any
    ) -> "Guard":
        """Compile a local ``charter.yaml`` (core CharterSchema) offline, then guard."""
        from .compile import compile_charter_file

        ruleset = compile_charter_file(path, autonomy_mode=autonomy_mode)
        kwargs.setdefault("autonomy_mode", autonomy_mode)
        return cls(ruleset, **kwargs)

    @classmethod
    def from_charter(
        cls, agent_id: str, env: str = "prod", base_url: Optional[str] = None,
        token: Optional[str] = None, **kwargs: Any,
    ) -> "Guard":
        """Pull a signed Charter from the Platform (planned — see platform_source)."""
        from .platform_source import fetch_ruleset

        ruleset = fetch_ruleset(agent_id, env, base_url=base_url, token=token)
        return cls(ruleset, **kwargs)

    @classmethod
    def from_config(
        cls, path: Optional[str] = None, *, on_ask: Optional[OnAsk] = None, **overrides: Any
    ) -> "Guard":
        """Build a Guard entirely from configuration — the mode is config, not code.

        The *same* agent code runs guard-only, guard+AGT (dual), or AGT-only (sole)
        depending purely on the config's ``policy``/``charter`` source and its
        optional ``agt:`` block (see examples/mode-*.yaml). Nothing about the agent
        changes between modes — only the file you point it at.
        """
        from .config import load_config

        cfg = load_config(config_file=path, cli_overrides=overrides or None)

        if cfg.policy:
            ruleset = load_ruleset(cfg.policy)
        elif cfg.charter:
            from .compile import compile_charter_file

            ruleset = compile_charter_file(cfg.charter, autonomy_mode=cfg.autonomy_mode)
        else:
            raise GuardError("config has no policy source: set 'policy:' or 'charter:'")

        agt = None
        if cfg.agt_enabled:
            agt = AgtBackend(
                enabled=True,
                sole=(cfg.agt_mode == "sole"),
                degrade_to_native=cfg.degrade_to_native,
                endpoint=cfg.agt_endpoint,
                token=cfg.agt_token,
            )

        sinks: list[Sink] = []
        if cfg.log:
            sinks.append(JsonlSink(cfg.log))
        if cfg.blastcontain_url and not cfg.dry_run and cfg.agent_id:
            sinks.append(LedgerSink(cfg.blastcontain_url, cfg.agent_id))

        return cls(
            ruleset,
            on_ask=on_ask,
            agent_id=cfg.agent_id or None,
            environment=cfg.environment or None,
            autonomy_mode=cfg.autonomy_mode,
            agt=agt,
            extra_sinks=sinks or None,
            hitl_timeout_sec=cfg.hitl_timeout_sec,
            escalation_contact=cfg.escalation_contact,
        )

    # ── registration ─────────────────────────────────────────────────────────────

    def on_ask(self, callback: OnAsk) -> "Guard":
        """Register the host's approval UI. Chainable."""
        self.resolver.on_ask = callback
        return self

    def attach(self, adapter: Any) -> "Guard":
        """Bind a framework adapter (it will call back into ``check``). Chainable."""
        bind = getattr(adapter, "bind", None)
        if callable(bind):
            bind(self)
        self._adapters.append(adapter)
        return self

    def describe_mode(self) -> str:
        """Human-readable enforcement mode (for banners / diagnostics)."""
        if self.agt is None or not self.agt.enabled:
            return "guard-only (in-process)"
        kind = "sole" if getattr(self.agt, "sole", False) else "dual"
        where = self.agt.endpoint or "injected"
        return f"guard+agt:{kind} (AGT @ {where})"

    # ── evaluation & enforcement ─────────────────────────────────────────────────

    def _make_input(
        self,
        tool_name: str,
        action_type: Optional[str] = None,
        args: Optional[dict] = None,
        identity: Optional[dict] = None,
        delegation_ctx: Optional[DelegationContext] = None,
    ) -> EvalInput:
        resolved = action_type if action_type is not None else infer_action_type(tool_name)
        return EvalInput(
            tool_name=tool_name,
            action_type=resolved,
            args=args or {},
            agent_id=self.agent_id,
            identity=identity or {},
            delegation_ctx=delegation_ctx,
        )

    def evaluate(self, inp: EvalInput) -> Decision:
        """Pure evaluation — no resolution, no telemetry. For introspection/tests."""
        decision, _ = self._decide(inp)
        return decision

    def explain(
        self,
        tool_name: str,
        *,
        action_type: Optional[str] = None,
        args: Optional[dict] = None,
        identity: Optional[dict] = None,
        delegation_ctx: Optional[DelegationContext] = None,
    ) -> Decision:
        """Evaluate a tool call by its parts (no telemetry). For ``guard simulate``."""
        inp = self._make_input(tool_name, action_type, args, identity, delegation_ctx)
        return self.evaluate(inp)

    def _decide(self, inp: EvalInput) -> tuple[Decision, bool]:
        native = self.backend.evaluate(self.ruleset, inp)
        if self.agt is None or not self.agt.enabled:
            return native, False
        return combine_with_agt(native, self.ruleset, inp, self.agt)

    def check(
        self,
        tool_name: str,
        *,
        action_type: Optional[str] = None,
        args: Optional[dict] = None,
        identity: Optional[dict] = None,
        delegation_ctx: Optional[DelegationContext] = None,
    ) -> EnforcementResult:
        """Evaluate, resolve any *ask*, emit telemetry. The main enforcement entry."""
        start = time.perf_counter()
        inp = self._make_input(tool_name, action_type, args, identity, delegation_ctx)
        decision, degraded = self._decide(inp)
        allowed, ask_result, learning = self._resolve(decision, inp)
        latency_ms = (time.perf_counter() - start) * 1000.0

        self._emit_decision(inp, decision, allowed, latency_ms, ask_result, degraded)
        if learning is not None:
            self._emit_learning(learning)

        return EnforcementResult(
            allowed=allowed,
            decision=decision,
            tool_name=tool_name,
            ask_result=ask_result,
            learning=learning,
            latency_ms=latency_ms,
            degraded=degraded,
        )

    def evaluate_and_emit(
        self,
        tool_name: str,
        *,
        action_type: Optional[str] = None,
        args: Optional[dict] = None,
        identity: Optional[dict] = None,
        delegation_ctx: Optional[DelegationContext] = None,
    ) -> Decision:
        """Evaluate and emit telemetry, but do **not** resolve an ``ask``.

        For hosts that render the approval prompt themselves (the Claude Code
        ``PreToolUse`` hook maps ``ask`` straight to its own permission prompt),
        so Guard records the decision without owning the UI round-trip.
        """
        start = time.perf_counter()
        inp = self._make_input(tool_name, action_type, args, identity, delegation_ctx)
        decision, degraded = self._decide(inp)
        latency_ms = (time.perf_counter() - start) * 1000.0
        self._emit_decision(
            inp, decision, decision.action is Action.ALLOW, latency_ms, None, degraded,
            final=decision.action.value,
        )
        return decision

    def _resolve(self, decision: Decision, inp: EvalInput):
        if decision.action is Action.ALLOW:
            return True, None, None
        if decision.action is Action.DENY:
            return False, None, None

        # ASK — put it to the human (or the autonomous approver).
        allowed, ask_result = self.resolver.resolve(
            decision, inp, agent_id=self.agent_id, environment=self.environment
        )
        learning = None
        if allowed and ask_result.choice is AskChoice.ALLOW_ALWAYS:
            learning = self.learning.propose_permitted_tool(
                self.agent_id, inp.tool_name, inp.action_type, ask_result.approver_id
            )
        return allowed, ask_result, learning

    def _emit_decision(
        self, inp, decision, allowed, latency_ms, ask_result, degraded, final=None
    ) -> None:
        event = build_decision_event(
            self.agent_id,
            self.environment,
            inp.tool_name,
            inp.action_type,
            decision,
            allowed=allowed,
            latency_ms=latency_ms,
            ask_choice=ask_result.choice.value if ask_result else None,
            approver_id=ask_result.approver_id if ask_result else None,
            degraded=degraded,
            final=final,
        )
        self.emitter.emit(event)

    def _emit_learning(self, proposal) -> None:
        self.emitter.emit(build_learning_event(self.agent_id, self.environment, proposal))

    # ── the decorator adapter ────────────────────────────────────────────────────

    def tool(
        self,
        _fn: Optional[Callable] = None,
        *,
        action_type: Optional[str] = None,
        name: Optional[str] = None,
    ):
        """Decorator: guard a hand-rolled tool. Raises GuardDenied if blocked.

        Usage: ``@guard.tool`` or ``@guard.tool(action_type="delete")``.
        """

        def decorate(fn: Callable) -> Callable:
            tool_name = name or fn.__name__
            try:
                sig: Optional[inspect.Signature] = inspect.signature(fn)
            except (ValueError, TypeError):
                sig = None

            @functools.wraps(fn)
            def wrapper(*a: Any, **kw: Any) -> Any:
                args = _bind_args(sig, a, kw)
                result = self.check(tool_name, action_type=action_type, args=args)
                if not result.allowed:
                    raise GuardDenied(result)
                return fn(*a, **kw)

            wrapper.__guarded__ = True  # type: ignore[attr-defined]
            return wrapper

        return decorate(_fn) if callable(_fn) else decorate

    # ── audit / lifecycle ────────────────────────────────────────────────────────

    @property
    def decisions(self) -> list[dict]:
        """The buffered decision CloudEvents (the live audit trail)."""
        return list(self._buffer.events)

    @property
    def learning_proposals(self):
        return self.learning.pending()

    def write_decision_log(self, path: str) -> dict:
        """Write a signed decision-log packet from the buffered events."""
        from .reporter import write_decision_log

        self.flush()
        return write_decision_log(self.agent_id, self.environment, self.decisions, path)

    def to_agt_yaml(self, **kwargs: Any) -> str:
        """Render this agent's policy as an AGT ``governance.toolkit/v1`` document."""
        from .agt_export import to_agt_yaml

        kwargs.setdefault("autonomy_mode", self.autonomy_mode)
        return to_agt_yaml(self.ruleset, **kwargs)

    def push_to_agt(self, **kwargs: Any) -> "PushResult":
        """Deploy this agent's policy to a running AGT (the out-of-process front)."""
        from .agt_export import push_to_agt

        kwargs.setdefault("autonomy_mode", self.autonomy_mode)
        return push_to_agt(self.ruleset, **kwargs)

    def flush(self, timeout: float = 2.0) -> None:
        self.emitter.flush(timeout)

    def close(self) -> None:
        self.emitter.close()

    def __enter__(self) -> "Guard":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def _bind_args(sig: Optional[inspect.Signature], a: tuple, kw: dict) -> dict:
    """Best-effort map of a call's positional+keyword args to a name->value dict."""
    if sig is None:
        return dict(kw)
    try:
        bound = sig.bind_partial(*a, **kw)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        return dict(kw)
