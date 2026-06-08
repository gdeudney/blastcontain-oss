"""
blastcontain_guard.ask — how an *ask* actually resolves (guard-spec §7, §7.1).

The evaluator produces ``ask``; *resolving* it is a separate, effectful step,
because the same decision resolves differently depending on who is present:

  * **interactive / copilot** — a synchronous inline prompt to the present user
    via the host's ``on_ask`` callback (allow once / allow always / deny);
  * **autonomous** — async approval routed to ``escalation_contact`` with a
    timeout, **deny on timeout**; or, with no approver configured, a hard deny.

The honesty line is enforced here too (charter-spec §3.7): an ask that requires
a **central** approver is a mandatory Standard — it never degrades to a present
user's click. In open, standalone (local-YAML) mode there is no central
authority, so such an ask collapses to **deny** with a "request Exception" note.

It is a config, not a rebuild: ``allow`` and ``deny`` are identical in either
mode, which is why Guard runs unchanged on an autonomous agent.
"""
from __future__ import annotations

from typing import Callable, Optional

from .models import (
    Action,
    AskChoice,
    AskRequest,
    AskResult,
    Decision,
    EvalInput,
)

# A host approval handler: given an AskRequest, return how the user answered.
# For forgiving host integrations we also accept a bare AskChoice or a string.
OnAsk = Callable[[AskRequest], "AskResult | AskChoice | str"]

# An autonomous approver: given a request and a timeout, return a result or None
# (None == timed out / no decision == deny).
AsyncApprover = Callable[[AskRequest, int], Optional[AskResult]]


class AskResolver:
    """Turns an ``ask`` decision into a concrete allow/deny, per autonomy mode."""

    def __init__(
        self,
        autonomy_mode: str = "interactive",
        on_ask: Optional[OnAsk] = None,
        hitl_timeout_sec: int = 300,
        escalation_contact: Optional[str] = None,
        async_approver: Optional[AsyncApprover] = None,
        central_approver: Optional[OnAsk] = None,
    ):
        self.autonomy_mode = autonomy_mode
        self.on_ask = on_ask
        self.hitl_timeout_sec = hitl_timeout_sec
        self.escalation_contact = escalation_contact
        self.async_approver = async_approver
        # Optional channel to a central authority (the commercial Platform's
        # Exception flow). Absent in standalone mode -> central asks deny.
        self.central_approver = central_approver

    def build_request(
        self, decision: Decision, inp: EvalInput, agent_id: str = "", environment: str = ""
    ) -> AskRequest:
        verb = inp.action_type or "use"
        return AskRequest(
            description=f"Agent wants to {verb} via '{inp.tool_name}'",
            tool_name=inp.tool_name,
            action_type=inp.action_type,
            approvers=list(decision.approvers),
            risk_tag=decision.risk_tag,
            concern=decision.concern,
            agent_id=agent_id,
            environment=environment,
        )

    def resolve(
        self, decision: Decision, inp: EvalInput, agent_id: str = "", environment: str = ""
    ) -> tuple[bool, AskResult]:
        """Resolve an ``ask`` decision. Returns ``(allowed, ask_result)``.

        Only call this for ``Action.ASK`` decisions; allow/deny need no round-trip.
        """
        if decision.action is not Action.ASK:  # defensive — callers gate on ASK
            allowed = decision.action is Action.ALLOW
            return allowed, AskResult(AskChoice.ALLOW_ONCE if allowed else AskChoice.DENY)

        req = self.build_request(decision, inp, agent_id, environment)

        # The honesty line: a central-approver ask is a mandatory Standard.
        if decision.requires_central:
            if self.central_approver is not None:
                return self._interpret(self.central_approver(req))
            return False, AskResult(
                AskChoice.DENY,
                note="mandatory Standard — requires a central Exception (no user override)",
            )

        if self.autonomy_mode == "autonomous":
            return self._resolve_autonomous(req)

        # interactive / copilot — prompt the present user.
        if self.on_ask is None:
            return False, AskResult(
                AskChoice.DENY, note="no approval handler registered — failing closed"
            )
        return self._interpret(self.on_ask(req))

    def _resolve_autonomous(self, req: AskRequest) -> tuple[bool, AskResult]:
        if self.async_approver is None:
            # No one to ask, unattended -> the ask compiles to deny (§7.1).
            return False, AskResult(
                AskChoice.DENY,
                note="autonomous mode with no approver configured — compiles to deny",
            )
        result = self.async_approver(req, self.hitl_timeout_sec)
        if result is None:
            return False, AskResult(
                AskChoice.DENY,
                note=f"autonomous approval timed out after {self.hitl_timeout_sec}s — denied",
            )
        return self._interpret(result)

    @staticmethod
    def _interpret(raw: "AskResult | AskChoice | str") -> tuple[bool, AskResult]:
        """Normalise whatever the host returned into ``(allowed, AskResult)``."""
        result = _coerce_result(raw)
        allowed = result.choice in (AskChoice.ALLOW_ONCE, AskChoice.ALLOW_ALWAYS)
        return allowed, result


_STR_TO_CHOICE = {
    "allow": AskChoice.ALLOW_ONCE,
    "allow_once": AskChoice.ALLOW_ONCE,
    "allow once": AskChoice.ALLOW_ONCE,
    "once": AskChoice.ALLOW_ONCE,
    "allow_always": AskChoice.ALLOW_ALWAYS,
    "allow always": AskChoice.ALLOW_ALWAYS,
    "always": AskChoice.ALLOW_ALWAYS,
    "deny": AskChoice.DENY,
    "block": AskChoice.DENY,
    "reject": AskChoice.DENY,
    "no": AskChoice.DENY,
}


def _coerce_result(raw: "AskResult | AskChoice | str") -> AskResult:
    if isinstance(raw, AskResult):
        return raw
    if isinstance(raw, AskChoice):
        return AskResult(raw)
    if isinstance(raw, str):
        choice = _STR_TO_CHOICE.get(raw.strip().lower())
        if choice is not None:
            return AskResult(choice)
    # Anything unrecognised is treated as a denial — the secure default.
    return AskResult(AskChoice.DENY, note=f"unrecognised approval response: {raw!r}")
