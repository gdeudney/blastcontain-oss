"""
blastcontain_guard.adapters.mcp — guard the MCP tool-call path.

The highest-leverage adapter: many side-of-desk copilots speak MCP, so one
adapter governs many hosts (guard-spec §6). MCP tool invocations are
``(tool_name, arguments) -> result``; this middleware evaluates each against the
Charter before the real handler runs.

It is intentionally SDK-agnostic — wrap whatever callable your server/client
uses (FastMCP's ``@mcp.tool`` target, ``mcp.server`` ``call_tool`` handler, a
client's ``call_tool``). On *deny*/refused *ask* you choose the failure mode:
raise ``GuardDenied`` (let the host map it), or return a default MCP-style error
result (``isError: true`` with the reason as text), which most hosts surface to
the model without crashing the session.
"""
from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable, Optional

from ..errors import GuardDenied
from ..models import EnforcementResult


def blocked_result(result: EnforcementResult) -> dict:
    """An MCP ``CallToolResult``-shaped error the host can surface to the model."""
    decision = result.decision
    reason = decision.reason
    if decision.requires_central:
        reason += " (mandatory Standard — request a central Exception to proceed)"
    return {
        "isError": True,
        "content": [
            {
                "type": "text",
                "text": (
                    f"⛔ blastcontain-guard blocked '{result.tool_name}' "
                    f"({decision.action.value}): {reason}"
                ),
            }
        ],
    }


class MCPMiddleware:
    """Evaluate MCP tool calls through Guard before they execute."""

    def __init__(self, guard: Any = None, *, raise_on_deny: bool = False):
        self.guard = guard
        self.raise_on_deny = raise_on_deny

    def bind(self, guard: Any) -> None:
        """Called by ``guard.attach(self)`` to wire in the Guard instance."""
        self.guard = guard

    def intercept(
        self, tool_name: str, arguments: Optional[dict] = None, *, action_type: Optional[str] = None
    ) -> EnforcementResult:
        """Evaluate a single MCP tool call. Returns the EnforcementResult."""
        if self.guard is None:
            raise RuntimeError("MCPMiddleware is not bound to a Guard (call guard.attach(mw))")
        return self.guard.check(tool_name, action_type=action_type, args=arguments or {})

    def _deny(self, result: EnforcementResult) -> Any:
        if self.raise_on_deny:
            raise GuardDenied(result)
        return blocked_result(result)

    def wrap_handler(
        self,
        handler: Callable[..., Any],
        *,
        action_type: Optional[str] = None,
    ) -> Callable[..., Any]:
        """Wrap a ``(tool_name, arguments) -> result`` handler with enforcement.

        Works for sync or ``async`` handlers (FastMCP / mcp.server are async).
        """
        if inspect.iscoroutinefunction(handler):
            async def async_wrapper(tool_name: str, arguments: Optional[dict] = None) -> Any:
                result = self.intercept(tool_name, arguments, action_type=action_type)
                if not result.allowed:
                    return self._deny(result)
                outcome: Awaitable[Any] = handler(tool_name, arguments)
                return await outcome

            return async_wrapper

        def sync_wrapper(tool_name: str, arguments: Optional[dict] = None) -> Any:
            result = self.intercept(tool_name, arguments, action_type=action_type)
            if not result.allowed:
                return self._deny(result)
            return handler(tool_name, arguments)

        return sync_wrapper
