"""
blastcontain_guard.adapters — surface the tool-call boundary to Guard.

The bulk of integrating Guard is small adapters that intercept a framework's
tool calls and hand them to ``guard.check`` (guard-spec §6). Each is independent
and ships incrementally:

  * ``wrap_callable`` / ``@guard.tool`` — the generic decorator for hand-rolled
    agents (``generic``);
  * ``MCPMiddleware``  — wrap the MCP client/server call path; the
    highest-leverage first adapter, since many side-of-desk copilots speak MCP;
  * ``ClaudeCodeHook`` — the ``PreToolUse`` hook, mapping allow/ask/deny to
    Claude Code's own permission decision.

LangChain/LangGraph and the OpenAI/Anthropic SDK wrappers are the same shape and
are planned next (guard-spec §6).
"""
from __future__ import annotations

from .claude_code import ClaudeCodeHook, run_hook
from .generic import wrap_callable
from .mcp import MCPMiddleware

__all__ = ["MCPMiddleware", "ClaudeCodeHook", "run_hook", "wrap_callable"]
