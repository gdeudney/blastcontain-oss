"""
blastcontain_guard.adapters.claude_code — the Claude Code ``PreToolUse`` hook.

Claude Code runs a hook before each tool use, passing the tool call as JSON on
stdin and reading a permission decision from stdout. Guard's allow/ask/deny maps
one-to-one onto Claude Code's ``permissionDecision`` (``allow``/``ask``/``deny``):
Guard *evaluates*, and Claude Code itself renders the *ask* in its own UI — so
the hook does not own the approval round-trip, it just reports the decision and
records it.

Wire it up in ``.claude/settings.json``::

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "*", "hooks": [
            {"type": "command",
             "command": "blastcontain-guard hook --policy .blastcontain/policy.yaml"}
          ]}
        ]
      }
    }

A malformed event or an internal hook error fails **open** (allow, with a stderr
warning) rather than bricking the editor — the genuine enforcement front is the
decision, and a broken integration shouldn't wedge the user's session. The
out-of-process choke point (§9) is where you put controls that must hold even
when an in-process front is bypassed.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Optional

from ..constants import infer_action_type
from ..models import Action

# Claude Code's built-in tools -> action verb. MCP tools (mcp__server__tool) and
# anything unlisted fall back to the name heuristic.
_CLAUDE_TOOL_ACTIONS: dict[str, str] = {
    "Bash": "exec",
    "Task": "exec",
    "Read": "read",
    "Glob": "read",
    "Grep": "read",
    "LS": "read",
    "NotebookRead": "read",
    "Write": "write",
    "Edit": "write",
    "MultiEdit": "write",
    "NotebookEdit": "write",
    "WebFetch": "send",     # outbound request — egress, can exfiltrate via URL
    "WebSearch": "send",
}

_ACTION_TO_PERMISSION = {
    Action.ALLOW: "allow",
    Action.ASK: "ask",
    Action.DENY: "deny",
}


def classify_tool(tool_name: str) -> str:
    """Map a Claude Code tool name to an action verb."""
    if tool_name in _CLAUDE_TOOL_ACTIONS:
        return _CLAUDE_TOOL_ACTIONS[tool_name]
    return infer_action_type(tool_name)


class ClaudeCodeHook:
    """Adapts a Guard to Claude Code's ``PreToolUse`` hook contract."""

    def __init__(self, guard: Any = None):
        self.guard = guard

    def bind(self, guard: Any) -> None:
        self.guard = guard

    def decide(self, event: dict) -> dict:
        """Evaluate a PreToolUse event and return the hook output mapping."""
        if self.guard is None:
            raise RuntimeError("ClaudeCodeHook is not bound to a Guard")

        tool_name = str(event.get("tool_name", "") or "")
        tool_input = event.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {"value": tool_input}

        decision = self.guard.evaluate_and_emit(
            tool_name, action_type=classify_tool(tool_name), args=tool_input
        )
        permission = _ACTION_TO_PERMISSION.get(decision.action, "ask")
        reason = decision.reason
        if decision.risk_tag:
            reason = f"{reason} — {decision.risk_tag}"
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission,
                "permissionDecisionReason": f"blastcontain-guard: {reason}",
            }
        }


def run_hook(
    guard: Any,
    stdin: Optional[Any] = None,
    stdout: Optional[Any] = None,
    fail_open: bool = True,
) -> int:
    """Read a PreToolUse event from stdin, write the decision to stdout.

    Returns a process exit code (0). On error, fails open (allow) by default.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    try:
        raw = stdin.read()
        event = json.loads(raw) if raw.strip() else {}
        output = ClaudeCodeHook(guard).decide(event)
    except Exception as exc:  # never wedge the editor on an integration bug
        if not fail_open:
            raise
        print(f"blastcontain-guard hook error (failing open): {exc}", file=sys.stderr)
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": f"blastcontain-guard hook error: {exc}",
            }
        }
    json.dump(output, stdout)
    stdout.write("\n")
    try:
        guard.flush()
    except Exception:
        pass
    return 0
