"""The Claude Code PreToolUse hook adapter."""
import io
import json

from blastcontain_guard import Guard
from blastcontain_guard.adapters.claude_code import ClaudeCodeHook, classify_tool, run_hook

NO_EXEC = {
    "default_action": "allow",
    "rules": [{"name": "no-shell", "condition": "action.type == 'exec'", "action": "deny"}],
}


def test_classify_builtin_tools():
    assert classify_tool("Bash") == "exec"
    assert classify_tool("Read") == "read"
    assert classify_tool("Write") == "write"
    assert classify_tool("WebFetch") == "send"
    # MCP / unknown falls back to the name heuristic
    assert classify_tool("mcp__db__delete_row") == "delete"


def test_decide_maps_to_permission_decision():
    hook = ClaudeCodeHook(Guard.from_dict(NO_EXEC, agent_id="cc"))
    out = hook.decide({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
    block = out["hookSpecificOutput"]
    assert block["hookEventName"] == "PreToolUse"
    assert block["permissionDecision"] == "deny"
    assert "blastcontain-guard" in block["permissionDecisionReason"]


def test_decide_allows_read():
    hook = ClaudeCodeHook(Guard.from_dict(NO_EXEC, agent_id="cc"))
    out = hook.decide({"tool_name": "Read", "tool_input": {"file_path": "x"}})
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_ask_passes_through_to_claude_code():
    rs = {"default_action": "deny",
          "rules": [{"name": "ask-write", "condition": "action.type == 'write'",
                     "action": "require_approval", "approvers": ["self"]}]}
    hook = ClaudeCodeHook(Guard.from_dict(rs, agent_id="cc"))
    out = hook.decide({"tool_name": "Write", "tool_input": {"file_path": "x"}})
    # Guard says 'ask'; Claude Code renders the prompt itself.
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_run_hook_roundtrip():
    guard = Guard.from_dict(NO_EXEC, agent_id="cc")
    stdin = io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}))
    stdout = io.StringIO()
    rc = run_hook(guard, stdin=stdin, stdout=stdout)
    assert rc == 0
    out = json.loads(stdout.getvalue())
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    # the decision was recorded
    assert guard.decisions[-1]["data"]["final"] == "deny"


def test_run_hook_fails_open_on_bad_json():
    guard = Guard.from_dict(NO_EXEC, agent_id="cc")
    stdout = io.StringIO()
    run_hook(guard, stdin=io.StringIO("}{ not json"), stdout=stdout, fail_open=True)
    out = json.loads(stdout.getvalue())
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
