"""Shared scenario id/name mapping for Drill findings (used by runner + generative)."""
from __future__ import annotations

_PREFIX = {
    "prompt_injection_direct": "DRILL-PI",
    "prompt_injection_indirect": "DRILL-PII",
    "data_exfiltration": "DRILL-EXF",
    "jailbreak": "DRILL-JB",
    "tool_misuse": "DRILL-TM",
    "mcp_hijack": "DRILL-MCP",
}
_NAME = {
    "prompt_injection_direct": "Prompt Injection (direct)",
    "prompt_injection_indirect": "Prompt Injection (indirect)",
    "data_exfiltration": "Data Exfiltration",
    "jailbreak": "Jailbreak",
    "tool_misuse": "Tool Misuse",
    "mcp_hijack": "MCP Hijack / Tool Poisoning",
}


def scenario_id(attack) -> str:
    return f"{_PREFIX.get(attack.category, 'DRILL')}:{attack.id}"


def scenario_name(category: str) -> str:
    return _NAME.get(category, category)
