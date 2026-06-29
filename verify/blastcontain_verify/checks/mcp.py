"""
MCP checks: MCP-01, MCP-02, MCP-03.

MCP-01  Unapproved MCP tool (not in Charter permitted_tools)
MCP-02  MCP server without authentication
MCP-03  Dangerous MCP tool capability combination
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

from ..contract import CheckContext, CheckGroupResult
from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP, MCP_CAPABILITY_CATEGORIES, MCP_DANGEROUS_PAIRS
from ..augmentation import CISCO_MCP_AVAILABLE, get_mcp_scanner


def _finding(check_id: str, finding_type: str, severity: Severity,
             title: str, detail: str, remediation: str,
             references: Optional[list[str]] = None,
             evidence: Optional[str] = None) -> InfraFinding:
    mit = MIT_RISK_MAP.get(finding_type, (None, None, None))
    return InfraFinding(
        check_id=check_id, finding_type=finding_type, severity=severity,
        title=title, detail=detail, remediation=remediation,
        references=references or [], evidence=evidence,
        mit_domain=mit[0], mit_causal_id=mit[1], mit_causal_label=mit[2],
    )


def _load_mcp_config(mcp_config: str) -> Optional[dict]:
    try:
        content = Path(mcp_config).read_text(errors="replace")
        return json.loads(content)
    except Exception:
        return None


def _get_mcp_servers(config: dict) -> list[dict]:
    """Extract server list from Claude-style mcpServers config."""
    servers = []
    mcp_servers = config.get("mcpServers", config.get("mcp_servers", {}))
    if isinstance(mcp_servers, dict):
        for name, spec in mcp_servers.items():
            if isinstance(spec, dict):
                spec["_name"] = name
                servers.append(spec)
    elif isinstance(mcp_servers, list):
        servers = mcp_servers
    return servers


def _categorise_tool(tool_name: str) -> set[str]:
    """Return the set of capability categories a tool name matches."""
    name_lower = tool_name.lower()
    cats: set[str] = set()
    for cat, patterns in MCP_CAPABILITY_CATEGORIES.items():
        if any(p in name_lower for p in patterns):
            cats.add(cat)
    return cats


def check_mcp01_unapproved_tools(
    mcp_config: Optional[str],
    permitted_tools: Optional[list[str]],
    cisco_api_key: str = "",
) -> tuple[list[InfraFinding], str, str]:
    """MCP-01: Tools not in Charter permitted_tools list."""
    if not mcp_config:
        return [], "SKIP", "--mcp-config not provided"

    config = _load_mcp_config(mcp_config)
    if not config:
        return [], "SKIP", "MCP config could not be parsed"

    servers = _get_mcp_servers(config)
    if not servers:
        return [], "SKIP", "no MCP servers defined in config"

    # Collect tool names from servers using Cisco scanner if available
    observed_tools: set[str] = set()

    if CISCO_MCP_AVAILABLE:
        scanner = get_mcp_scanner(api_key=cisco_api_key)
        if scanner:
            for server in servers:
                url = server.get("url") or server.get("baseUrl", "")
                command = server.get("command", "")
                try:
                    if url and url.startswith("http"):
                        from ..augmentation import AnalyzerEnum
                        analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
                        result = asyncio.run(scanner.scan_remote_server_tools(url=url, analyzers=analyzers))
                    elif command:
                        from ..augmentation import AnalyzerEnum
                        analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
                        cmd_parts = command.split() if isinstance(command, str) else command
                        result = asyncio.run(scanner.scan_stdio_server_tools(command=cmd_parts, analyzers=analyzers))
                    else:
                        continue
                    if hasattr(result, "tools"):
                        for tool in result.tools:
                            observed_tools.add(getattr(tool, "name", str(tool)))
                except Exception:
                    pass

    # If no Cisco scanner, use names from the config itself
    if not observed_tools:
        for server in servers:
            tools = server.get("tools") or server.get("allowed_tools", [])
            for t in tools:
                if isinstance(t, str):
                    observed_tools.add(t)
                elif isinstance(t, dict):
                    observed_tools.add(t.get("name", ""))

    if permitted_tools is None:
        return [], "SKIP", (
            "No Charter permitted_tools list — MCP-01 disabled until Charter is wired"
        )
    if not observed_tools:
        return [], "SKIP", "no MCP tools observed to evaluate"

    permitted_set = {t.lower() for t in permitted_tools}
    unapproved = [t for t in observed_tools if t.lower() not in permitted_set]

    if not unapproved:
        return [], "PASS", ""

    return [_finding(
        check_id="MCP-01",
        finding_type="blastcontain.mcp.unapproved_tool",
        severity=Severity.HIGH,
        title="Unapproved MCP Tools Detected",
        detail=(
            f"Found {len(unapproved)} MCP tool(s) not in the agent Charter "
            f"`permitted_tools` list: {', '.join(sorted(unapproved)[:5])}. "
            "Unapproved tools extend the agent's capability surface beyond what "
            "was declared and authorised."
        ),
        remediation=(
            "For each unapproved tool:\n"
            "1. If legitimate: add to Charter `permitted_tools` and get sign-off.\n"
            "2. If not required: remove from the MCP server configuration.\n"
            "Enable AGT MCP Security Gateway (default-deny) to enforce the allowlist."
        ),
        evidence=f"Unapproved: {', '.join(sorted(unapproved)[:5])}",
    )], "FAIL", ""


def check_mcp02_missing_auth(mcp_config: Optional[str]) -> tuple[list[InfraFinding], str, str]:
    """MCP-02: MCP server without authentication."""
    if not mcp_config:
        return [], "SKIP", "--mcp-config not provided"

    config = _load_mcp_config(mcp_config)
    if not config:
        return [], "SKIP", "MCP config could not be parsed"

    servers = _get_mcp_servers(config)
    if not servers:
        return [], "SKIP", "no MCP servers defined in config"

    # Flag each problematic server exactly once, collecting all of its issues.
    # Auth is only meaningful for network-reachable (http/https) servers; a
    # stdio `command` server is a local subprocess and needs no network auth.
    unauth: list[str] = []
    for server in servers:
        name = server.get("_name") or server.get("name", "unknown")
        url = server.get("url") or server.get("baseUrl", "")
        command = server.get("command")
        auth = server.get("auth") or server.get("authentication") or server.get("apiKey")

        is_network = bool(url) and not command
        issues: list[str] = []
        if is_network and not auth:
            issues.append("no auth")
        if url.startswith("http://"):
            issues.append("HTTP — plaintext")

        if issues:
            unauth.append(f"{name} ({'; '.join(issues)})")

    if not unauth:
        return [], "PASS", ""

    return [_finding(
        check_id="MCP-02",
        finding_type="blastcontain.mcp.missing_auth",
        severity=Severity.HIGH,
        title="MCP Server Without Authentication",
        detail=(
            f"Found {len(unauth)} MCP server(s) with no authentication configured: "
            f"{', '.join(unauth[:5])}. An unauthenticated MCP server can be called "
            "by any agent or process that can reach it, not just the authorised agent."
        ),
        remediation=(
            "Add authentication to every MCP server:\n"
            "  In config:  `auth: {type: bearer, token: $MCP_TOKEN}`\n"
            "  Use HTTPS:  replace `http://` with `https://`\n"
            "  Dev only:   bind to `127.0.0.1` if auth cannot be added immediately."
        ),
        evidence=f"Unauth servers: {', '.join(unauth[:5])}",
    )], "FAIL", ""


def check_mcp03_dangerous_combinations(
    mcp_config: Optional[str],
    cisco_api_key: str = "",
) -> tuple[list[InfraFinding], str, str]:
    """MCP-03: Dangerous MCP tool capability combination."""
    if not mcp_config:
        return [], "SKIP", "--mcp-config not provided"

    config = _load_mcp_config(mcp_config)
    if not config:
        return [], "SKIP", "MCP config could not be parsed"

    servers = _get_mcp_servers(config)
    if not servers:
        return [], "SKIP", "no MCP servers defined in config"

    # Collect all tool names across all servers
    all_tools: list[str] = []
    for server in servers:
        tools = server.get("tools") or server.get("allowed_tools", [])
        for t in tools:
            name = t if isinstance(t, str) else t.get("name", "")
            if name:
                all_tools.append(name)

    if not all_tools:
        return [], "SKIP", "no MCP tools defined in config"

    # Determine active categories
    active_categories: set[str] = set()
    for tool in all_tools:
        active_categories.update(_categorise_tool(tool))

    if len(active_categories) < 2:
        return [], "PASS", ""

    # Check for dangerous pairs
    worst_severity: Optional[str] = None
    triggered_pairs: list[str] = []

    severity_rank = {"CRITICAL": 2, "HIGH": 1}

    for cat_a, cat_b, attack, sev in MCP_DANGEROUS_PAIRS:
        if cat_a in active_categories and cat_b in active_categories:
            triggered_pairs.append(f"{cat_a}+{cat_b} ({attack})")
            if worst_severity is None or severity_rank.get(sev, 0) > severity_rank.get(worst_severity, 0):
                worst_severity = sev

    if not triggered_pairs:
        return [], "PASS", ""

    severity = Severity.CRITICAL if worst_severity == "CRITICAL" else Severity.HIGH
    tools_preview = ", ".join(all_tools[:8])

    return [_finding(
        check_id="MCP-03",
        finding_type="blastcontain.mcp.dangerous_combination",
        severity=severity,
        title=f"Dangerous MCP Tool Combination Detected ({len(triggered_pairs)} pair(s))",
        detail=(
            f"The agent's MCP servers provide {len(active_categories)} capability "
            f"categories that form {len(triggered_pairs)} dangerous pair(s): "
            f"{'; '.join(triggered_pairs[:3])}. "
            "These combinations create end-to-end attack chains — an attacker can "
            "read data then send it, or drop and execute arbitrary code."
        ),
        remediation=(
            "Remove capabilities not required for the agent's stated purpose. "
            "Separate dangerous capabilities across different agents with different "
            "trust tiers rather than combining them in one agent. "
            "Use AGT PolicyEngine to restrict tool invocation order and context."
        ),
        evidence=(
            f"Active categories: {', '.join(sorted(active_categories))} | "
            f"Tools: {tools_preview}"
        ),
    )], "FAIL", ""


def run(ctx: CheckContext) -> CheckGroupResult:
    mcp_config = ctx.cfg.mcp_config
    cisco_api_key = ctx.cfg.cisco_api_key
    # Charter integration is deferred (blocked on the platform UI/server that
    # issues Charters). Until then MCP-01 SKIPs: no allowlist to compare against.
    permitted_tools: Optional[list[str]] = None
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    checks = [
        ("MCP-01", check_mcp01_unapproved_tools,      [mcp_config, permitted_tools, cisco_api_key]),
        ("MCP-02", check_mcp02_missing_auth,           [mcp_config]),
        ("MCP-03", check_mcp03_dangerous_combinations, [mcp_config, cisco_api_key]),
    ]

    for check_id, fn, args in checks:
        result_findings, status, reason = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": reason})
        else:
            findings.extend(result_findings)

    return CheckGroupResult(findings=findings, passed=passed, skipped=skipped)
