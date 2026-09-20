"""Passive MCP target assessment. Never connects to or starts a configured server."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from .config import VerifyConfig
from .contract import CheckContext, ScanState
from .models import InfraFinding, ScanResult, ScanStatus, Severity
from .checks.mcp import _categorise_tool
from .constants import MCP_DANGEROUS_PAIRS

_ID = re.compile(r"[A-Za-z0-9_.:/-]{1,128}\Z")
_MAX_INPUT = 2 * 1024 * 1024


@dataclass
class MCPTargetResult(ScanResult):
    target: dict = field(default_factory=dict)
    inventory: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        data = super().as_dict()
        data.pop("agent_id")
        data.update(target=self.target, inventory=self.inventory, coverage=self.coverage)
        return data


def _read_json(path: str) -> tuple[dict, str]:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(_MAX_INPUT + 1)
        if len(raw) > _MAX_INPUT:
            raise ValueError
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
    except (OSError, ValueError, TypeError, RecursionError):
        # Parser messages can echo secrets from input. Do not include them.
        raise ValueError("Input must be a readable JSON object of at most 2 MiB") from None
    return value, hashlib.sha256(raw).hexdigest()


def _identifier(value: object) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Identifiers must be 1–128 letters, digits or _ . : / -")
    return value


def validate_target_config(cfg: VerifyConfig) -> None:
    if cfg.target_type not in ("agent", "mcp"):
        raise ValueError("target_type must be agent or mcp")
    if cfg.target_type == "agent":
        if cfg.target_id or cfg.mcp_server or cfg.policy or cfg.scan_scope:
            raise ValueError("--target-id, --mcp-server, --policy and --scan-scope require --target-type mcp")
        if not cfg.agent_id:
            raise ValueError("--agent-id is required (or set agent_id in config file)")
        return
    _identifier(cfg.target_id)
    if cfg.agent_id:
        raise ValueError("Use --target-id, not --agent-id, for an MCP target")
    if not cfg.mcp_config:
        raise ValueError("--mcp-config is required for an MCP target")
    if cfg.scan_scope not in (None, "config", "runtime"):
        raise ValueError("scan_scope must be config or runtime")
    if cfg.scan_scope == "runtime" and not Path(cfg.search_path).is_dir():
        raise ValueError("Runtime --search-path must be an existing directory")
    if cfg.blastcontain_url:
        raise ValueError("MCP Ledger ingestion is not supported yet; use local output files")
    if cfg.api_live_probe:
        raise ValueError("MCP assessment does not support live API probes")


def run_mcp_scan(cfg: VerifyConfig) -> MCPTargetResult:
    from .registry import BUILTIN_GROUPS
    from .scanner import _apply_skip_filter

    validate_target_config(cfg)
    result = MCPTargetResult(
        agent_id="", environment=cfg.environment,
        target={"type": "mcp", "id": cfg.target_id,
                "scope": cfg.scan_scope or "config", "evidence_source": "declared_configuration"},
    )
    required = {f"MCP-{number:02}" for number in range(1, 7)}
    errored = False

    def skip(check: str, reason: str) -> None:
        result.skipped.append({"check_id": check, "reason": reason})

    def finding(check: str, title: str, detail: str, remediation: str,
                severity: Severity = Severity.HIGH) -> None:
        result.findings.append(InfraFinding(
            check_id=check, finding_type=f"blastcontain.mcp.{check.lower().replace('-', '_')}",
            severity=severity, title=title, detail=detail, remediation=remediation,
            evidence="Declared configuration; no server calls performed",
        ))

    try:
        config, digest = _read_json(cfg.mcp_config)
        servers = config.get("mcpServers", config.get("mcp_servers"))
        if not isinstance(servers, dict) or not servers:
            raise ValueError("MCP config must contain a non-empty mcpServers object")
        if not cfg.mcp_server and len(servers) != 1:
            raise ValueError("Select one server with --mcp-server when config contains multiple servers")
        name = _identifier(cfg.mcp_server or next(iter(servers)))
        server = servers.get(name)
        if not isinstance(server, dict):
            raise ValueError("Selected MCP server is absent or is not an object")
        command, url = server.get("command"), server.get("url", server.get("baseUrl"))
        if bool(command) == bool(url):
            raise ValueError("Selected server must define exactly one command or URL")
        if command and (not isinstance(command, str) or not command.strip()):
            raise ValueError("stdio command must be a non-empty string")
        if url:
            if not isinstance(url, str):
                raise ValueError("Server URL must be a string")
            parsed = urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname:
                raise ValueError("Server URL must use HTTP or HTTPS with a host")
            # Also validate port syntax, without echoing the supplied URL.
            try:
                parsed.port
            except ValueError:
                raise ValueError("Invalid server URL port") from None
        transport = "stdio" if command else "http"
        if url:
            required.discard("MCP-06")
        declared_transport = server.get("type", server.get("transport"))
        if declared_transport is not None and declared_transport not in (
            ("stdio",) if command else ("http", "sse", "streamable-http")
        ):
            raise ValueError("Declared transport conflicts with the server command/URL")
        for key in ("env", "headers"):
            value = server.get(key, {})
            if not isinstance(value, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                   for k, v in value.items()):
                raise ValueError(f"{key} must map string names to string values")
        args = server.get("args", [])
        if not isinstance(args, list) or any(not isinstance(a, str) for a in args):
            raise ValueError("args must be a list of strings")
        result.target["server_name"] = name
        result.inventory = {"source_sha256": digest, "transport": transport,
                            "tools": [], "tools_declared": "tools" in server}
        if "tools" in server:
            tools = server["tools"]
            if not isinstance(tools, list):
                raise ValueError("tools must be a list of names or tool objects")
            seen = set()
            for tool in tools:
                tool_name = _identifier(tool.get("name") if isinstance(tool, dict) else tool)
                if tool_name in seen:
                    raise ValueError("Duplicate tool names in selected server")
                seen.add(tool_name)
                entry = {"name": tool_name, "evidence_source": "declared_configuration"}
                if isinstance(tool, dict) and "inputSchema" in tool:
                    if not isinstance(tool["inputSchema"], dict):
                        raise ValueError("Tool inputSchema must be an object")
                    entry["input_schema_sha256"] = hashlib.sha256(
                        json.dumps(tool["inputSchema"], sort_keys=True).encode()
                    ).hexdigest()
                entry["capability_hints"] = sorted(_categorise_tool(tool_name))
                result.inventory["tools"].append(entry)
            result.passed.append("MCP-04")
        else:
            skip("MCP-04", "Tool inventory not declared; no live discovery performed")

        # MCP-02 is a configuration check, not proof that authentication works.
        auth = server.get("auth", server.get("authentication"))
        if auth is not None and not isinstance(auth, dict):
            raise ValueError("auth/authentication must be an object")
        auth_configured = bool(auth) and auth.get("type") not in ("none", "anonymous") and auth.get("enabled") is not False
        has_auth = auth_configured or bool(server.get("apiKey")) or any(
            key.lower() == "authorization" and value.strip()
            for key, value in server.get("headers", {}).items()
        )
        if url and (parsed.scheme == "http" or not has_auth):
            finding("MCP-02", "Network MCP authentication/transport configuration risk",
                    "Plaintext HTTP or missing authentication configuration was declared. "
                    "Authentication behavior has not been tested.",
                    "Use HTTPS and configure authentication; validate enforcement separately.")
        else:
            result.passed.append("MCP-02")

        if cfg.policy:
            policy, policy_hash = _read_json(cfg.policy)
            if set(policy) != {"target_id", "permitted_tools"} or policy["target_id"] != cfg.target_id:
                raise ValueError("Policy requires matching target_id and permitted_tools only")
            permitted = policy["permitted_tools"]
            if not isinstance(permitted, list):
                raise ValueError("permitted_tools must be a list")
            permitted = {_identifier(tool) for tool in permitted}
            result.target["policy_sha256"] = policy_hash
            if not result.inventory["tools_declared"]:
                skip("MCP-01", "No declared tools to compare with local policy")
            else:
                unapproved = [t["name"] for t in result.inventory["tools"] if t["name"] not in permitted]
                if unapproved:
                    finding("MCP-01", "Declared tools outside local allowlist",
                            "Unapproved tools: " + ", ".join(unapproved),
                            "Remove unneeded tools or explicitly review the local policy.")
                else:
                    result.passed.append("MCP-01")
        else:
            skip("MCP-01", "No local --policy; expected tool permissions are unknown")

        if result.inventory["tools_declared"]:
            categories = {c for t in result.inventory["tools"] for c in t["capability_hints"]}
            pairs = [description for a, b, description, _ in MCP_DANGEROUS_PAIRS
                     if a in categories and b in categories]
            if pairs:
                finding("MCP-03", "Potentially dangerous declared tool combination",
                        "Name-based heuristic only: " + "; ".join(pairs),
                        "Review actual per-tool permissions and separate unnecessary capabilities.")
            else:
                result.passed.append("MCP-03")
        else:
            skip("MCP-03", "Tool inventory unavailable for capability heuristics")

        # Report risk without serializing environment values, URLs or command args.
        inline_secret = any(
            re.search(r"TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY", key, re.I)
            and value and not re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value)
            for key, value in server.get("env", {}).items()
        )
        credential_values = [server.get("apiKey", "")]
        credential_values += [value for key, value in (auth or {}).items()
                              if re.search(r"token|secret|password|key", key, re.I)]
        credential_values += [value for key, value in server.get("headers", {}).items()
                              if re.search(r"authorization|api.key|token", key, re.I)]
        embedded_auth = any(isinstance(value, str) and value
                            and not re.fullmatch(r"(?:Bearer )?\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", value)
                            for value in credential_values)
        url_credentials = bool(url and (parsed.username or parsed.password or parsed.query))
        if inline_secret or url_credentials or embedded_auth:
            finding("MCP-05", "Credential material may be embedded in MCP configuration",
                    "Secret-like environment values or URL credentials/query parameters are present; values omitted.",
                    "Use scoped runtime credential injection; remove credentials from URLs and tracked config.")
        else:
            result.passed.append("MCP-05")
        if command:
            dangerous = any(a in ("--privileged", "--network=host", "--pid=host")
                            or "docker.sock" in a or "podman.sock" in a
                            or a.startswith("--cap-add") for a in args)
            if dangerous:
                finding("MCP-06", "Broad privileges declared in MCP launch arguments",
                        "Launch arguments request host access, capabilities or a container runtime socket.",
                        "Remove broad launch privileges and limit mounts and service access.")
            else:
                result.passed.append("MCP-06")
        else:
            skip("MCP-06", "Not applicable: HTTP configuration has no local launch command")
    except (ValueError, TypeError, RecursionError):
        errored = True
        # Only controlled messages; urlsplit errors may contain portions of input.
        finding("SCAN-MCP", "MCP assessment input could not be evaluated",
                "Invalid configuration or policy. Check JSON shape, server selection, transport and identifiers.",
                "See docs/mcp.md for the accepted configuration and policy schema.")

    # No plugins in this passive profile: installed plugins may execute arbitrary code.
    runtime_groups = {"process", "filesystem", "persistence", "local", "credentials", "code", "tls"}
    ctx = CheckContext(cfg, ScanState())
    for group in BUILTIN_GROUPS:
        if group.name == "mcp":
            continue
        if cfg.scan_scope == "runtime" and group.name in runtime_groups and not errored:
            required.update(group.provides)
            if group.name == "filesystem":
                workstation = "workstation" in cfg.environment.lower() or "local" in cfg.environment.lower()
                required.discard("DISK-02" if workstation else "DISK-01")
            try:
                checks = group.run(ctx)
                result.findings.extend(checks.findings)
                result.passed.extend(checks.passed)
                for skipped in checks.skipped:
                    if (skipped["check_id"] == "LOCAL-01"
                            and skipped.get("reason") == "No workstation indicators detected"):
                        skipped["category"] = "not_applicable"
                        required.discard("LOCAL-01")
                result.skipped.extend(checks.skipped)
            except Exception:
                errored = True
                finding("SCAN-" + group.name.upper(), "Runtime check group failed",
                        "Runtime evidence is incomplete; exception text omitted to protect secrets.",
                        "Inspect the runtime and retry the scan.")
        else:
            for check in sorted(group.provides):
                skip(check, "Local runtime not observed; use --scan-scope runtime in the target context"
                     if group.name in runtime_groups and cfg.scan_scope != "runtime"
                     else "Outside the initial MCP assessment profile")

    skip_set = {c.strip().upper() for c in cfg.skip_checks if c.strip()}
    result.findings, result.passed, result.skipped = _apply_skip_filter(
        result.findings, result.passed, result.skipped, skip_set,
    )
    assessed = set(result.passed) | {f.check_id for f in result.findings}
    missing = sorted(required - assessed)
    result.coverage = {
        "profile": "mcp-passive-v1", "complete": not errored and not missing,
        "required_checks": sorted(required), "missing_required_checks": missing,
        "runtime_observed": cfg.scan_scope == "runtime" and not errored,
        "runtime_attribution": "invoking process; operator must run in target context"
        if cfg.scan_scope == "runtime" else "not observed",
        "check_evidence": {
            check: ("declared_configuration" if check.startswith("MCP-") else "local_observation")
            for check in sorted(assessed) if not check.startswith("SCAN-")
        },
        "authentication_validated": False, "tools_invoked": False,
        "feature_coverage": {
            "capabilities_and_connections": "declared tools and name-based hints only; adjacency unvalidated",
            "runtime_containment": "partial local observations" if cfg.scan_scope == "runtime" else "not assessed",
            "scoped_authorization": "declared tool allowlist only; per-call/resource enforcement unvalidated",
            "identity_and_credentials": "configuration credential hints only; delegation and token validation unvalidated",
            "egress_restrictions": "not assessed; no network probes",
            "exact_action_approval": "not assessed",
            "replay_and_cumulative_limits": "not assessed",
            "untrusted_inputs_and_outputs": "not assessed",
            "dependencies_and_changes": "config and schema hashes only; dependencies not audited",
            "audit_and_independent_stopping": "scan evidence only; target audit and revocation unvalidated",
        },
        "limitations": ["Declared tools may differ from exposed tools", "No live control validation",
                        "Name-based capabilities are heuristic", "No third-party check plugins executed"],
    }
    result.status = ScanStatus.ERROR if not result.coverage["complete"] else result.derive_status()
    return result
