"""
API checks: API-01, API-02.

API-01  Destructive API permissions in OpenAPI spec (with live OPTIONS probe)
API-02  Unauthenticated destructive endpoints
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP

_DESTRUCTIVE_METHODS = {"DELETE", "PUT", "PATCH"}
_DESTRUCTIVE_POST_KEYWORDS = {
    "delete", "remove", "purge", "destroy", "drop", "truncate",
    "wipe", "reset", "flush", "erase",
}


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


def _load_openapi(api_spec: str) -> Optional[dict]:
    try:
        content = Path(api_spec).read_text(errors="replace")
        if api_spec.endswith((".yaml", ".yml")):
            import yaml  # type: ignore
            return yaml.safe_load(content)
        return json.loads(content)
    except Exception:
        return None


def _live_probe_allows(url: str, path: str, method: str) -> bool:
    """Do a live OPTIONS probe to check if a method is allowed."""
    try:
        import httpx  # type: ignore
        full_url = url.rstrip("/") + path
        resp = httpx.options(full_url, timeout=5)
        allow_header = resp.headers.get("allow", "")
        return method.upper() in allow_header.upper()
    except Exception:
        return False


def check_api01_destructive_permissions(
    api_spec: Optional[str],
    live_probe: bool = False,
) -> tuple[list[InfraFinding], str]:
    """
    API-01: Destructive API permissions.

    live_probe: when True, sends HTTP OPTIONS to each spec server URL to
    confirm the endpoint is reachable. OFF by default — live probes break
    the offline guarantee and let a malicious spec coax the scanner into
    sending outbound HTTP to attacker-controlled URLs.
    """
    if not api_spec:
        return [], "SKIP"

    spec = _load_openapi(api_spec)
    if not spec:
        return [], "SKIP"

    paths = spec.get("paths", {})
    servers = spec.get("servers", [])
    base_urls = [s.get("url", "") for s in servers if isinstance(s, dict)]

    destructive_endpoints: list[dict] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            method_upper = method.upper()
            if method_upper not in _DESTRUCTIVE_METHODS and method_upper != "POST":
                continue
            if method_upper == "POST":
                # Check operation id, summary, and path for destructive keywords
                op_id = str(operation.get("operationId", "")).lower()
                summary = str(operation.get("summary", "")).lower()
                path_lc = path.lower()
                if not any(
                    kw in op_id or kw in summary or kw in path_lc
                    for kw in _DESTRUCTIVE_POST_KEYWORDS
                ):
                    continue

            # Live probe — only when explicitly enabled
            confirmed_live = False
            if live_probe:
                for base_url in base_urls:
                    if base_url.startswith("http"):
                        confirmed_live = _live_probe_allows(base_url, path, method_upper)
                        if confirmed_live:
                            break

            destructive_endpoints.append({
                "path": path,
                "method": method_upper,
                "confirmed": confirmed_live,
            })

    if not destructive_endpoints:
        return [], "PASS"

    confirmed = [e for e in destructive_endpoints if e["confirmed"]]
    severity = (
        Severity.CRITICAL if confirmed
        else Severity.HIGH if any(e["method"] in _DESTRUCTIVE_METHODS for e in destructive_endpoints)
        else Severity.MEDIUM
    )

    endpoint_summary = "; ".join(
        f"{e['method']} {e['path']}{'(confirmed live)' if e['confirmed'] else ''}"
        for e in destructive_endpoints[:5]
    )

    return [_finding(
        check_id="API-01",
        finding_type="blastcontain.api.destructive_permission",
        severity=severity,
        title="Destructive API Permissions in Agent Tool Spec",
        detail=(
            f"Found {len(destructive_endpoints)} destructive endpoint(s) in the agent's "
            f"API specification{f', {len(confirmed)} confirmed live' if confirmed else ''}. "
            "An agent with DELETE/PUT/PATCH permissions can destroy or corrupt data "
            "if triggered by a prompt injection or delegation chain attack."
        ),
        remediation=(
            "Review each destructive endpoint:\n"
            "1. If not required: remove from the agent tool spec.\n"
            "2. If required: register in Charter `permitted_apis` with explicit "
            "   method and resource ID scope.\n"
            "3. Add AGT PolicyEngine policy to block destructive calls not matching "
            "   an expected resource ID pattern."
        ),
        evidence=endpoint_summary,
    )], "FAIL"


def check_api02_unauthenticated_endpoints(
    api_spec: Optional[str],
) -> tuple[list[InfraFinding], str]:
    """API-02: Destructive endpoints with no security scheme."""
    if not api_spec:
        return [], "SKIP"

    spec = _load_openapi(api_spec)
    if not spec:
        return [], "SKIP"

    paths = spec.get("paths", {})
    global_security = spec.get("security", [])
    unauth: list[str] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.upper() not in _DESTRUCTIVE_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            op_security = operation.get("security")
            # No per-operation security AND no global security = unauthenticated
            if op_security is None and not global_security:
                unauth.append(f"{method.upper()} {path}")
            elif op_security == []:  # Explicitly no security
                unauth.append(f"{method.upper()} {path} (explicitly unauthenticated)")

    if not unauth:
        return [], "PASS"

    return [_finding(
        check_id="API-02",
        finding_type="blastcontain.api.unauthenticated_endpoint",
        severity=Severity.HIGH,
        title="Destructive Endpoints Without Authentication",
        detail=(
            f"Found {len(unauth)} destructive endpoint(s) with no security scheme: "
            f"{'; '.join(unauth[:5])}. "
            "Unauthenticated destructive endpoints can be called by any agent in the "
            "delegation chain, not just the authorised principal."
        ),
        remediation=(
            "Add an authentication requirement to all destructive endpoints:\n"
            "  OpenAPI: `security: [{bearerAuth: []}]` on each path.\n"
            "  API gateway: enforce authentication before forwarding to the service.\n"
            "Use short-lived OAuth tokens scoped to the specific agent identity."
        ),
        evidence="; ".join(unauth[:5]),
    )], "FAIL"


def run(
    api_spec: Optional[str] = None,
    live_probe: bool = False,
    **_,
) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    checks = [
        ("API-01", check_api01_destructive_permissions,  [api_spec, live_probe]),
        ("API-02", check_api02_unauthenticated_endpoints, [api_spec]),
    ]

    for check_id, fn, args in checks:
        result_findings, status = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": "--api-spec not provided"})
        else:
            findings.extend(result_findings)

    return findings, passed, skipped
