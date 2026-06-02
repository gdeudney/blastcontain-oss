"""
BlastContain Verify — report writer.

Produces:
  1. A human-readable Markdown compliance report
  2. A cryptographically signed JSON Audit Packet (Ed25519 or HMAC)

Signing primitives are delegated to `blastcontain_core.signing`. See its
docstring for algorithm selection and canonical encoding details.
"""
from __future__ import annotations

import datetime
import json
import os
from collections import defaultdict

from blastcontain_core.signing import sign_packet

from .models import InfraFinding, ScanResult, ScanStatus, Severity

# Status display
_STATUS_EMOJI = {
    ScanStatus.APPROVED:    "✅",
    ScanStatus.REJECTED:    "🟠",
    ScanStatus.QUARANTINED: "🔴",
    ScanStatus.ERROR:       "⚠️",
}

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

_CHECK_GROUPS = {
    "ENV":   "Environment",
    "DISK":  "Filesystem",
    "CRED":  "Credentials",
    "PRIV":  "Process",
    "CAP":   "Process",
    "NET":   "Network",
    "PERM":  "Persistence",
    "MEM":   "Memory",
    "SKILL": "Skills",
    "API":   "APIs",
    "MCP":   "MCP Servers",
    "CODE":  "Code",
    "SUP":   "Supply Chain",
    "TLS":   "Transport",
    "LOCAL": "Local",
    "SCAN":  "Scanner",
}


def _group_of(check_id: str) -> str:
    prefix = check_id.split("-")[0]
    return _CHECK_GROUPS.get(prefix, "Other")


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def write_markdown_report(result: ScanResult, path: str) -> None:
    """Write a Markdown compliance report to disk."""
    lines: list[str] = []

    status_emoji = _STATUS_EMOJI.get(result.status, "⚠️")
    br = f"{result.blast_radius_factor:.1f}x (TIER_{result.max_tier})"

    lines += [
        "# BlastContain Verify — Agent Compliance Report",
        "",
        f"**Agent:** `{result.agent_id}` | **Environment:** `{result.environment}` | "
        f"**Status:** {status_emoji} {result.status.value}",
        f"**Scanned:** {result.scanned_at} | **Blast Radius Factor:** {br} | "
        f"**Scan ID:** `{result.scan_id}`",
        "",
    ]

    # Summary table
    lines += ["## Summary", ""]
    group_counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "PASS": 0, "SKIP": 0}
    )
    for finding in result.findings:
        group_counts[_group_of(finding.check_id)][finding.severity.value] += 1
    for check_id in result.passed:
        group_counts[_group_of(check_id)]["PASS"] += 1
    for skip in result.skipped:
        group_counts[_group_of(skip["check_id"])]["SKIP"] += 1

    lines += [
        "| Group | 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | ✅ PASS | ⏭ SKIP |",
        "|---|---|---|---|---|---|",
    ]
    total = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "PASS": 0, "SKIP": 0}
    for grp in sorted(group_counts):
        c = group_counts[grp]
        lines.append(
            f"| {grp} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | "
            f"{c['PASS']} | {c['SKIP']} |"
        )
        for k in total:
            total[k] += c[k]
    lines += [
        f"| **Total** | **{total['CRITICAL']}** | **{total['HIGH']}** | "
        f"**{total['MEDIUM']}** | **{total['PASS']}** | **{total['SKIP']}** |",
        "",
    ]

    # Augmentation
    aug = result.augmentation
    active = [k for k, v in aug.items() if v]
    inactive = [k for k, v in aug.items() if not v]
    if active or inactive:
        lines += ["## Augmentation", ""]
        if active:
            lines.append(f"**Active:** {', '.join(active)}")
        if inactive:
            lines.append(
                f"**Not installed:** {', '.join(inactive)} "
                f"— `pip install \"blastcontain-verify[full]\"` for full coverage"
            )
        lines.append("")

    # Findings by severity
    for severity, header in [
        (Severity.CRITICAL, "## 🔴 Critical Findings"),
        (Severity.HIGH,     "## 🟠 High Findings"),
        (Severity.MEDIUM,   "## 🟡 Medium Findings"),
    ]:
        bucket = [f for f in result.findings if f.severity == severity]
        if bucket:
            lines += [header, ""]
            for finding in bucket:
                lines += _format_finding(finding)

    if result.passed:
        lines += ["## ✅ Passed Checks", "", "| Check ID | Group |", "|---|---|"]
        for check_id in sorted(result.passed):
            lines.append(f"| {check_id} | {_group_of(check_id)} |")
        lines.append("")

    if result.skipped:
        lines += ["## ⏭ Skipped Checks", "", "| Check ID | Reason |", "|---|---|"]
        for skip in sorted(result.skipped, key=lambda s: s["check_id"]):
            lines.append(f"| {skip['check_id']} | {skip.get('reason', '—')} |")
        lines.append("")

    mit_findings = [f for f in result.findings if f.mit_causal_id]
    if mit_findings:
        lines += [
            "## MIT AI Risk Repository Coverage", "",
            "| Check ID | MIT Domain | Causal ID | Label |",
            "|---|---|---|---|",
        ]
        for f in sorted(mit_findings, key=lambda x: x.mit_causal_id or ""):
            lines.append(
                f"| {f.check_id} | {f.mit_domain} | {f.mit_causal_id} | {f.mit_causal_label} |"
            )
        lines.append("")

    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _format_finding(finding: InfraFinding) -> list[str]:
    lines: list[str] = [
        f"### {finding.check_id} — {finding.title}",
        "",
        f"**Severity:** {_SEV_EMOJI[finding.severity]} {finding.severity.value} | "
        f"**Type:** `{finding.finding_type}`",
    ]
    if finding.mit_causal_id:
        lines.append(
            f"**MIT Risk:** {finding.mit_domain} — {finding.mit_causal_id}: {finding.mit_causal_label}"
        )
    lines += [
        "",
        "**What happened**", "",
        finding.detail, "",
        "**How to fix**", "",
        finding.remediation, "",
    ]
    if finding.evidence:
        lines += [f"**Evidence:** `{finding.evidence}`", ""]
    if finding.references:
        lines += ["**References**", ""]
        for ref in finding.references:
            lines.append(f"- {ref}")
        lines.append("")
    return lines


def write_audit_packet(result: ScanResult, path: str) -> dict:
    """
    Write and return a signed JSON Audit Packet.

    Signing algorithm is chosen by blastcontain_core.signing.sign_packet
    based on environment configuration. See its docstring for details.
    """
    payload = result.as_dict()
    payload["generator"] = "blastcontain-verify"
    payload["generator_version"] = "0.1.0"

    signed_at = _utc_now_iso()
    signature = sign_packet(payload, signed_at=signed_at)

    packet = {
        "schema_version": "1.1",
        "packet":         payload,
        "signature":      signature,
    }

    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
    with open(path, "w", encoding="utf-8") as f:
        json.dump(packet, f, indent=2)

    return packet


def post_to_ledger(result: ScanResult, blastcontain_url: str) -> bool:
    """POST the scan result to the BlastContain Ledger. Returns True on success."""
    try:
        import httpx  # type: ignore
        url = f"{blastcontain_url.rstrip('/')}/v1/agents/{result.agent_id}/findings"
        resp = httpx.post(url, json=result.as_dict(), timeout=10)
        return resp.status_code in (200, 201, 202)
    except Exception:
        return False
