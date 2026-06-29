"""
Process checks: PRIV-01, CAP-01.

PRIV-01  Elevated process privilege (root / admin)
CAP-01   Dangerous Linux capabilities in effective capability set
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

from ..contract import CheckContext, CheckGroupResult
from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP, DANGEROUS_CAPS


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


def check_priv01_elevated_privilege() -> tuple[list[InfraFinding], str]:
    """PRIV-01: Agent running as root or admin."""
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return [], "SKIP"
        if is_admin:
            return [_finding(
                check_id="PRIV-01",
                finding_type="blastcontain.priv.elevated_privilege",
                severity=Severity.CRITICAL,
                title="Agent Running with Administrator Privileges",
                detail=(
                    "The agent process is running as a Windows Administrator. "
                    "An agent running as admin can modify system files, install "
                    "drivers, and access all user data on the machine."
                ),
                remediation=(
                    "Run the agent as a standard (non-admin) Windows user account. "
                    "Create a dedicated service account with minimal permissions."
                ),
                evidence="IsUserAnAdmin() returned True",
            )], "FAIL"
        return [], "PASS"

    # Linux / macOS
    try:
        uid = os.getuid()
    except AttributeError:
        return [], "SKIP"

    if uid == 0:
        return [_finding(
            check_id="PRIV-01",
            finding_type="blastcontain.priv.elevated_privilege",
            severity=Severity.CRITICAL,
            title="Agent Running as Root (UID 0)",
            detail=(
                "The agent process is running as root (UID 0). A compromised "
                "agent running as root has unrestricted access to the host system, "
                "can modify any file, kill any process, and load kernel modules."
            ),
            remediation=(
                "Add a non-root user to your Containerfile: `USER agent`\n"
                "Or set in Kubernetes: `securityContext.runAsNonRoot: true` "
                "and `runAsUser: 1000`."
            ),
            evidence="os.getuid() == 0",
        )], "FAIL"

    return [], "PASS"


def check_cap01_dangerous_capabilities() -> tuple[list[InfraFinding], str]:
    """CAP-01: Dangerous Linux capabilities in effective set."""
    if not sys.platform.startswith("linux"):
        return [], "SKIP"

    status_path = Path("/proc/self/status")
    if not status_path.exists():
        return [], "SKIP"

    try:
        content = status_path.read_text()
    except Exception:
        return [], "SKIP"

    # Parse CapEff hex value
    match = re.search(r"CapEff:\s+([0-9a-fA-F]+)", content)
    if not match:
        return [], "SKIP"

    cap_eff_hex = int(match.group(1), 16)
    if cap_eff_hex == 0:
        return [], "PASS"

    # Map bit positions to capability names
    # Linux capability bit positions (partial, covering dangerous set)
    CAP_BITS: dict[int, str] = {
        1:  "CAP_DAC_OVERRIDE",
        6:  "CAP_SETUID",
        7:  "CAP_SETGID",
        12: "CAP_NET_ADMIN",
        13: "CAP_NET_RAW",
        16: "CAP_SYS_PTRACE",
        17: "CAP_SYS_MODULE",
        18: "CAP_SYS_RAWIO",
        21: "CAP_SYS_ADMIN",
    }

    active_dangerous: list[str] = []
    for bit, cap_name in CAP_BITS.items():
        if (cap_eff_hex >> bit) & 1 and cap_name in DANGEROUS_CAPS:
            active_dangerous.append(cap_name)

    if not active_dangerous:
        return [], "PASS"

    return [_finding(
        check_id="CAP-01",
        finding_type="blastcontain.priv.dangerous_capabilities",
        severity=Severity.CRITICAL,
        title="Dangerous Linux Capabilities Active",
        detail=(
            f"The agent process has {len(active_dangerous)} dangerous Linux "
            f"capability/capabilities in its effective set: {', '.join(active_dangerous)}. "
            "These capabilities allow privilege escalation, kernel module loading, "
            "ptrace of other processes, or raw network access."
        ),
        remediation=(
            "Drop all capabilities and add back only what is strictly required:\n"
            "  Docker:     `--cap-drop ALL --cap-add <specific>`\n"
            "  Kubernetes: `securityContext.capabilities: drop: [ALL] add: []`"
        ),
        references=[
            "https://man7.org/linux/man-pages/man7/capabilities.7.html",
        ],
        evidence=f"CapEff: {match.group(1)} — active: {', '.join(active_dangerous)}",
    )], "FAIL"


def run(ctx: CheckContext) -> CheckGroupResult:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    checks = [
        ("PRIV-01", check_priv01_elevated_privilege,    []),
        ("CAP-01",  check_cap01_dangerous_capabilities, []),
    ]

    for check_id, fn, args in checks:
        result_findings, status = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": "Not applicable to this platform"})
        else:
            findings.extend(result_findings)

    return CheckGroupResult(findings=findings, passed=passed, skipped=skipped)
