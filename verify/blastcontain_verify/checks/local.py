"""
Local environment checks: LOCAL-01.

LOCAL-01  Agent running on developer workstation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from ..contract import CheckContext, CheckGroupResult
from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP, SECRET_ENV_NAMES, SECRET_VALUE_PREFIXES

_IDE_ENV_VARS = {
    "VSCODE_PID", "VSCODE_IPC_HOOK", "CURSOR_TRACE_ID", "CURSOR_SESSION_ID",
    "JETBRAINS_IDE", "IDEA_INITIAL_DIRECTORY", "TERM_PROGRAM",
}

_IDE_CONFIG_DIRS = [".vscode", ".cursor", ".idea", ".windsurf"]


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


def check_local01_workstation_detected() -> tuple[list[InfraFinding], str]:
    """LOCAL-01: Agent running on developer workstation."""
    indicators: list[str] = []

    # Home path heuristic
    home = os.path.expanduser("~")
    if sys.platform == "darwin" and "/Users/" in home:
        indicators.append(f"macOS home path: {home}")
    elif sys.platform == "win32" and "\\Users\\" in home:
        indicators.append(f"Windows user home: {home}")

    # IDE environment variables
    for var in _IDE_ENV_VARS:
        if var in os.environ:
            indicators.append(f"IDE env: {var}")

    # IDE config directories in home
    for ide_dir in _IDE_CONFIG_DIRS:
        if Path(home, ide_dir).exists():
            indicators.append(f"IDE config: ~/{ide_dir}")

    if not indicators:
        return [], "SKIP"

    # Check for live credentials in env to escalate severity
    live_creds = [
        k for k in os.environ
        if k.upper() in SECRET_ENV_NAMES
        or os.environ[k].startswith(SECRET_VALUE_PREFIXES)
    ]

    severity = Severity.CRITICAL if live_creds else Severity.HIGH
    cred_note = (
        f" Additionally, {len(live_creds)} live credential(s) detected in env."
        if live_creds else ""
    )

    return [_finding(
        check_id="LOCAL-01",
        finding_type="blastcontain.local.workstation_detected",
        severity=severity,
        title="Agent Running on Developer Workstation",
        detail=(
            f"Detected {len(indicators)} developer workstation indicator(s): "
            f"{', '.join(indicators[:3])}. "
            "An agent running on a workstation shares access to the developer's "
            "credential store, browsing history, SSH keys, and all files on the machine."
            + cred_note
        ),
        remediation=(
            "Run the agent inside a container even on development machines:\n"
            "  `docker run --rm --read-only --network=none <image>`\n"
            "This isolates the agent from your local environment. "
            "Use a dedicated agent development container with minimal mounts."
        ),
        evidence="; ".join(indicators[:3]),
    )], "FAIL"


def run(ctx: CheckContext) -> CheckGroupResult:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    result_findings, status = check_local01_workstation_detected()
    if status == "PASS":
        passed.append("LOCAL-01")
    elif status == "SKIP":
        skipped.append({"check_id": "LOCAL-01", "reason": "No workstation indicators detected"})
    else:
        findings.extend(result_findings)

    return CheckGroupResult(findings=findings, passed=passed, skipped=skipped)
