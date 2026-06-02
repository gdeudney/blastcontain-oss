"""
Persistence checks: PERM-01.

PERM-01  Write access to startup / persistence paths.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP, PERSISTENCE_PATHS


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


def _path_writable(path: str) -> bool:
    """Check if path or its parent directory is writable."""
    p = Path(path)
    # If path exists, check directly
    if p.exists():
        if p.is_dir():
            canary = p / ".blastcontain_canary.tmp"
            try:
                canary.write_text("canary")
                canary.unlink()
                return True
            except Exception:
                return False
        else:
            return os.access(path, os.W_OK)
    # If path doesn't exist, check parent
    return os.access(str(p.parent), os.W_OK) if p.parent.exists() else False


def check_perm01_persistence_locations() -> tuple[list[InfraFinding], str]:
    """PERM-01: Write access to startup and cron paths."""
    writable: list[str] = []

    for path in PERSISTENCE_PATHS:
        if _path_writable(path):
            writable.append(path)

    if not writable:
        return [], "PASS"

    return [_finding(
        check_id="PERM-01",
        finding_type="blastcontain.perm.persistence_writable",
        severity=Severity.CRITICAL,
        title="Persistence Locations Are Writable",
        detail=(
            f"The agent process can write to {len(writable)} persistence path(s): "
            f"{', '.join(writable[:3])}{'...' if len(writable) > 3 else ''}. "
            "A compromised agent with write access to startup locations (rc files, "
            "cron jobs, LaunchAgents) can survive container or system restarts by "
            "reinstalling itself."
        ),
        remediation=(
            "Use a read-only root filesystem: `--read-only` in Docker, "
            "`readOnlyRootFilesystem: true` in Kubernetes. "
            "Ensure the agent runs as a non-root user without a home directory "
            "that includes shell config files."
        ),
        evidence="Writable: " + ", ".join(writable[:5]),
    )], "FAIL"


def run(**_) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    result_findings, status = check_perm01_persistence_locations()
    if status == "PASS":
        passed.append("PERM-01")
    elif status == "SKIP":
        skipped.append({"check_id": "PERM-01", "reason": "No persistence paths defined for this platform"})
    else:
        findings.extend(result_findings)

    return findings, passed, skipped
