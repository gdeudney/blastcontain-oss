"""
Filesystem checks: DISK-01, DISK-02.

DISK-01  Root filesystem writable (developer workstation)
DISK-02  Container root filesystem writable
"""
from __future__ import annotations

import os
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP


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


def _is_workstation_env(environment: str) -> bool:
    return "workstation" in environment.lower() or "local" in environment.lower()


def _canary_writable(path: str) -> bool:
    canary = os.path.join(path, ".blastcontain_canary.tmp")
    try:
        with open(canary, "w") as f:
            f.write("canary")
        os.remove(canary)
        return True
    except Exception:
        return False


def check_disk01_workstation_rootfs(environment: str) -> tuple[list[InfraFinding], str]:
    """DISK-01: Root filesystem writable on developer workstation."""
    if not _is_workstation_env(environment):
        return [], "SKIP"

    home = os.path.expanduser("~")
    if _canary_writable(home):
        return [_finding(
            check_id="DISK-01",
            finding_type="blastcontain.disk.rootfs_writable",
            severity=Severity.CRITICAL,
            title="Agent Running Uncontainerised on Developer Workstation",
            detail=(
                f"The agent is running on a developer workstation (environment={environment!r}) "
                "with a writable home filesystem. Live credentials, model weights, and "
                "agent context are directly accessible by any process on the machine."
            ),
            remediation=(
                "Run the agent inside a container even on development machines. "
                "Use Docker Desktop or Podman: `docker run --read-only --rm <image>`. "
                "This isolates the agent from your local credential store and filesystem."
            ),
            evidence=f"Canary write succeeded in {home}",
        )], "FAIL"

    return [], "PASS"


def check_disk02_container_rootfs(environment: str) -> tuple[list[InfraFinding], str]:
    """DISK-02: Container root filesystem writable."""
    if _is_workstation_env(environment):
        return [], "SKIP"  # DISK-01 covers workstations

    if _canary_writable("/tmp"):  # nosec B108 — intentional: DISK-02 probes whether /tmp is writable
        # /tmp being writable is expected — check a more sensitive location
        if _canary_writable("/var") or _canary_writable("/usr"):
            return [_finding(
                check_id="DISK-02",
                finding_type="blastcontain.disk.rootfs_writable",
                severity=Severity.MEDIUM,
                title="Container Root Filesystem Is Writable",
                detail=(
                    "The container root filesystem is not read-only. A compromised "
                    "agent process can write binaries, modify configuration, or "
                    "tamper with application code inside the container."
                ),
                remediation=(
                    "Run the container with a read-only root filesystem and a tmpfs for "
                    "legitimate runtime writes:\n"
                    "  Docker: `--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m`\n"
                    "  Kubernetes: `securityContext.readOnlyRootFilesystem: true` "
                    "with an `emptyDir` tmpfs mount."
                ),
            )], "FAIL"

    return [], "PASS"


def run(environment: str = "staging", **_) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    checks = [
        ("DISK-01", check_disk01_workstation_rootfs, [environment]),
        ("DISK-02", check_disk02_container_rootfs,   [environment]),
    ]

    for check_id, fn, args in checks:
        result_findings, status = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": "Not applicable to this environment"})
        else:
            findings.extend(result_findings)

    return findings, passed, skipped
