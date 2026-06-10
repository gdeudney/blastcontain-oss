"""
Environment checks: ENV-01, ENV-02, ENV-03.

ENV-01  Kernel isolation (gVisor / microVM)
ENV-02  Network egress restriction
ENV-03  Model weight directory mutability
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Optional

from ..contract import CheckContext, CheckGroupResult
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


def check_env01_kernel_isolation() -> tuple[list[InfraFinding], str]:
    """ENV-01: Shared host-kernel environment."""
    if not sys.platform.startswith("linux"):
        return [], "SKIP"

    # Check for gVisor signal in dmesg
    try:
        result = subprocess.run(
            ["dmesg"], capture_output=True, text=True, timeout=5
        )
        if "gVisor" in result.stdout or "runsc" in result.stdout:
            return [], "PASS"
    except Exception:
        pass

    # Check osrelease for host kernel signatures
    osrelease_path = Path("/proc/sys/kernel/osrelease")
    try:
        osrelease = osrelease_path.read_text().strip().lower()
    except Exception:
        return [], "SKIP"

    host_sigs = {"ubuntu", "fedora", "debian", "arch", "centos", "rhel", "amazon", "generic"}
    if any(sig in osrelease for sig in host_sigs):
        return [_finding(
            check_id="ENV-01",
            finding_type="blastcontain.env.kernel_isolation_missing",
            severity=Severity.CRITICAL,
            title="Shared Host-Kernel Environment Detected",
            detail=(
                f"The agent is running on a shared host kernel ({osrelease!r}). "
                "No gVisor or microVM isolation detected. A kernel exploit by a "
                "compromised agent can escape to the host and affect all other "
                "workloads on the node."
            ),
            remediation=(
                "Run the agent container with gVisor sandbox: "
                "`docker run --runtime=runsc <image>` "
                "or set `runtimeClassName: gvisor` in your Kubernetes pod spec. "
                "Alternatively, run agents in a microVM (Kata Containers, Firecracker)."
            ),
            references=[
                "https://gvisor.dev/docs/user_guide/quick_start/docker/",
                "https://gvisor.dev/docs/user_guide/install/",
                "https://katacontainers.io/",
            ],
            evidence=f"osrelease: {osrelease}",
        )], "FAIL"

    return [], "PASS"


def check_env02_egress_restriction(probe_target: str = "8.8.8.8:53") -> tuple[list[InfraFinding], str]:
    """ENV-02: Network egress unrestricted."""
    host, _, port_str = probe_target.rpartition(":")
    probe_host = host or "8.8.8.8"
    probe_port = int(port_str) if port_str.isdigit() else 53
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((probe_host, probe_port))
        sock.close()
        if result == 0:
            return [_finding(
                check_id="ENV-02",
                finding_type="blastcontain.env.egress_unrestricted",
                severity=Severity.HIGH,
                title="Network Egress Unrestricted",
                detail=(
                    "The agent process can reach external networks (8.8.8.8:53 TCP "
                    "reachable). An agent with unrestricted egress can exfiltrate "
                    "data to attacker-controlled infrastructure, download malicious "
                    "payloads, or establish reverse shells."
                ),
                remediation=(
                    "Apply an egress network policy:\n"
                    "  Docker:     `docker run --network=none`\n"
                    "  Compose:    `networks: internal: true`\n"
                    "  Kubernetes: `NetworkPolicy` with `policyTypes: [Egress]` "
                    "and an explicit allowlist of required destinations."
                ),
            )], "FAIL"
    except Exception:
        pass  # Connection refused or timed out — egress blocked

    return [], "PASS"


def check_env03_model_weights_writable(model_dir: str) -> tuple[list[InfraFinding], str]:
    """ENV-03: Model weight directory writable."""
    if not model_dir or not os.path.isdir(model_dir):
        return [], "SKIP"

    canary = os.path.join(model_dir, ".blastcontain_canary.tmp")
    try:
        with open(canary, "w") as f:
            f.write("blastcontain-verify-canary")
        os.remove(canary)
    except OSError:
        # Any OS-level write denial means the directory is not writable, which
        # is the desired secure state. This covers EACCES (PermissionError) for
        # ownership/mode denials AND EROFS for read-only bind mounts — a :ro
        # mount raises OSError(EROFS), NOT PermissionError.
        return [], "PASS"
    except Exception:
        return [], "SKIP"

    return [_finding(
        check_id="ENV-03",
        finding_type="blastcontain.env.model_weights_writable",
        severity=Severity.CRITICAL,
        title="Model Weight Directory Is Writable",
        detail=(
            f"The model directory `{model_dir}` is writable by the agent process. "
            "A supply chain attack or compromised agent can silently replace model "
            "weights, poisoning all subsequent inference without any observable event."
        ),
        remediation=(
            f"Mount the model directory as read-only:\n"
            f"  Docker:     `-v /host/models:{model_dir}:ro`\n"
            f"  Kubernetes: `readOnly: true` on the volumeMount spec."
        ),
        evidence=f"Successfully wrote and deleted canary at {canary}",
    )], "FAIL"


def run(ctx: CheckContext) -> CheckGroupResult:
    model_dir = ctx.cfg.model_dir
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    probe_target = ctx.cfg.egress_probe_target
    checks = [
        ("ENV-01", check_env01_kernel_isolation, []),
        ("ENV-02", check_env02_egress_restriction, [probe_target]),
        ("ENV-03", check_env03_model_weights_writable, [model_dir]),
    ]

    for check_id, fn, args in checks:
        result_findings, status = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": "Not applicable to this environment"})
        else:
            findings.extend(result_findings)

    return CheckGroupResult(findings=findings, passed=passed, skipped=skipped)
