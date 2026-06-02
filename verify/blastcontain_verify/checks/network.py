"""
Network checks: NET-01, NET-02.

NET-01  DNS exfiltration channel open (UDP/53 egress)
NET-02  External network listeners on all interfaces
"""
from __future__ import annotations

import re
import socket
import subprocess
import sys
from pathlib import Path
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


def check_net01_dns_egress(probe_target: str = "8.8.8.8:53") -> tuple[list[InfraFinding], str]:
    """NET-01: UDP DNS egress to external resolver."""
    host, _, port_str = probe_target.rpartition(":")
    probe_host = host or "8.8.8.8"
    probe_port = int(port_str) if port_str.isdigit() else 53
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        # Minimal valid DNS query for google.com A record
        dns_query = (
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x06google\x03com\x00\x00\x01\x00\x01"
        )
        sock.sendto(dns_query, (probe_host, probe_port))
        data, _ = sock.recvfrom(512)
        sock.close()
        if data:
            return [_finding(
                check_id="NET-01",
                finding_type="blastcontain.net.dns_exfil_open",
                severity=Severity.HIGH,
                title="DNS Exfiltration Channel Open",
                detail=(
                    f"The agent can send and receive UDP DNS traffic to {probe_host}:{probe_port}. "
                    "DNS is a classic covert exfiltration channel — data is encoded "
                    "in DNS query hostnames and responses. Many egress filters block "
                    "HTTP/HTTPS but leave DNS unrestricted."
                ),
                remediation=(
                    "Block UDP/53 and TCP/53 egress entirely. "
                    "Redirect DNS to an internal resolver: set `--dns 10.0.0.1` in "
                    "Docker, or `dnsConfig.nameservers` in Kubernetes. "
                    "The internal resolver should not be reachable from outside the cluster."
                ),
            )], "FAIL"
    except Exception:
        pass  # Timeout or refused — DNS egress blocked

    return [], "PASS"


def _parse_proc_net_tcp(path: str) -> list[str]:
    """Parse /proc/net/tcp or /proc/net/tcp6 for LISTEN sockets on all interfaces."""
    listeners: list[str] = []
    try:
        lines = Path(path).read_text().splitlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            state = parts[3]
            if state != "0A":  # 0A = TCP_LISTEN
                continue
            local_addr = parts[1]
            # Format: HEXIP:HEXPORT
            addr_parts = local_addr.split(":")
            if len(addr_parts) != 2:
                continue
            hex_addr = addr_parts[0]
            hex_port = addr_parts[1]
            port = int(hex_port, 16)
            # All-zeros or "::" means listening on all interfaces
            if hex_addr in ("00000000", "00000000000000000000000000000000"):
                listeners.append(str(port))
    except Exception:
        pass
    return listeners


def check_net02_external_listeners() -> tuple[list[InfraFinding], str]:
    """NET-02: Services listening on 0.0.0.0 or ::."""
    listeners: list[int] = []

    if sys.platform.startswith("linux"):
        for proc_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            for port_str in _parse_proc_net_tcp(proc_file):
                port = int(port_str)
                if port not in listeners:
                    listeners.append(port)

    if not listeners:
        # Fallback: netstat
        try:
            result = subprocess.run(
                ["netstat", "-tlnp"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if "LISTEN" in line:
                    if "0.0.0.0:" in line or ":::" in line:
                        match = re.search(r"(?:0\.0\.0\.0|:::?)\s*:(\d+)", line)
                        if match:
                            port = int(match.group(1))
                            if port not in listeners:
                                listeners.append(port)
        except Exception:
            pass

    if not listeners:
        return [], "PASS"

    port_list = ", ".join(str(p) for p in sorted(listeners))
    return [_finding(
        check_id="NET-02",
        finding_type="blastcontain.net.external_listeners",
        severity=Severity.HIGH,
        title="Services Listening on All Network Interfaces",
        detail=(
            f"Found {len(listeners)} service(s) listening on 0.0.0.0 or all interfaces "
            f"(ports: {port_list}). A service bound to all interfaces is reachable from "
            "any network the container is attached to, including networks shared with "
            "other containers."
        ),
        remediation=(
            "Bind services to localhost explicitly:\n"
            "  Code:       `app.run(host='127.0.0.1')`\n"
            "  Docker:     `--publish 127.0.0.1:8080:8080` (not `-p 8080:8080`)\n"
            "  Only expose ports intentionally through a load balancer or API gateway."
        ),
        evidence=f"Listening ports on 0.0.0.0: {port_list}",
    )], "FAIL"


def run(**kwargs) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []
    probe_target = kwargs.get("egress_probe_target", "8.8.8.8:53")

    checks = [
        ("NET-01", check_net01_dns_egress,         [probe_target]),
        ("NET-02", check_net02_external_listeners,  []),
    ]

    for check_id, fn, args in checks:
        result_findings, status = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": "Not applicable"})
        else:
            findings.extend(result_findings)

    return findings, passed, skipped
