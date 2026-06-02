"""
Skill checks: SKILL-01, SKILL-02.

SKILL-01  Exfiltration-capable tool in skill definitions
SKILL-02  Cisco AI Skill Scanner findings
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import yaml

from ..models import InfraFinding, Severity
from ..constants import MIT_RISK_MAP, EXFIL_SKILL_PATTERNS
from ..augmentation import CISCO_SKILL_AVAILABLE, get_skill_scanner


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


def _collect_names(node, out: list[str]) -> None:
    """Recursively collect tool/function names from a parsed skill manifest.

    Handles common skill spec shapes:
      - flat keys: name / tool_name / id
      - OpenAI-style nested: {"type": "function", "function": {"name": ...}}
      - lists of tools: {"tools": [ ... ]}
    """
    if isinstance(node, dict):
        for key in ("name", "tool_name", "id"):
            val = node.get(key)
            if isinstance(val, str) and val:
                out.append(val.lower())
        # Nested function spec (OpenAI tool-calling style)
        fn = node.get("function")
        if isinstance(fn, dict):
            _collect_names(fn, out)
        elif isinstance(fn, str) and fn:
            out.append(fn.lower())
        # Recurse into nested tool lists / dicts
        for child_key in ("tools", "functions", "skills"):
            child = node.get(child_key)
            if isinstance(child, (list, dict)):
                _collect_names(child, out)
    elif isinstance(node, list):
        for item in node:
            _collect_names(item, out)


def _extract_tool_names(skills_dir: str) -> list[str]:
    """Walk skills directory and extract tool/function names from skill manifests (JSON + YAML)."""
    tool_names: list[str] = []
    for root, dirs, files in os.walk(skills_dir, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for filename in files:
            if not filename.endswith((".json", ".yaml", ".yml")):
                continue
            filepath = os.path.join(root, filename)
            try:
                content = Path(filepath).read_text(errors="replace")
                if filename.endswith(".json"):
                    data = json.loads(content)
                else:
                    data = yaml.safe_load(content)
                _collect_names(data, tool_names)
            except Exception:
                # Fall back to name-based check on the file itself
                tool_names.append(Path(filename).stem.lower())

    return tool_names


def check_skill01_exfil_capable(skills_dir: Optional[str]) -> tuple[list[InfraFinding], str, str]:
    """SKILL-01: Exfiltration-capable tool in skill definitions."""
    if not skills_dir or not os.path.isdir(skills_dir):
        return [], "SKIP", "--skills-dir not provided"

    tool_names = _extract_tool_names(skills_dir)
    if not tool_names:
        return [], "SKIP", "no tool/function names found in skill manifests"

    hits = [
        name for name in tool_names
        if any(pat in name for pat in EXFIL_SKILL_PATTERNS)
    ]

    if not hits:
        return [], "PASS", ""

    return [_finding(
        check_id="SKILL-01",
        finding_type="blastcontain.skill.exfil_capable",
        severity=Severity.HIGH,
        title="Exfiltration-Capable Skill Tool Detected",
        detail=(
            f"Found {len(hits)} tool(s) in the skills directory with names matching "
            f"exfiltration-capable patterns: {', '.join(hits[:5])}. "
            "Tools that can POST data, send email, or upload files represent a "
            "direct data exfiltration capability that can be triggered by prompt injection."
        ),
        remediation=(
            "Review each flagged tool. If the tool is required:\n"
            "1. Register it explicitly in the agent Charter under `permitted_tools`.\n"
            "2. Restrict it with an AGT PolicyEngine allowlist to specific "
            "   destinations and payload sizes.\n"
            "3. Remove tools not required for the agent's declared purpose."
        ),
        evidence=f"Flagged tools: {', '.join(hits[:5])}",
    )], "FAIL", ""


def check_skill02_cisco_scan(skills_dir: Optional[str]) -> tuple[list[InfraFinding], str, str]:
    """SKILL-02: Cisco AI Skill Scanner findings.

    The Cisco scanner assesses Claude Agent Skills — directories containing a
    `SKILL.md` manifest (plus any bundled scripts). It scans recursively and
    returns a Report aggregating per-skill ScanResults.
    """
    if not skills_dir or not os.path.isdir(skills_dir):
        return [], "SKIP", "--skills-dir not provided"

    if not CISCO_SKILL_AVAILABLE:
        return [], "SKIP", "cisco-ai-skill-scanner not installed"

    scanner = get_skill_scanner()
    if scanner is None:
        return [], "SKIP", "cisco-ai-skill-scanner not available"

    try:
        report = scanner.scan_directory(skills_dir, recursive=True)
    except Exception as exc:
        return [], "SKIP", f"Cisco skill scanner error: {exc}"

    # The scanner only recognises Claude-format skills (a dir with SKILL.md).
    # If none are present there is nothing for this check to assess.
    if getattr(report, "total_skills_scanned", 0) == 0:
        return [], "SKIP", "no Claude-format skills (SKILL.md) found to scan"

    crit = getattr(report, "critical_count", 0)
    high = getattr(report, "high_count", 0)
    med = getattr(report, "medium_count", 0)

    if crit:
        severity, max_severity_str = Severity.CRITICAL, "CRITICAL"
    elif high:
        severity, max_severity_str = Severity.HIGH, "HIGH"
    elif med:
        severity, max_severity_str = Severity.MEDIUM, "MEDIUM"
    else:
        # Only LOW / INFO notes (or no findings) — not actionable.
        return [], "PASS", ""

    # Collect evidence: the highest-severity rule titles across all scanned skills.
    wanted = {"CRITICAL", "HIGH", "MEDIUM"}
    evidence_bits: list[str] = []
    for sr in getattr(report, "scan_results", []) or []:
        skill_name = getattr(sr, "skill_name", "?")
        for f in getattr(sr, "findings", []) or []:
            sev = str(getattr(f, "severity", "")).rsplit(".", 1)[-1].upper()
            if sev in wanted:
                title = getattr(f, "title", getattr(f, "rule_id", "finding"))
                evidence_bits.append(f"{skill_name}: {title} [{sev}]")
    evidence = "; ".join(evidence_bits[:5]) or f"max_severity={max_severity_str}"

    return [_finding(
        check_id="SKILL-02",
        finding_type="blastcontain.skill.cisco_finding",
        severity=severity,
        title=f"Cisco AI Skill Scanner — {max_severity_str} Finding",
        detail=(
            f"The Cisco AI Skill Scanner flagged "
            f"{crit} critical / {high} high / {med} medium issue(s) across "
            f"{report.total_skills_scanned} skill(s) in `{skills_dir}`. "
            "Cisco findings indicate security risks in the skill code identified "
            "by static analysis, taint-flow, bytecode, and YARA rules — e.g. "
            "command injection, credential-file access, or covert data exfiltration."
        ),
        remediation=(
            "Review the Cisco Skill Scanner output for each finding. "
            "Remove or remediate flagged capabilities (shell execution, eval/exec, "
            "reads of credential files, network exfiltration). Re-run until the "
            "scanner reports no critical/high/medium findings."
        ),
        evidence=evidence,
    )], "FAIL", ""


def run(
    skills_dir: Optional[str] = None,
    **_,
) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    checks = [
        ("SKILL-01", check_skill01_exfil_capable, [skills_dir]),
        ("SKILL-02", check_skill02_cisco_scan,     [skills_dir]),
    ]

    for check_id, fn, args in checks:
        result_findings, status, reason = fn(*args)
        if status == "PASS":
            passed.append(check_id)
        elif status == "SKIP":
            skipped.append({"check_id": check_id, "reason": reason})
        else:
            findings.extend(result_findings)

    return findings, passed, skipped
