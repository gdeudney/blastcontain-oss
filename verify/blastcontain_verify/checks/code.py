"""
Code checks: CODE-01.

CODE-01  Dangerous code execution patterns in agent source.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import (
    MIT_RISK_MAP, CODE_CRITICAL_PATTERNS, CODE_HIGH_PATTERNS,
    CODE_SCAN_EXTENSIONS, CODE_SKIP_DIRS,
)
from ..ignore import load_ignore_patterns, is_ignored


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


def check_code01_dangerous_patterns(search_path: str) -> tuple[list[InfraFinding], str]:
    """CODE-01: Dangerous code execution patterns."""
    critical_hits: list[str] = []
    high_hits: list[str] = []

    compiled_critical = [(re.compile(pat), label) for pat, label in CODE_CRITICAL_PATTERNS]
    compiled_high = [(re.compile(pat), label) for pat, label in CODE_HIGH_PATTERNS]
    ignore_patterns = load_ignore_patterns(search_path)

    for root, dirs, files in os.walk(search_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in CODE_SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            if Path(filename).suffix.lower() not in CODE_SCAN_EXTENSIONS:
                continue
            filepath = os.path.join(root, filename)
            if is_ignored(os.path.relpath(filepath, search_path), ignore_patterns):
                continue
            try:
                content = Path(filepath).read_text(errors="replace")
            except Exception:
                continue

            rel = os.path.relpath(filepath, search_path)

            for pattern, label in compiled_critical:
                if pattern.search(content):
                    critical_hits.append(f"{rel}: {label}")

            for pattern, label in compiled_high:
                if pattern.search(content):
                    high_hits.append(f"{rel}: {label}")

    if not critical_hits and not high_hits:
        return [], "PASS"

    # Report as single finding at highest severity found
    severity = Severity.CRITICAL if critical_hits else Severity.HIGH
    all_hits = (critical_hits + high_hits)[:10]

    return [_finding(
        check_id="CODE-01",
        finding_type="blastcontain.code.dangerous_pattern",
        severity=severity,
        title="Dangerous Code Execution Pattern Detected",
        detail=(
            f"Found {len(critical_hits)} CRITICAL and {len(high_hits)} HIGH-severity "
            "dangerous code patterns in agent source files. These patterns enable "
            "arbitrary code execution, insecure deserialization, or dynamic imports "
            "that can be exploited via prompt injection."
        ),
        remediation=(
            "Replace dangerous patterns with safe alternatives:\n"
            "  eval()/exec()      → ast.literal_eval() for data, never for code\n"
            "  os.system()        → subprocess.run(shell=False, args=[...])\n"
            "  shell=True         → shell=False with explicit argument list\n"
            "  pickle.load()      → json for data exchange\n"
            "  yaml.load()        → yaml.safe_load()\n"
            "  __import__()       → explicit import statements"
        ),
        references=[
            "https://bandit.readthedocs.io/en/latest/",
            "https://docs.python.org/3/library/ast.html#ast.literal_eval",
        ],
        evidence="; ".join(all_hits),
    )], "FAIL"


def run(search_path: str = ".", **_) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    result_findings, status = check_code01_dangerous_patterns(search_path)
    if status == "PASS":
        passed.append("CODE-01")
    elif status == "SKIP":
        skipped.append({"check_id": "CODE-01", "reason": "No source files found"})
    else:
        findings.extend(result_findings)

    return findings, passed, skipped
