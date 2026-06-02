"""
Memory checks: MEM-01, MEM-03, MEM-05.

MEM-01   Unmasked PII in session context
MEM-03   Memory/vector store without tenant namespace isolation
MEM-05   Viable PII exfiltration path (MEM-01 + ENV-02 combined condition)
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import (
    MIT_RISK_MAP, GENERIC_NAMESPACES, VECTOR_DB_ENV_INDICATORS,
)
from ..augmentation import presidio_analyze, PRESIDIO_AVAILABLE


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


# Fallback PII patterns (used when Presidio unavailable)
_PII_PATTERNS: list[tuple[str, str]] = [
    (r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",           "SSN pattern"),
    (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  "Credit card pattern"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "Phone number"),
    (r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b", "Date of birth"),
]


def _scan_text_for_pii(text: str) -> list[str]:
    """Return list of PII type labels found in text."""
    found: list[str] = []

    if PRESIDIO_AVAILABLE:
        results = presidio_analyze(text)
        found = list({r.entity_type for r in results})
    else:
        for pattern, label in _PII_PATTERNS:
            if re.search(pattern, text):
                found.append(label)

    return found


def check_mem01_pii_in_context(context_file: Optional[str]) -> tuple[list[InfraFinding], str]:
    """MEM-01: Unmasked PII in session context file."""
    if not context_file:
        return [], "SKIP"

    path = Path(context_file)
    if not path.exists():
        return [], "SKIP"

    try:
        text = path.read_text(errors="replace")
    except Exception:
        return [], "SKIP"

    pii_types = _scan_text_for_pii(text)
    if not pii_types:
        return [], "PASS"

    scanner_label = "Presidio" if PRESIDIO_AVAILABLE else "pattern matching (Presidio not installed)"

    return [_finding(
        check_id="MEM-01",
        finding_type="blastcontain.mem.pii_in_context",
        severity=Severity.MEDIUM,
        title="Unmasked PII Found in Session Context",
        detail=(
            f"Detected {len(pii_types)} PII type(s) in the session context file "
            f"`{context_file}` using {scanner_label}: {', '.join(pii_types)}. "
            "Raw PII in agent context is at risk of appearing in logs, model outputs, "
            "or tool calls — and can be exfiltrated if the agent has network egress."
        ),
        remediation=(
            "Use Presidio Anonymizer at context ingestion time to replace PII with "
            "synthetic tokens before the context enters the agent. "
            "Never pass raw user data (names, SSNs, credit cards) into agent context. "
            "Install: `pip install presidio-analyzer presidio-anonymizer`"
        ),
        references=[
            "https://microsoft.github.io/presidio/",
        ],
        evidence=f"PII types detected: {', '.join(pii_types)}",
    )], "FAIL"


def check_mem03_namespace_isolation() -> tuple[list[InfraFinding], str]:
    """MEM-03: Vector/memory store without tenant namespace isolation."""
    # Check for vector DB env vars
    db_indicators = [k for k in VECTOR_DB_ENV_INDICATORS if k in os.environ]
    if not db_indicators:
        return [], "SKIP"

    issues: list[str] = []

    # Pinecone: must have PINECONE_NAMESPACE set and not generic
    if "PINECONE_API_KEY" in os.environ:
        namespace = os.environ.get("PINECONE_NAMESPACE", "")
        if not namespace or namespace.lower() in GENERIC_NAMESPACES:
            issues.append(f"PINECONE_NAMESPACE={namespace!r} (generic or missing)")

    # Redis: database 0 is the shared default
    redis_url = os.environ.get("REDIS_URL", "")
    if redis_url and (redis_url.endswith("/0") or redis_url.endswith("redis:6379")):
        issues.append(f"REDIS_URL using database 0: {redis_url[:40]}")

    # Qdrant: check for generic collection name in env
    qdrant_collection = os.environ.get("QDRANT_COLLECTION", "")
    if qdrant_collection.lower() in GENERIC_NAMESPACES:
        issues.append(f"QDRANT_COLLECTION={qdrant_collection!r} (generic name)")

    if not issues:
        return [], "PASS"

    return [_finding(
        check_id="MEM-03",
        finding_type="blastcontain.mem.namespace_isolation_missing",
        severity=Severity.CRITICAL,
        title="Memory Store Lacks Tenant Namespace Isolation",
        detail=(
            f"Detected {len(issues)} vector/memory store configuration issue(s) "
            f"indicating shared namespace usage: {'; '.join(issues)}. "
            "Agents sharing a vector store namespace can read each other's memory, "
            "including sensitive context from other users or sessions."
        ),
        remediation=(
            "Use agent-scoped namespaces:\n"
            "  Pinecone:   `PINECONE_NAMESPACE=agent_{agent_id}_v1`\n"
            "  Qdrant:     `QDRANT_COLLECTION=agent_{agent_id}_v1`\n"
            "  Redis:      Use database > 0 or key prefix `agent:{agent_id}:`\n"
            "Each agent in prod should have an isolated, non-sharable namespace."
        ),
        evidence="; ".join(issues),
    )], "FAIL"


def check_mem05_pii_exfil_path(
    mem01_fired: bool, env02_fired: bool
) -> tuple[list[InfraFinding], str]:
    """MEM-05: Viable PII exfiltration path (composite condition)."""
    if not mem01_fired or not env02_fired:
        return [], "SKIP"

    return [_finding(
        check_id="MEM-05",
        finding_type="blastcontain.mem.pii_exfil_path",
        severity=Severity.CRITICAL,
        title="Viable PII Exfiltration Path Confirmed",
        detail=(
            "MEM-01 (PII in context) and ENV-02 (unrestricted egress) both fired. "
            "The agent has PII in its session context AND can reach external networks. "
            "This is a confirmed viable exfiltration path — no further attack sophistication "
            "is required to exfiltrate personal data."
        ),
        remediation=(
            "Fix both root causes:\n"
            "1. ENV-02: Apply network egress policy to block external connectivity.\n"
            "2. MEM-01: Use Presidio Anonymizer to mask PII before it enters agent context."
        ),
    )], "FAIL"


def run(
    context_file: Optional[str] = None,
    env02_fired: bool = False,
    **_,
) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []
    mem01_fired = False

    # MEM-01
    mem01_findings, status = check_mem01_pii_in_context(context_file)
    if status == "PASS":
        passed.append("MEM-01")
    elif status == "SKIP":
        skipped.append({"check_id": "MEM-01", "reason": "No --context-file provided"})
    else:
        findings.extend(mem01_findings)
        mem01_fired = True

    # MEM-03
    mem03_findings, status = check_mem03_namespace_isolation()
    if status == "PASS":
        passed.append("MEM-03")
    elif status == "SKIP":
        skipped.append({"check_id": "MEM-03", "reason": "No vector DB environment detected"})
    else:
        findings.extend(mem03_findings)

    # MEM-05 (composite)
    mem05_findings, status = check_mem05_pii_exfil_path(mem01_fired, env02_fired)
    if status == "PASS":
        passed.append("MEM-05")
    elif status == "SKIP":
        skipped.append({
            "check_id": "MEM-05",
            "reason": "Requires both MEM-01 and ENV-02 to fire",
        })
    else:
        findings.extend(mem05_findings)

    return findings, passed, skipped
