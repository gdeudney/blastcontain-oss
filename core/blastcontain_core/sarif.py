"""
blastcontain_core.sarif — SARIF 2.1.0 output for security findings.

SARIF (Static Analysis Results Interchange Format) is the OASIS standard
consumed by:
  - GitHub Code Scanning  (`github/codeql-action/upload-sarif`)
  - GitLab Security Dashboard
  - Azure DevOps
  - Most IDE security extensions (Sonar, Snyk, etc.)

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Schema: https://json.schemastore.org/sarif-2.1.0.json
"""
from __future__ import annotations

import json
import os

from .models import InfraFinding, ScanResult, Severity


# SARIF level mapping: see § 3.27.10 of the spec.
_LEVEL_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH:     "error",
    Severity.MEDIUM:   "warning",
    Severity.LOW:      "note",
    Severity.INFO:     "note",
}

# SARIF security-severity is a 0.0–10.0 numeric score used by GitHub
# to filter findings. Mirrors CVSS magnitude bands roughly.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH:     "7.5",
    Severity.MEDIUM:   "5.0",
    Severity.LOW:      "2.0",
    Severity.INFO:     "0.0",
}


def _rule_for(check_id: str, sample: InfraFinding, help_uri: str) -> dict:
    """Build a SARIF reportingDescriptor (rule definition) for a check ID."""
    rule: dict = {
        "id":   check_id,
        "name": check_id.replace("-", "") + sample.finding_type.split(".")[-1].title().replace("_", ""),
        "shortDescription": {"text": sample.title},
        "fullDescription":  {"text": sample.detail[:1000]},
        "helpUri":          sample.references[0] if sample.references else help_uri,
        "help": {
            "text":     sample.remediation,
            "markdown": f"**How to fix**\n\n{sample.remediation}",
        },
        "defaultConfiguration": {
            "level": _LEVEL_MAP.get(sample.severity, "warning"),
        },
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(sample.severity, "5.0"),
            "tags": ["security", "blastcontain"],
        },
    }
    if sample.mit_causal_id:
        rule["properties"]["mit-domain"]    = sample.mit_domain or ""
        rule["properties"]["mit-causal-id"] = sample.mit_causal_id
        rule["properties"]["mit-label"]     = sample.mit_causal_label or ""
        rule["properties"]["tags"].append(f"mit-risk:{sample.mit_causal_id}")
    return rule


def _result_for(finding: InfraFinding, rule_index: int) -> dict:
    """Build a SARIF result for a single finding."""
    result: dict = {
        "ruleId":    finding.check_id,
        "ruleIndex": rule_index,
        "level":     _LEVEL_MAP.get(finding.severity, "warning"),
        "message":   {"text": finding.detail},
        # SARIF requires at least one location. Most findings are environmental,
        # not file-bound — use logicalLocations.
        "locations": [{
            "logicalLocations": [{
                "name":               finding.check_id,
                "kind":               "function",
                "fullyQualifiedName": f"blastcontain.checks.{finding.check_id}",
            }],
        }],
        "properties": {
            "finding_type": finding.finding_type,
            "severity":     finding.severity.value,
        },
    }
    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence
    if finding.mit_causal_id:
        result["properties"]["mit_causal_id"] = finding.mit_causal_id
    return result


def _invocation(scan: ScanResult) -> dict:
    """SARIF invocation block — describes the scan run itself."""
    return {
        "executionSuccessful": scan.status.value != "ERROR",
        "endTimeUtc":          scan.scanned_at,
        "properties": {
            "agent_id":            scan.agent_id,
            "environment":         scan.environment,
            "scan_id":             scan.scan_id,
            "status":              scan.status.value,
            "blast_radius_factor": scan.blast_radius_factor,
            "max_tier":            scan.max_tier,
            "augmentation":        scan.augmentation,
            "passed_checks":       scan.passed,
            "skipped_checks":      scan.skipped,
        },
    }


def build_sarif(
    scan: ScanResult,
    tool_name: str = "blastcontain-verify",
    tool_version: str = "0.0.0",
    tool_info_uri: str = "https://github.com/blastcontain/verify",
    help_uri: str = "https://github.com/blastcontain/verify/blob/main/docs/spec.md",
) -> dict:
    """Build a SARIF 2.1.0 log dict for the given ScanResult."""
    rules: list[dict] = []
    rule_index_by_id: dict[str, int] = {}
    for finding in scan.findings:
        if finding.check_id not in rule_index_by_id:
            rule_index_by_id[finding.check_id] = len(rules)
            rules.append(_rule_for(finding.check_id, finding, help_uri))

    results = [
        _result_for(f, rule_index_by_id[f.check_id])
        for f in scan.findings
    ]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           tool_name,
                    "version":        tool_version,
                    "informationUri": tool_info_uri,
                    "rules":          rules,
                },
            },
            "invocations": [_invocation(scan)],
            "results":     results,
        }],
    }


def write_sarif(
    scan: ScanResult,
    path: str,
    tool_name: str = "blastcontain-verify",
    tool_version: str = "0.0.0",
    tool_info_uri: str = "https://github.com/blastcontain/verify",
    help_uri: str = "https://github.com/blastcontain/verify/blob/main/docs/spec.md",
) -> dict:
    """Write a SARIF 2.1.0 log file for the given ScanResult and return the dict."""
    sarif = build_sarif(scan, tool_name, tool_version, tool_info_uri, help_uri)

    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass

    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    return sarif
