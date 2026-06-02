"""
Credential checks: CRED-01, CRED-02, CRED-03.

CRED-01  Hardcoded secrets in files on disk
CRED-02  Live credentials in process environment variables
CRED-03  Wildcard API capability in tool specs
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional

from ..models import InfraFinding, Severity
from ..constants import (
    MIT_RISK_MAP, SECRET_ENV_NAMES, SECRET_VALUE_PREFIXES,
    SECRET_SCAN_EXTENSIONS, SECRET_SCAN_FILENAMES, SECRET_SKIP_DIRS,
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


# Pattern: KEY_NAME = "value" or KEY_NAME: value
_SECRET_INLINE_RE = re.compile(
    r'(?i)(' + '|'.join(re.escape(n) for n in sorted(SECRET_ENV_NAMES)) + r')\s*[=:]\s*["\']?([^\s\'"]+)["\']?'
)


def check_cred01_secrets_on_disk(search_path: str) -> tuple[list[InfraFinding], str]:
    """CRED-01: Hardcoded secrets in files."""
    hits: list[str] = []
    ignore_patterns = load_ignore_patterns(search_path)

    for root, dirs, files in os.walk(search_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SECRET_SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            if (Path(filename).suffix.lower() not in SECRET_SCAN_EXTENSIONS
                    and filename.lower() not in SECRET_SCAN_FILENAMES):
                continue
            filepath = os.path.join(root, filename)
            if is_ignored(os.path.relpath(filepath, search_path), ignore_patterns):
                continue
            try:
                content = Path(filepath).read_text(errors="replace")
            except Exception:
                continue
            for match in _SECRET_INLINE_RE.finditer(content):
                key_name = match.group(1).upper()
                value = match.group(2)
                if len(value) > 4 and value not in ("true", "false", "null", "none", "example"):
                    rel = os.path.relpath(filepath, search_path)
                    hits.append(f"{rel}: {key_name}")
                    if len(hits) >= 10:
                        break
            if len(hits) >= 10:
                break

    if not hits:
        return [], "PASS"

    return [_finding(
        check_id="CRED-01",
        finding_type="blastcontain.cred.secrets_on_disk",
        severity=Severity.CRITICAL,
        title="Hardcoded Secrets Found in Source Files",
        detail=(
            f"Found {len(hits)} credential pattern(s) hardcoded in source files. "
            "Secrets in source code are exposed in version history, container images, "
            "and any environment where the code is deployed — including by anyone with "
            "read access to the repository."
        ),
        remediation=(
            "Immediately:\n"
            "1. Rotate all exposed credentials — assume they are compromised.\n"
            "2. Remove from source files and history: `git filter-repo` or BFG Repo Cleaner.\n"
            "3. Inject secrets at runtime via a secrets manager (AWS Secrets Manager, "
            "HashiCorp Vault, Azure Key Vault) or mounted Kubernetes Secrets."
        ),
        references=[
            "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        ],
        evidence="; ".join(hits[:5]) + (" ..." if len(hits) > 5 else ""),
    )], "FAIL"


def check_cred02_env_credentials() -> tuple[list[InfraFinding], str]:
    """CRED-02: Live credentials in process environment."""
    hits: list[str] = []

    for key, value in os.environ.items():
        if key.upper() in SECRET_ENV_NAMES:
            hits.append(key)
        elif value and value.startswith(SECRET_VALUE_PREFIXES):
            hits.append(f"{key} (value prefix match)")

    if not hits:
        return [], "PASS"

    return [_finding(
        check_id="CRED-02",
        finding_type="blastcontain.cred.live_env_credentials",
        severity=Severity.CRITICAL,
        title="Live Credentials Found in Process Environment",
        detail=(
            f"Found {len(hits)} credential(s) in the agent process environment. "
            "Environment variables are readable by the process itself, any child "
            "process, and any code that calls `os.environ`. A prompt injection "
            "or code execution vulnerability can exfiltrate all env credentials instantly."
        ),
        remediation=(
            "Replace environment variable secrets with file-mounted secrets:\n"
            "  Docker:     `--secret id=mykey,src=/host/path/key.txt`\n"
            "  Kubernetes: `volumes: [secret: secretName: my-secret]`\n"
            "Read the secret once at startup, store in memory, then unset the env var."
        ),
        evidence="; ".join(hits[:5]),
    )], "FAIL"


def check_cred03_wildcard_capability(search_path: str) -> tuple[list[InfraFinding], str]:
    """CRED-03: Wildcard API capability in tool or skill definitions."""
    # Wildcard *permission values* — not glob paths or YAML anchors.
    #   "*" '*' "/*" '/*'    quoted pure-wildcard value (JSON and YAML). The
    #                        optional leading `/` catches IAM-style `"/*"`, but
    #                        a trailing quote is required so file globs such as
    #                        "*.py" or "src/*" are NOT flagged.
    #   key: *               bare YAML wildcard value; the negative lookahead
    #                        excludes `*alias` (anchor refs), `*/`, `**`,
    #                        `*.py` (glob paths) and `*-foo`.
    wildcard_patterns = [
        r'["\'](?:/)?\*["\']',
        r":\s*\*(?![\w*\-/.])",
    ]
    hits: list[str] = []

    scan_exts = {".json", ".yaml", ".yml", ".toml"}
    for root, dirs, files in os.walk(search_path, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SECRET_SKIP_DIRS and not d.startswith(".")]
        for filename in files:
            if Path(filename).suffix.lower() not in scan_exts:
                continue
            filepath = os.path.join(root, filename)
            try:
                content = Path(filepath).read_text(errors="replace")
            except Exception:
                continue
            for pat in wildcard_patterns:
                if re.search(pat, content):
                    hits.append(os.path.relpath(filepath, search_path))
                    break

    if not hits:
        return [], "PASS"

    return [_finding(
        check_id="CRED-03",
        finding_type="blastcontain.cred.wildcard_api_capability",
        severity=Severity.HIGH,
        title="Wildcard API Capability Detected",
        detail=(
            f"Found wildcard permission patterns (`\"*\"`, `'*'`, `key: *`) in {len(hits)} tool "
            "or skill definition file(s). Wildcard capabilities grant the agent "
            "access to all endpoints and operations, far beyond what any legitimate "
            "task should require."
        ),
        remediation=(
            "Replace wildcard permissions with an explicit allowlist of required "
            "endpoints and methods. Register the allowlist in the agent Charter under "
            "`permitted_apis`. Use the AGT PolicyEngine to enforce the allowlist at runtime."
        ),
        evidence="; ".join(hits[:5]),
    )], "FAIL"


def run(search_path: str = ".", **_) -> tuple[list[InfraFinding], list[str], list[dict]]:
    findings: list[InfraFinding] = []
    passed: list[str] = []
    skipped: list[dict] = []

    checks = [
        ("CRED-01", check_cred01_secrets_on_disk,     [search_path]),
        ("CRED-02", check_cred02_env_credentials,      []),
        ("CRED-03", check_cred03_wildcard_capability,  [search_path]),
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
