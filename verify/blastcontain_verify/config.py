"""
BlastContain Verify — configuration loader.

Merges blastcontain-verify.yaml with CLI flags. CLI flags always win.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class VerifyConfig:
    # Required
    agent_id: str = ""
    environment: str = "staging"

    # Source scanning
    search_path: str = "."
    skills_dir: Optional[str] = None          # defaults to search_path if not set
    api_spec: Optional[str] = None
    mcp_config: Optional[str] = None
    model_dir: str = "/models"
    context_file: Optional[str] = None

    # Output
    output: Optional[str] = None              # signed JSON audit packet path
    report: Optional[str] = None             # markdown report path

    # Server integration
    blastcontain_url: Optional[str] = None

    # Scan behaviour
    cisco_api_key: str = ""
    max_tier: int = 0
    dry_run: bool = False
    acknowledge_risk: bool = False

    # Network probe target — override when internal resolvers block 8.8.8.8
    # Format: "host:port" e.g. "10.0.0.1:53" or "internal-resolver:53"
    egress_probe_target: str = "8.8.8.8:53"

    # Checks to skip outright. Format: ["CRED-02", "LOCAL-01"].
    # Skipped checks appear in the audit packet as SKIP with reason
    # "User-requested skip (--skip-checks)". Use sparingly — every skip
    # is a declared, signed exception in the audit trail.
    skip_checks: list[str] = field(default_factory=list)

    # API-01 live HTTP probe. OFF by default to preserve the offline
    # guarantee and to prevent malicious OpenAPI specs from triggering
    # scanner-originated network calls. Enable only when scanning trusted specs.
    api_live_probe: bool = False

    # SARIF 2.1.0 output path. Consumed by GitHub Code Scanning,
    # GitLab Security Dashboard, and most IDE extensions.
    sarif: Optional[str] = None

    def effective_skills_dir(self) -> str:
        return self.skills_dir or self.search_path


def load_config(
    config_file: Optional[str] = None,
    cli_overrides: Optional[dict] = None,
) -> VerifyConfig:
    """
    Load config from YAML file, then apply CLI overrides on top.
    CLI values of None mean "not provided" — they do not override file values.
    """
    cfg = VerifyConfig()

    # Resolve config file path
    candidates = [config_file, "blastcontain-verify.yaml", "blastcontain-verify.yml"]
    yaml_path: Optional[Path] = None
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            yaml_path = Path(candidate)
            break

    # Load YAML if present
    if yaml_path:
        try:
            import yaml  # type: ignore
            with open(yaml_path) as f:
                data = yaml.safe_load(f) or {}
            _apply_dict(cfg, data)
        except ImportError:
            pass  # PyYAML not installed — continue with defaults

    # Apply CLI overrides (None values skipped)
    if cli_overrides:
        _apply_dict(cfg, {k: v for k, v in cli_overrides.items() if v is not None})

    # Resolve env var fallback for server URL
    if not cfg.blastcontain_url:
        cfg.blastcontain_url = os.environ.get("BLASTCONTAIN_URL")

    # Resolve env var fallback for Cisco API key
    if not cfg.cisco_api_key:
        cfg.cisco_api_key = os.environ.get("CISCO_AIDEFENSE_API_KEY", "")

    return cfg


def _apply_dict(cfg: VerifyConfig, data: dict) -> None:
    """Apply a flat dict of config values onto a VerifyConfig instance."""
    mapping = {
        "agent_id":         "agent_id",
        "environment":      "environment",
        "search_path":      "search_path",
        "skills_dir":       "skills_dir",
        "api_spec":         "api_spec",
        "mcp_config":       "mcp_config",
        "model_dir":        "model_dir",
        "context_file":     "context_file",
        "output":           "output",
        "report":           "report",
        "blastcontain_url": "blastcontain_url",
        "cisco_api_key":       "cisco_api_key",
        "max_tier":            "max_tier",
        "dry_run":             "dry_run",
        "acknowledge_risk":    "acknowledge_risk",
        "egress_probe_target": "egress_probe_target",
        "skip_checks":         "skip_checks",
        "api_live_probe":      "api_live_probe",
        "sarif":               "sarif",
    }
    for yaml_key, attr in mapping.items():
        if yaml_key in data and data[yaml_key] is not None:
            value = data[yaml_key]
            # skip_checks may arrive as a CSV string from CLI; normalise to list
            if attr == "skip_checks" and isinstance(value, str):
                value = [c.strip() for c in value.split(",") if c.strip()]
            setattr(cfg, attr, value)
