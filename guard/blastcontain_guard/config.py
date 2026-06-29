"""
blastcontain_guard.config — configuration loader.

Merges ``blastcontain-guard.yaml`` with CLI flags (CLI wins), mirroring the
Verify / Drill config pattern so the tools feel the same. Everything is optional:
Guard's whole open path is ``--policy policy.yaml`` and nothing else.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class GuardConfig:
    # Identity
    agent_id: str = ""
    environment: str = "staging"

    # Policy source (exactly one is the active source; policy wins if both set)
    policy: Optional[str] = None            # a governance.toolkit/v1 ruleset YAML
    charter: Optional[str] = None           # a core charter.yaml, compiled offline
    autonomy_mode: str = "interactive"      # interactive | autonomous

    # Telemetry / audit
    log: Optional[str] = None               # JSONL decision sink
    decision_log: Optional[str] = None      # signed decision-log packet output
    proposals_out: Optional[str] = None     # learning proposals output
    blastcontain_url: Optional[str] = None  # Ledger URL (or $BLASTCONTAIN_URL)
    dry_run: bool = False                   # don't POST to the Ledger

    # Backends (the optional AGT second front)
    agt_enabled: bool = False
    agt_mode: str = "dual"                   # dual = AGT backs native | sole = AGT decides
    agt_endpoint: Optional[str] = None       # AGT decision endpoint (out-of-process)
    agt_token: Optional[str] = None
    degrade_to_native: bool = False

    # HITL
    hitl_timeout_sec: int = 300
    escalation_contact: Optional[str] = None


_FIELDS = (
    "agent_id", "environment", "policy", "charter", "autonomy_mode",
    "log", "decision_log", "proposals_out", "blastcontain_url", "dry_run",
    "agt_enabled", "agt_mode", "agt_endpoint", "agt_token", "degrade_to_native",
    "hitl_timeout_sec", "escalation_contact",
)

# A nested `agt:` mapping in YAML maps onto the flat agt_* fields, so a config can
# read either way.
_AGT_KEYS = {
    "enabled": "agt_enabled",
    "mode": "agt_mode",
    "endpoint": "agt_endpoint",
    "token": "agt_token",  # nosec B105 — maps the YAML key to a config field name, not a secret
    "degrade_to_native": "degrade_to_native",
}


def load_config(
    config_file: Optional[str] = None,
    cli_overrides: Optional[dict] = None,
) -> GuardConfig:
    """Load YAML config, then apply CLI overrides (None = not provided)."""
    cfg = GuardConfig()

    candidates = [config_file, "blastcontain-guard.yaml", "blastcontain-guard.yml"]
    yaml_path: Optional[Path] = None
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            yaml_path = Path(candidate)
            break

    if yaml_path:
        try:
            import yaml  # type: ignore

            with open(yaml_path, encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            _apply_dict(cfg, data)
        except ImportError:
            pass

    if cli_overrides:
        _apply_dict(cfg, {k: v for k, v in cli_overrides.items() if v is not None})

    if not cfg.blastcontain_url:
        cfg.blastcontain_url = os.environ.get("BLASTCONTAIN_URL")

    return cfg


def _apply_dict(cfg: GuardConfig, data: dict) -> None:
    for key in _FIELDS:
        if key in data and data[key] is not None:
            setattr(cfg, key, data[key])
    agt = data.get("agt")
    if isinstance(agt, dict):
        for key, field_name in _AGT_KEYS.items():
            if key in agt and agt[key] is not None:
                setattr(cfg, field_name, agt[key])
