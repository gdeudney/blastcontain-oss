"""
BlastContain Drill — configuration loader.

Merges blastcontain-drill.yaml with CLI flags. CLI flags always win.
Mirrors the Verify config pattern so the two tools feel the same.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DrillConfig:
    # Required
    agent_id: str = ""
    environment: str = "staging"

    # Cage
    cage: str = "inprocess"                    # inprocess | podman
    max_steps: int = 4

    # Target model (the in-cage agent) — any OpenAI-compatible endpoint
    target_base_url: str = "http://localhost:1234/v1"
    target_model: str = ""

    # Black-box mode — attack an already-running agent over HTTP instead
    agent_url: Optional[str] = None

    # Scoring
    judge_base_url: Optional[str] = None       # defaults to target_base_url
    judge_model: Optional[str] = None          # defaults to target_model
    guard_model: Optional[str] = None          # e.g. qwen3guard-gen-8b (optional)

    # Corpus
    corpus: str = "latest"                     # pin a version for reproducibility
    scenarios: list[str] = field(default_factory=list)  # categories; empty = all
    limit: Optional[int] = None                # cap attacks per category
    enable_aig: bool = False                   # add AI-Infra-Guard source if up
    enable_operators: bool = False             # add the model-free Operators layer

    # Generative layer — an abliterated/Heretic attacker model in a refinement loop
    generative: bool = False
    generative_only: bool = False              # skip the static corpus; run only the loop
    attacker_model: Optional[str] = None
    attacker_base_url: Optional[str] = None    # defaults to target_base_url
    generative_iters: int = 4
    generative_corpus: Optional[str] = None    # write discovered jailbreaks here (sensitive)

    # Charter — its permitted_tools define "forbidden" for the forbidden-tool probe
    charter: Optional[str] = None

    # Output
    output: Optional[str] = None               # signed DrillReport JSON
    report: Optional[str] = None               # Markdown report

    # Server integration
    blastcontain_url: Optional[str] = None
    dry_run: bool = False

    def effective_judge_base_url(self) -> str:
        return self.judge_base_url or self.target_base_url

    def effective_judge_model(self) -> str:
        return self.judge_model or self.target_model

    def effective_attacker_base_url(self) -> str:
        return self.attacker_base_url or self.target_base_url


_FIELDS = (
    "agent_id", "environment", "cage", "max_steps", "target_base_url",
    "target_model", "agent_url", "judge_base_url", "judge_model", "guard_model",
    "corpus", "scenarios", "limit", "enable_aig", "enable_operators", "charter", "output", "report",
    "generative", "generative_only", "attacker_model", "attacker_base_url",
    "generative_iters", "generative_corpus",
    "blastcontain_url", "dry_run",
)


def load_config(
    config_file: Optional[str] = None,
    cli_overrides: Optional[dict] = None,
) -> DrillConfig:
    """Load YAML config, then apply CLI overrides (None = not provided)."""
    cfg = DrillConfig()

    candidates = [config_file, "blastcontain-drill.yaml", "blastcontain-drill.yml"]
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


def _apply_dict(cfg: DrillConfig, data: dict) -> None:
    for key in _FIELDS:
        if key in data and data[key] is not None:
            value = data[key]
            if key == "scenarios" and isinstance(value, str):
                value = [c.strip() for c in value.split(",") if c.strip()]
            setattr(cfg, key, value)
