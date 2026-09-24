"""
Discovery scanner: filesystem / repo walk.

Walks a path for two shadow-AI fingerprints: unregistered model-weight files
and agent config entrypoints. Honours ``.blastcontainignore`` via
``blastcontain_core.ignore`` and skips the usual heavy dirs.
"""
from __future__ import annotations

import os
from pathlib import Path

from ..models import AssetClassification, DiscoveredAsset

_MODEL_EXTENSIONS = frozenset({".gguf", ".bin", ".pt", ".safetensors", ".onnx", ".ckpt"})
_AGENT_CONFIG_NAMES = frozenset({
    "agent.json", "agent.yaml", "agent.yml", "charter.json", "charter.yaml",
    "langgraph.json", "crewai.yaml", "autogen.json", "smolagents.json",
})
_SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", ".venv", "venv",
                        ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build"})


def scan(search_path: str = ".") -> list[DiscoveredAsset]:
    """Walk `search_path` for model files and agent config entrypoints."""
    root_path = Path(search_path)
    if not root_path.exists():
        return []

    assets: list[DiscoveredAsset] = []
    for root, dirs, files in os.walk(search_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for filename in files:
            filepath = os.path.join(root, filename)
            rel = os.path.relpath(filepath, search_path)
            ext = Path(filename).suffix.lower()
            name = filename.lower()

            if ext in _MODEL_EXTENSIONS:
                assets.append(DiscoveredAsset(
                    asset_id=f"model-{rel}",
                    asset_type="model_file",
                    location=filepath,
                    classification=AssetClassification.UNKNOWN_SHADOW_AI,
                    risk_indicators=["unregistered model-weight file"],
                    scanner="repo",
                ))
            elif name in _AGENT_CONFIG_NAMES:
                assets.append(DiscoveredAsset(
                    asset_id=f"config-{rel}",
                    asset_type="agent_config",
                    location=filepath,
                    classification=AssetClassification.UNKNOWN_SHADOW_AI,
                    risk_indicators=["agent configuration file"],
                    candidate_ids=[Path(root).name],   # the dir often == the agent name
                    scanner="repo",
                ))
    return assets
