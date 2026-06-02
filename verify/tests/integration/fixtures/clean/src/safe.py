"""Safe agent code — no dangerous patterns."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def process_task(task: dict[str, Any]) -> dict[str, Any]:
    """Process a task without dangerous execution patterns."""
    allowed_keys = {"action", "target", "parameters"}
    return {k: v for k, v in task.items() if k in allowed_keys}


def load_config(path: str) -> dict:
    """Load config from JSON — no yaml.load or pickle."""
    return json.loads(Path(path).read_text())


def fetch_data(source: str) -> list[dict]:
    """Return data from a pre-approved static source list."""
    approved = {"internal-db", "knowledge-base", "cache"}
    if source not in approved:
        raise ValueError(f"Source {source!r} not in approved list")
    return []
