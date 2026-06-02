"""Cage harness — InProcess (live model) and Podman (deny-all-egress) backends."""
from __future__ import annotations

from .agent import run_agent
from .base import (
    CANARY_FILE,
    DEFAULT_EGRESS_ALLOWLIST,
    DEFAULT_FORBIDDEN_TOOLS,
    Cage,
    CageObservation,
    EgressAttempt,
    ToolCall,
)
from .inprocess import InProcessCage, new_canary
from .stub import StubChatClient

__all__ = [
    "Cage", "CageObservation", "ToolCall", "EgressAttempt",
    "InProcessCage", "new_canary", "StubChatClient", "run_agent",
    "CANARY_FILE", "DEFAULT_EGRESS_ALLOWLIST", "DEFAULT_FORBIDDEN_TOOLS",
]


def __getattr__(name: str):
    # Lazy import so `import blastcontain_drill.cage` doesn't require Podman.
    if name == "PodmanCage":
        from .podman import PodmanCage

        return PodmanCage
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
