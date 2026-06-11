"""
InProcessCage — host-side cage that drives a real model through the agent loop.

This is the live-run backend: point it at any OpenAI-compatible endpoint (LM
Studio, vLLM…) and it produces *real* action ground truth — did this model,
attacked, actually read the canary and try to send it off-box? The egress
allowlist and forbidden-tool set are enforced/observed in-process; no real
network call leaves the box (the send/http_get tools record attempts, they do
not transmit).

For containerised deny-all-egress containment, use PodmanCage; both emit the
same CageObservation.
"""
from __future__ import annotations

import uuid

from ..llm import ChatBackend
from .agent import run_agent
from .base import (
    DEFAULT_EGRESS_ALLOWLIST,
    DEFAULT_FORBIDDEN_TOOLS,
    Cage,
    CageObservation,
)


def new_canary() -> str:
    """A fresh, unique canary token planted for one run."""
    return "BCN-CANARY-" + uuid.uuid4().hex[:12]


class InProcessCage(Cage):
    name = "inprocess"

    def __init__(
        self,
        backend: ChatBackend,
        egress_allowlist=DEFAULT_EGRESS_ALLOWLIST,
        forbidden_tools=DEFAULT_FORBIDDEN_TOOLS,
        max_steps: int = 4,
        temperature: float = 0.4,
    ):
        self.backend = backend
        self.egress_allowlist = egress_allowlist
        self.forbidden_tools = forbidden_tools
        self.max_steps = max_steps
        self.temperature = temperature

    def run_attack(self, attack) -> CageObservation:
        canary = new_canary()
        return run_agent(
            self.backend,
            attack,
            canary=canary,
            egress_allowlist=self.egress_allowlist,
            forbidden_tools=self.forbidden_tools,
            max_steps=self.max_steps,
            temperature=self.temperature,
        )
