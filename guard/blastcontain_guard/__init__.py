"""
blastcontain-guard — the in-process enforcer teams embed in their copilots.

Guard loads an agent's policy — a local ``governance.toolkit/v1`` YAML ruleset
(open, standalone) *or* a compiled Charter — intercepts tool calls at the
framework boundary, resolves **allow / ask / deny**, prompts the user on *ask*,
and streams every decision as a signed CloudEvent to the Ledger. AGT is an
*optional backend*, not a requirement (guard-spec §1, §8).

The wedge is fully open and standalone: Guard + a local YAML is a complete,
useful governance toolkit on its own; the commercial Platform (which *issues*
signed Charters) is purely additive (guard-spec §1.1).

Layout:
  policy      — the ``governance.toolkit/v1`` ruleset (load + validate)
  condition   — a safe, eval-free expression evaluator for rule conditions
  evaluator   — the deterministic allow/ask/deny decision (first-match,
                default-deny, the approver split, single-hop delegation)
  ask         — how *ask* actually resolves (interactive prompt vs autonomous)
  learning    — allow-always -> a permitted_tools proposal (derive-then-ratify)
  telemetry   — decisions as CloudEvents over pluggable sinks (jsonl/Ledger/OTel)
  guard       — the facade: from_yaml / from_charter_file, on_ask, @guard.tool
  compile     — CharterSchema (blastcontain-core) -> a compiled ruleset
  backends    — native (always-on primary) + AGT (optional, fail-closed)
  adapters    — framework hooks: generic decorator, MCP middleware, Claude Code
  reporter    — a signed decision-log packet (Audit-Packet envelope)

Shared primitives (signing, the Charter schema) come from blastcontain-core, so
Guard's signed output drops into the same Ledger as Verify and Drill.
"""
from __future__ import annotations

__version__ = "0.1.0"

from .guard import Guard, GuardDenied
from .models import (
    Action,
    Approver,
    AskChoice,
    AskRequest,
    AskResult,
    Decision,
    EnforcementResult,
    EvalInput,
)

__all__ = [
    "Guard",
    "GuardDenied",
    "Action",
    "Approver",
    "AskChoice",
    "AskRequest",
    "AskResult",
    "Decision",
    "EnforcementResult",
    "EvalInput",
    "__version__",
]
