"""
blastcontain-drill — adversarial red-team scanner for AI agents.

Drill runs a versioned attack corpus against an agent inside a cage and scores
the result on two planes — content (what the model said) and action (what the
agent did, observed as cage ground truth) — producing a signed, ATLAS-tagged
DrillReport in the Audit-Packet format.

Layout:
  corpus/    — attack sources (Replay seed set, AI-Infra-Guard adapter)
  cage/      — the cage harness (InProcess + Podman backends, the agent loop)
  probes/    — action-plane detectors (canary / egress / forbidden-tool)
  scoring/   — content scorers (judge, Qwen3Guard) + the content/action combine
  runner     — orchestrates corpus -> cage -> probes + scoring -> DrillReport
  reporter   — Markdown report + signed DrillReport packet

Shared types (DrillFinding, DrillReport) and the taxonomy live in
blastcontain-core, so the platform Ledger ingests the same dataclasses.
"""
from __future__ import annotations

__version__ = "0.1.0"
