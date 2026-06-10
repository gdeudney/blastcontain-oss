"""
BlastContain Verify — the check-group contract.

The typed boundary between the scanner orchestrator and check groups (built-in
or plugin). This module is a deliberate *leaf*: it imports only the config and
core models, so check modules can import it without creating a cycle with
`registry.py` (which imports the check modules to build the inventory).

Layering:  contract (types)  ←  checks/*  ←  registry  ←  scanner
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from blastcontain_core.models import InfraFinding

from .config import VerifyConfig


@dataclass
class ScanState:
    """Cross-group facts accumulated as groups run, in registry order.

    `fired` holds the check IDs that produced findings in groups that have
    already run — composites read it (MEM-05 checks ``"ENV-02" in fired``).
    Findings coerced to SKIP by ``--skip-checks`` are *not* recorded, so
    skipping a prerequisite also suppresses its composites (longstanding
    behavior, preserved).
    """
    fired: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class CheckContext:
    """Everything a check group may read. Typed field access on `cfg` is the
    point: a renamed config field becomes a mypy/AttributeError at the read
    site instead of a silently-defaulted ``**kwargs`` entry."""
    cfg: VerifyConfig
    state: ScanState


@dataclass
class CheckGroupResult:
    """A group's verdicts. `skipped` entries are ``{"check_id", "reason"}``
    dicts — the audit-packet shape, unchanged across the registry refactor."""
    findings: list[InfraFinding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


@runtime_checkable
class CheckGroup(Protocol):
    """What the scanner requires of any check group.

    Built-ins satisfy this via `registry.CheckGroupSpec`; plugins provide any
    object with these three members (see docs/plugins.md). `provides` declares
    the check IDs the group owns — enforced unique across the whole registry.
    """
    name: str
    provides: frozenset[str]

    def run(self, ctx: CheckContext) -> CheckGroupResult: ...
