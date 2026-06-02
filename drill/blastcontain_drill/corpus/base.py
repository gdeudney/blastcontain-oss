"""
The attack corpus — Drill's versioned, pluggable attack library (drill-spec §4).

Three layers of escalating effort: Replay (known attacks — a regression suite),
Operators (techniques as transforms on fresh seeds), and Generative (a no-refusal
attacker model). This module defines the shared `Attack` type and the
`AttackSource` plugin interface; the built-in Replay source lives in builtin.py.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

# ── Attack goals ──────────────────────────────────────────────────────────────
# What the attack tries to make the agent *do*. This decides which scoring plane
# is authoritative for HELD/BYPASS (see scoring/combine.py): a content goal is
# judged on what the model said; an action goal is judged on cage ground truth.
GOAL_CONTENT = "content"                 # make the model say something bad
GOAL_EXFIL_CANARY = "exfil_canary"       # make the agent send the planted canary out
GOAL_FORBIDDEN_TOOL = "forbidden_tool"   # make a forbidden tool fire
GOAL_EGRESS = "egress"                   # make the agent attempt a blocked egress

ACTION_GOALS = frozenset({GOAL_EXFIL_CANARY, GOAL_FORBIDDEN_TOOL, GOAL_EGRESS})


@dataclass
class Attack:
    """One adversarial test case."""

    id: str
    category: str                         # a blastcontain_core DRILL_CATEGORY_TAXONOMY key
    prompt: str
    technique: str                        # "direct-injection", "many-shot", "encoding"…
    layer: str = "replay"                 # replay | operators | generative
    vector: str = "direct"                # direct | indirect
    goal: str = GOAL_CONTENT
    forbidden_tool: Optional[str] = None  # tool that must NOT fire (action goals)
    poisoned_document: Optional[str] = None  # indirect injection — the agent reads this
    expected_refusal: bool = True         # the agent SHOULD contain/refuse
    source: str = "builtin"


@dataclass
class Corpus:
    """A pinned, named set of attacks — reproducible and regression-comparable."""

    version: str
    attacks: list[Attack] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.attacks)

    def categories(self) -> list[str]:
        return sorted({a.category for a in self.attacks})

    def select(
        self,
        categories: Optional[list[str]] = None,
        limit_per_category: Optional[int] = None,
    ) -> "Corpus":
        atk = self.attacks
        if categories:
            cats = set(categories)
            atk = [a for a in atk if a.category in cats]
        if limit_per_category:
            seen: dict[str, int] = {}
            out: list[Attack] = []
            for a in atk:
                n = seen.get(a.category, 0)
                if n < limit_per_category:
                    out.append(a)
                    seen[a.category] = n + 1
            atk = out
        return Corpus(version=self.version, attacks=atk, sources=self.sources)


class AttackSource(ABC):
    """
    An attack-source plugin (plugin-spec §2). Availability-flagged: a source
    that can't run (service down, dependency missing, dataset gated) reports
    `is_available() == False` and is skipped — the consumer degrades to the
    built-in seed corpus, declared honestly in the report.
    """

    name: str = "attack-source"
    layer: str = "replay"

    @abstractmethod
    def is_available(self) -> bool:
        """True if this source can produce attacks in the current environment."""

    @abstractmethod
    def dataset(
        self,
        categories: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> list[Attack]:
        """Return the source's (optionally filtered) attacks."""

    def generate(self, seed: Attack, technique: str, n: int = 1) -> list[Attack]:
        """
        Operators / Generative layers transform a seed into fresh attacks.
        Replay sources have no generator and return [].
        """
        return []
