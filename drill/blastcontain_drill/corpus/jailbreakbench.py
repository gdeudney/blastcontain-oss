"""
JailbreakBench (JBB-Behaviors) attack source — a vendored Replay dataset.

100 harmful behaviors (standard content-policy jailbreak targets) + 100 thematically-paired
BENIGN behaviors. The benign split is the value-add: it lets Drill score **over-refusal**
(a refusal on a safe request = a false positive), which the hand-written seed corpus can't
express. Harmful rows carry expected_refusal=True; benign rows expected_refusal=False, which the
combine step reads to flip the verdict (see scoring/combine.py).

MIT-licensed, ungated — see data/jbb/SOURCE.md. Data only; the upstream judge is not used.
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Optional

from .base import GOAL_CONTENT, Attack, AttackSource

_DATA = Path(__file__).parent / "data" / "jbb"

# Pinned to the JBB-Behaviors commit the CSVs were vendored from (HF dataset repo).
# Recorded in the signed report as `jailbreakbench@<rev>` for reproducibility.
JBB_REVISION = "886acc3"


class JailbreakBenchSource(AttackSource):
    name = "jailbreakbench"
    layer = "replay"
    revision = JBB_REVISION

    def is_available(self) -> bool:
        return (_DATA / "harmful-behaviors.csv").exists()

    def _load_file(self, filename: str, benign: bool) -> list[Attack]:
        path = _DATA / filename
        if not path.exists():
            return []
        attacks: list[Attack] = []
        with open(path, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                goal = (row.get("Goal") or "").strip()
                if not goal:
                    continue
                idx = (row.get("Index") or str(len(attacks))).strip()
                behavior = (row.get("Category") or "").strip().lower().replace(" ", "-")
                attacks.append(
                    Attack(
                        id=f"jbb-{'benign' if benign else 'harm'}-{idx}",
                        # Harmful JBB behaviors are content-policy jailbreaks; benign ones are
                        # over-refusal probes (no Drill taxonomy — they aren't attacks).
                        category="benign" if benign else "jailbreak",
                        prompt=goal,
                        technique=f"jbb/{behavior}" if behavior else "jbb",
                        layer="replay",
                        goal=GOAL_CONTENT,
                        expected_refusal=not benign,
                        source="jailbreakbench",
                    )
                )
        return attacks

    def dataset(
        self,
        categories: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> list[Attack]:
        attacks = self._load_file("harmful-behaviors.csv", benign=False)
        attacks += self._load_file("benign-behaviors.csv", benign=True)
        if categories:
            cats = set(categories)
            attacks = [a for a in attacks if a.category in cats]
        if limit:
            seen: dict[str, int] = {}
            out: list[Attack] = []
            for a in attacks:
                n = seen.get(a.category, 0)
                if n < limit:
                    out.append(a)
                    seen[a.category] = n + 1
            attacks = out
        return attacks
