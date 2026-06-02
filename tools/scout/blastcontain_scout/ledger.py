"""
Seen-ledger — persistent dedupe so each scout run only surfaces *new* papers.

A small JSON file (committed to the repo) mapping arXiv id -> first-seen date.
Checked into git so the dedupe state travels with the repo and a scheduled run
on any machine agrees on what's already been triaged.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass
class Ledger:
    path: str
    seen: dict[str, str]  # arxiv_id -> ISO date first seen

    @classmethod
    def load(cls, path: str) -> "Ledger":
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            seen = data.get("seen", data) if isinstance(data, dict) else {}
        except (OSError, ValueError):
            seen = {}
        return cls(path=path, seen=dict(seen))

    def is_new(self, arxiv_id: str) -> bool:
        return arxiv_id not in self.seen

    def filter_new(self, papers, today: str):
        """Return only papers not already in the ledger (does not mutate)."""
        return [p for p in papers if self.is_new(p.arxiv_id)]

    def mark(self, papers, today: str) -> int:
        """Record papers as seen. Returns how many were newly added."""
        added = 0
        for p in papers:
            if p.arxiv_id not in self.seen:
                self.seen[p.arxiv_id] = today
                added += 1
        return added

    def save(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"seen": self.seen}, f, indent=2, sort_keys=True)
