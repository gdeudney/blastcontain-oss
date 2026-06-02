"""
Attack corpus package — assembles a pinned Corpus from available sources.

The built-in Replay seed set always contributes; optional sources (AI-Infra-Guard,
HF datasets, an attacker model) add on top when available, via the same
availability-flag pattern Verify uses for augmentation.
"""
from __future__ import annotations

from typing import Optional

from .aig import AIGAttackSource
from .base import (
    ACTION_GOALS,
    GOAL_CONTENT,
    GOAL_EGRESS,
    GOAL_EXFIL_CANARY,
    GOAL_FORBIDDEN_TOOL,
    Attack,
    AttackSource,
    Corpus,
)
from .builtin import BUILTIN_CORPUS_VERSION, BuiltinReplaySource
from .operators import OperatorsSource

__all__ = [
    "Attack", "AttackSource", "Corpus", "load_corpus",
    "BuiltinReplaySource", "AIGAttackSource", "OperatorsSource", "BUILTIN_CORPUS_VERSION",
    "GOAL_CONTENT", "GOAL_EXFIL_CANARY", "GOAL_FORBIDDEN_TOOL", "GOAL_EGRESS",
    "ACTION_GOALS",
]


def load_corpus(
    version: str = "latest",
    categories: Optional[list[str]] = None,
    limit: Optional[int] = None,
    extra_sources: Optional[list[AttackSource]] = None,
    enable_aig: bool = False,
    enable_operators: bool = False,
) -> Corpus:
    """
    Build a Corpus from all available sources.

    `version` "latest" pins to the built-in corpus version. `limit` caps attacks
    per category. `enable_operators` adds the model-free technique-transform layer;
    `enable_aig` adds the AI-Infra-Guard source if its service is up. Sources that
    aren't available are skipped; the ones that contributed are recorded in
    `Corpus.sources` so the report declares provenance honestly.
    """
    sources: list[AttackSource] = [BuiltinReplaySource()]
    if enable_operators:
        sources.append(OperatorsSource())
    if enable_aig:
        sources.append(AIGAttackSource())
    if extra_sources:
        sources.extend(extra_sources)

    attacks: list[Attack] = []
    used: list[str] = []
    for src in sources:
        try:
            if not src.is_available():
                continue
            got = src.dataset(categories=categories, limit=limit)
        except Exception:
            continue
        if got:
            attacks.extend(got)
            used.append(src.name)

    ver = BUILTIN_CORPUS_VERSION if (not version or version == "latest") else version
    return Corpus(version=ver, attacks=attacks, sources=used)
