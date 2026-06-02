"""
Render the scout's output: a human-readable digest + inert corpus scaffolds.

The scaffolds are the key derive-then-ratify trick: each dataset/technique paper
becomes a *valid but inert* `AttackSource` subclass whose `is_available()` returns
False, so it is silently skipped by `load_corpus` until a human vendors the data
and flips it on. That means the PR can be merged safely — it adds proposals, not
live attacks — and the reviewer ratifies by implementing `dataset()`.
"""
from __future__ import annotations

import re

from .analyze import Analysis

_KIND_HEADERS = {
    "dataset": "🆕 Datasets (candidate AttackSources)",
    "technique": "🛠 Techniques (candidate Operators)",
    "intel": "📌 Intel (relevant, no reusable artifact)",
}


def slug(arxiv_id: str) -> str:
    return "c_" + re.sub(r"[^0-9a-z]+", "_", arxiv_id.lower()).strip("_")


def scaffold_filename(analysis: Analysis) -> str:
    return f"{slug(analysis.paper.arxiv_id)}.py"


def month_bucket(paper) -> str:
    """A YYYY-MM bucket from the paper's date (arXiv ids are YYMM), for foldering."""
    pub = (paper.published or "")[:7]
    if len(pub) == 7 and pub[4] == "-" and pub[:4].isdigit() and pub[5:7].isdigit():
        return pub
    digits = re.sub(r"[^0-9]", "", paper.arxiv_id)
    if len(digits) >= 4 and "01" <= digits[2:4] <= "12":
        return f"20{digits[:2]}-{digits[2:4]}"
    return "undated"


def scaffold_relpath(analysis: Analysis, source: str = "arxiv") -> str:
    """Path under contrib/, bucketed by source then month: e.g. arxiv/2026-06/c_x.py."""
    return f"{source}/{month_bucket(analysis.paper)}/{scaffold_filename(analysis)}"


def render_scaffold(analysis: Analysis) -> str:
    """A valid-but-inert AttackSource scaffold citing the paper."""
    p = analysis.paper
    s = slug(p.arxiv_id)
    cls = "Contrib" + "".join(part.title() for part in s.split("_") if part)
    authors = ", ".join(p.authors[:4]) + ("…" if len(p.authors) > 4 else "")
    return f'''"""
CANDIDATE attack source — proposed by blastcontain-scout, NOT yet ratified.

Paper:    {p.title}
arXiv:    {p.arxiv_id}  ({p.abs_url})
Authors:  {authors}
Category: {analysis.suggested_category}
Kind:     {analysis.kind}
Artifact: {analysis.artifact_url or "(none found — check the paper)"}
License:  {analysis.license_note}

Summary:  {analysis.summary}

⚠️  INERT until ratified. `is_available()` returns False, so `load_corpus` skips
this source. To ratify: (1) verify the license permits vendoring (Apache/MIT/BSD;
reject Llama-Community / gated), (2) vendor the data or implement `dataset()`,
(3) flip `is_available()` to a real check, (4) register it in `corpus/__init__.py`
with an `enable_*` flag, and (5) set `revision` to the dataset commit/version.
"""
from __future__ import annotations

from typing import Optional

# Absolute import so the scaffold is valid no matter how deep it is foldered under
# contrib/ (e.g. contrib/arxiv/2026-06/) — relative-import depth would otherwise break.
from blastcontain_drill.corpus.base import GOAL_CONTENT, Attack, AttackSource


class {cls}Source(AttackSource):
    name = "{s.replace('_', '-')}"
    layer = "replay"
    revision = "{p.arxiv_id}"   # TODO: pin to the dataset commit once vendored

    def is_available(self) -> bool:
        return False  # TODO: flip once the data is vendored and the license verified

    def dataset(
        self,
        categories: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> list[Attack]:
        # TODO: load attacks from the paper's released artifact, e.g.:
        #   Attack(id="{s}-0", category="{analysis.suggested_category}",
        #          prompt="…", technique="{p.arxiv_id}", goal=GOAL_CONTENT,
        #          expected_refusal=True, source="{s.replace('_', '-')}")
        return []
'''


def _line(a: Analysis, source: str) -> str:
    p = a.paper
    bits = [
        f"- **{p.title}** · `arXiv:{p.arxiv_id}` · relevance {a.relevance:.2f} · "
        f"category `{a.suggested_category}` · license: {a.license_note}",
        f"  - {a.summary}",
        f"  - {p.abs_url}",
    ]
    if a.artifact_url:
        bits.append(f"  - artifact: {a.artifact_url}")
    if a.kind in ("dataset", "technique"):
        rel = scaffold_relpath(a, source)
        bits.append(f"  - scaffold: `drill/blastcontain_drill/corpus/contrib/{rel}` (inert until ratified)")
    return "\n".join(bits)


def render_digest(analyses: list[Analysis], today: str, source: str = "arxiv") -> str:
    keepers = [a for a in analyses if a.relevant]
    lines = [
        f"# Corpus Scout digest — {today}",
        "",
        f"{len(keepers)} relevant new paper(s) of {len(analyses)} scanned. "
        "Scaffolds are **inert** (`is_available()` → False) — review, verify license, "
        "vendor data, then enable. _Derived by blastcontain-scout; a human ratifies._",
        "",
    ]
    for kind in ("dataset", "technique", "intel"):
        group = [a for a in keepers if a.kind == kind]
        if not group:
            continue
        lines += [f"## {_KIND_HEADERS[kind]}", ""]
        lines += [_line(a, source) for a in sorted(group, key=lambda x: -x.relevance)]
        lines.append("")
    flagged = [a for a in keepers if a.license_note.lower().startswith("unknown")
               or "llama" in a.license_note.lower()]
    if flagged:
        lines += ["## ⚖️ License watch (verify before vendoring)", ""]
        lines += [f"- `arXiv:{a.paper.arxiv_id}` — {a.license_note}" for a in flagged]
        lines.append("")
    return "\n".join(lines)
