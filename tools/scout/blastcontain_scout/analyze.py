"""
Triage + classification — the "derive" brain.

Two stages, both availability-flagged so the scout runs with or without a model:

  1. score_relevance()  — model-free keyword score (always runs; cheap pre-filter).
  2. classify()         — an LLM (local LM Studio, OpenAI-compatible) confirms
                          relevance and classifies the paper into dataset /
                          technique / intel, suggests a Drill category, and notes
                          any released artifact + license. Falls back to a keyword
                          heuristic when no model is reachable.

License is treated as *unknown until a human verifies* — the scout only flags the
need (the Llama-Guard / JAILJUDGE lesson: non-permissive sources must not be
vendored). It proposes; a human ratifies.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from .arxiv import Paper

# Drill attack-category keys the scout may suggest (mirrors core DRILL_CATEGORY_TAXONOMY).
DRILL_CATEGORIES = (
    "prompt_injection_direct",
    "prompt_injection_indirect",
    "data_exfiltration",
    "jailbreak",
    "tool_misuse",
    "mcp_hijack",
)

_ARTIFACT_HOSTS = ("github.com", "huggingface.co", "gitlab.com", "zenodo.org")
_RELEASE_HINTS = ("we release", "we introduce", "dataset", "benchmark", "we provide", "open-source", "open source")
_TECHNIQUE_HINTS = ("attack", "method", "approach", "framework", "template", "algorithm", "technique", "bypass")

_CATEGORY_HINTS = (
    ("indirect", "prompt_injection_indirect"),
    ("tool poison", "mcp_hijack"),
    ("mcp", "mcp_hijack"),
    ("tool", "tool_misuse"),
    ("exfiltrat", "data_exfiltration"),
    ("data leak", "data_exfiltration"),
    ("inject", "prompt_injection_direct"),
    ("jailbreak", "jailbreak"),
)


@dataclass
class Analysis:
    paper: Paper
    relevance: float
    relevant: bool
    kind: str                       # "dataset" | "technique" | "intel"
    summary: str
    suggested_category: str
    artifact_url: Optional[str]
    license_note: str
    rationale: str
    scored_by: str                  # "llm" | "heuristic"


def score_relevance(paper: Paper, terms) -> float:
    """Model-free 0..1 relevance from term hits (title weighted 3x)."""
    title = paper.title.lower()
    summary = paper.summary.lower()
    hits = 0.0
    for t in terms:
        tl = t.lower()
        hits += 3.0 * title.count(tl) + summary.count(tl)
    # Squash: 0 hits -> 0, ~3 weighted hits -> ~0.75, saturates toward 1.
    return round(1.0 - 1.0 / (1.0 + hits), 3)


def find_artifact(text: str) -> Optional[str]:
    """First dataset/code URL on a known host, if any."""
    for m in re.finditer(r"https?://[^\s)\]}>,]+", text):
        url = m.group(0).rstrip(".")
        if any(h in url for h in _ARTIFACT_HOSTS):
            return url
    return None


def _guess_category(text: str) -> str:
    low = text.lower()
    for needle, cat in _CATEGORY_HINTS:
        if needle in low:
            return cat
    return "jailbreak"


def _heuristic(paper: Paper, relevance: float, threshold: float) -> Analysis:
    text = paper.text
    low = text.lower()
    artifact = find_artifact(text)
    if artifact and any(h in low for h in _RELEASE_HINTS):
        kind = "dataset"
    elif any(h in low for h in _TECHNIQUE_HINTS):
        kind = "technique"
    else:
        kind = "intel"
    return Analysis(
        paper=paper,
        relevance=relevance,
        relevant=relevance >= threshold,
        kind=kind,
        summary=paper.title,
        suggested_category=_guess_category(text),
        artifact_url=artifact,
        license_note="unknown — verify before vendoring",
        rationale="keyword heuristic (no judge model)",
        scored_by="heuristic",
    )


_SYSTEM = (
    "You triage AI-security papers for a red-team attack corpus. Given a paper's "
    "title and abstract, decide whether it is relevant to jailbreaking, prompt "
    "injection, or attacking LLM agents/tools, and what it contributes: "
    "'dataset' (it releases reusable attack data), 'technique' (a new attack "
    "method/template), or 'intel' (relevant findings but no directly reusable "
    "artifact). Pick the single best category from this list: "
    f"{', '.join(DRILL_CATEGORIES)}. Note any released dataset/code URL and its "
    "license if stated (else 'unknown'). Reply with ONLY a JSON object: "
    '{"relevant":bool,"kind":"dataset|technique|intel","category":"<one>",'
    '"summary":"<one line, what is new>","artifact_url":"<url or null>",'
    '"license":"<text or unknown>","rationale":"<short>"}'
)


def _parse_json(raw: str) -> dict:
    try:
        return json.loads(raw)
    except Exception:
        m = re.search(r"\{.*\}", raw or "", re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return {}
    return {}


def classify(
    paper: Paper,
    terms,
    backend=None,
    threshold: float = 0.5,
) -> Analysis:
    """LLM classification with a keyword-heuristic fallback."""
    relevance = score_relevance(paper, terms)
    if backend is None:
        return _heuristic(paper, relevance, threshold)
    user = f"TITLE: {paper.title}\n\nABSTRACT: {paper.summary}\n\nClassify it."
    try:
        raw = backend.chat(
            [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": user}],
            temperature=0.0,
            max_tokens=400,
        )
    except Exception:
        return _heuristic(paper, relevance, threshold)
    v = _parse_json(raw)
    if not v:
        return _heuristic(paper, relevance, threshold)
    kind = str(v.get("kind", "intel")).lower()
    if kind not in ("dataset", "technique", "intel"):
        kind = "intel"
    category = str(v.get("category", "")).strip()
    if category not in DRILL_CATEGORIES:
        category = _guess_category(paper.text)
    artifact = v.get("artifact_url") or find_artifact(paper.text)
    if isinstance(artifact, str) and not artifact.lower().startswith("http"):
        artifact = None
    lic = str(v.get("license", "unknown")).strip() or "unknown"
    return Analysis(
        paper=paper,
        relevance=relevance,
        relevant=bool(v.get("relevant", relevance >= threshold)),
        kind=kind,
        summary=str(v.get("summary", paper.title))[:300],
        suggested_category=category,
        artifact_url=artifact,
        license_note=lic if lic.lower() != "unknown" else "unknown — verify before vendoring",
        rationale=str(v.get("rationale", ""))[:300],
        scored_by="llm",
    )
