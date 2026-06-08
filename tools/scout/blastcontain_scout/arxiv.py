"""
arXiv query + Atom parsing — the discovery engine.

Uses the public arXiv API (no key) at export.arxiv.org. We search recent papers
in the security/NLP/ML categories for jailbreak / prompt-injection / agent-attack
terms, newest first, and parse the Atom feed into `Paper` records. Parsing is
split out so it is unit-testable against a fixture without network access.
"""
from __future__ import annotations

# Parse with defusedxml, not the stdlib ElementTree: the feed is untrusted network
# input, and defused fromstring() forbids entity/external-entity expansion (billion
# laughs / XXE) while returning standard Element objects, so the rest of the parser
# is unchanged.
import defusedxml.ElementTree as ET
from dataclasses import dataclass, field
from defusedxml.common import DefusedXmlException
from typing import Optional

API_URL = "https://export.arxiv.org/api/query"

# arXiv categories worth watching for agent-attack research.
DEFAULT_CATEGORIES = ("cs.CR", "cs.CL", "cs.AI", "cs.LG")

# Abstract terms that signal a jailbreak / agent-attack contribution.
DEFAULT_TERMS = (
    "jailbreak",
    "prompt injection",
    "prompt-injection",
    "red team",
    "red-teaming",
    "adversarial prompt",
    "guardrail bypass",
    "agent hijack",
    "indirect injection",
    "tool poisoning",
)

_ATOM = "{http://www.w3.org/2005/Atom}"
_ARXIV = "{http://arxiv.org/schemas/atom}"


@dataclass
class Paper:
    """One arXiv entry, normalized."""

    arxiv_id: str                 # bare id, e.g. "2401.12345" (version stripped)
    title: str
    summary: str
    published: str                # ISO date
    updated: str
    authors: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    pdf_url: Optional[str] = None
    abs_url: Optional[str] = None

    @property
    def text(self) -> str:
        return f"{self.title}\n{self.summary}"


def build_query(
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    terms: tuple[str, ...] = DEFAULT_TERMS,
) -> str:
    """Build an arXiv `search_query` string: (cat:… OR …) AND (abs:"…" OR …)."""
    cat = " OR ".join(f"cat:{c}" for c in categories)
    # Quote multi-word terms so arXiv treats them as phrases.
    abs_terms = " OR ".join(
        f'abs:"{t}"' if " " in t else f"abs:{t}" for t in terms
    )
    return f"({cat}) AND ({abs_terms})"


def _strip_id(raw: str) -> str:
    """http://arxiv.org/abs/2401.12345v2  ->  2401.12345"""
    tail = (raw or "").rsplit("/", 1)[-1]
    if "v" in tail:
        head, _, ver = tail.rpartition("v")
        if head and ver.isdigit():
            return head
    return tail


def parse_feed(xml_text: str) -> list[Paper]:
    """Parse an arXiv Atom feed into Paper records."""
    try:
        root = ET.fromstring(xml_text)
    except (ET.ParseError, DefusedXmlException):
        # Malformed XML, or a feed that trips defusedxml's entity/DTD guards — treat
        # as "no papers" so one bad/hostile response doesn't crash an unattended run.
        return []
    papers: list[Paper] = []
    for entry in root.findall(f"{_ATOM}entry"):
        raw_id = (entry.findtext(f"{_ATOM}id") or "").strip()
        title = " ".join((entry.findtext(f"{_ATOM}title") or "").split())
        summary = " ".join((entry.findtext(f"{_ATOM}summary") or "").split())
        if not raw_id or not title:
            continue
        authors = [
            (a.findtext(f"{_ATOM}name") or "").strip()
            for a in entry.findall(f"{_ATOM}author")
        ]
        cats = [
            c.get("term", "") for c in entry.findall(f"{_ATOM}category")
        ]
        pdf_url = None
        for link in entry.findall(f"{_ATOM}link"):
            if link.get("title") == "pdf" or link.get("type") == "application/pdf":
                pdf_url = link.get("href")
        papers.append(
            Paper(
                arxiv_id=_strip_id(raw_id),
                title=title,
                summary=summary,
                published=(entry.findtext(f"{_ATOM}published") or "").strip(),
                updated=(entry.findtext(f"{_ATOM}updated") or "").strip(),
                authors=[a for a in authors if a],
                categories=[c for c in cats if c],
                pdf_url=pdf_url,
                abs_url=raw_id,
            )
        )
    return papers


def fetch(
    max_results: int = 50,
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    terms: tuple[str, ...] = DEFAULT_TERMS,
    timeout: float = 30.0,
    retries: int = 3,
    backoff: float = 3.0,
) -> list[Paper]:
    """
    Query the live arXiv API (newest first) and return parsed papers.

    arXiv rate-limits (429) and occasionally 5xx's. Since the scout runs unattended
    on a schedule, retry transient failures with a polite backoff (honoring any
    Retry-After header) so one blip doesn't fail the whole run. A non-transient
    client error (4xx other than 429) raises immediately.
    """
    import time

    import httpx

    params = {
        "search_query": build_query(categories, terms),
        "start": 0,
        "max_results": max_results,
        "sortBy": "submittedDate",
        "sortOrder": "descending",
    }
    resp = None
    for attempt in range(retries + 1):
        resp = httpx.get(API_URL, params=params, timeout=timeout, follow_redirects=True)
        if resp.status_code < 400:
            return parse_feed(resp.text)
        if resp.status_code != 429 and resp.status_code < 500:
            break  # non-transient client error — stop and raise below
        if attempt < retries:
            wait = float(resp.headers.get("retry-after") or backoff * (attempt + 1))
            time.sleep(min(wait, 30.0))
    resp.raise_for_status()
    return []
