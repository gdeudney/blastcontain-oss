"""
Evidence scrubbing (roadmap P2) — hash PII/secrets before persist.

Scan evidence and decision payloads can carry exactly what governance is
trying to protect (a leaked key in a CRED finding's evidence, an email in a
tool argument). Persisting that verbatim makes the Ledger itself a liability.

Matched spans are replaced with ``[scrubbed:<kind>:<sha256-12>]`` — the hash
keeps values *correlatable* (the same secret scrubs to the same token across
packets) without keeping them *readable*. Regex baseline always runs; Presidio
upgrades PII detection when installed (availability-flag pattern — used if
present, never required).
"""
from __future__ import annotations

import hashlib
import re

# Order matters: longer/stricter patterns first so a key isn't half-eaten by a
# broader match.
_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("key", re.compile(r"\b(?:sk|pk|ghp|gho|xox[bps]|AKIA)[A-Za-z0-9_\-]{16,}\b")),
    ("bearer", re.compile(r"(?i)\b(?:bearer|token|api[_-]?key|secret)\s*[:=]\s*\S{8,}")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)

# Keys whose string values are scrubbed wherever they appear.
_SENSITIVE_KEYS = ("evidence", "detail", "args", "reason", "value", "snippet")


def _token(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    return f"[scrubbed:{kind}:{digest}]"


def scrub_text(text: str) -> tuple[str, int]:
    """Replace PII/secret spans in one string; returns (scrubbed, hits)."""
    hits = 0
    for kind, pattern in _PATTERNS:
        def _replace(match: re.Match, kind: str = kind) -> str:
            nonlocal hits
            hits += 1
            return _token(kind, match.group(0))

        text = pattern.sub(_replace, text)

    analyzer = _presidio()
    if analyzer is not None:
        try:
            results = analyzer.analyze(text=text, language="en",
                                       entities=["PERSON", "PHONE_NUMBER", "LOCATION"])
            for result in sorted(results, key=lambda r: -r.start):
                span = text[result.start:result.end]
                text = text[:result.start] + _token(result.entity_type.lower(), span) \
                    + text[result.end:]
                hits += 1
        except Exception:
            pass    # Presidio is best-effort augmentation, never a failure path
    return text, hits


def scrub_mapping(value, in_sensitive: bool = False) -> tuple[object, int]:
    """Walk a JSON-ish structure; scrub strings under sensitive keys."""
    total = 0
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            sensitive = in_sensitive or str(key).lower() in _SENSITIVE_KEYS
            scrubbed, hits = scrub_mapping(item, sensitive)
            out[key] = scrubbed
            total += hits
        return out, total
    if isinstance(value, list):
        out_list = []
        for item in value:
            scrubbed, hits = scrub_mapping(item, in_sensitive)
            out_list.append(scrubbed)
            total += hits
        return out_list, total
    if isinstance(value, str) and in_sensitive:
        return scrub_text(value)
    return value, 0


def scrub_packet(packet: dict) -> tuple[dict, int]:
    """Scrub a finding packet (or decision event) before it is persisted."""
    scrubbed, hits = scrub_mapping(packet)
    if hits:
        scrubbed["evidence_scrubbed"] = hits
    return scrubbed, hits


_PRESIDIO_ANALYZER = None
_PRESIDIO_TRIED = False


def _presidio():
    """The optional Presidio analyzer (None when not installed or disabled).

    Used-if-present (availability-flag pattern); set
    ``BLASTCONTAIN_SCRUB_PRESIDIO=0`` to skip it — its NLP engine takes tens of
    seconds to initialize, which tests and latency-sensitive ingest may decline.
    """
    global _PRESIDIO_ANALYZER, _PRESIDIO_TRIED
    if not _PRESIDIO_TRIED:
        _PRESIDIO_TRIED = True
        import os

        if os.environ.get("BLASTCONTAIN_SCRUB_PRESIDIO", "1").lower() in ("0", "false", "no"):
            _PRESIDIO_ANALYZER = None
            return None
        try:
            from presidio_analyzer import AnalyzerEngine  # type: ignore

            _PRESIDIO_ANALYZER = AnalyzerEngine()
        except Exception:
            _PRESIDIO_ANALYZER = None
    return _PRESIDIO_ANALYZER
