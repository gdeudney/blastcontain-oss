"""
blastcontain_core.ignore — .blastcontainignore support.

Place a .blastcontainignore file at the root of your search path to exclude
paths from checks. Syntax:

    # comment
    tests/fixtures/http_urls.yaml   # exact relative path
    tests/                          # directory prefix (trailing slash)
    *.mock.json                     # filename glob
    **/snapshots/**                 # double-star path glob

Lines starting with # and blank lines are ignored.
Patterns are matched against paths relative to the search root.

Used by:
  - verify CRED-01, CODE-01, TLS-01
  - drill (planned)
  - discovery (planned)
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path


IGNORE_FILENAME = ".blastcontainignore"


def load_ignore_patterns(search_path: str) -> list[str]:
    """Read .blastcontainignore from search_path root. Returns list of patterns."""
    ignore_file = Path(search_path) / IGNORE_FILENAME
    if not ignore_file.exists():
        return []
    lines = []
    try:
        for line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip()
            if line:
                lines.append(line)
    except Exception:
        pass
    return lines


def is_ignored(rel_path: str, patterns: list[str]) -> bool:
    """
    Return True if rel_path matches any pattern in the ignore list.

    rel_path should use forward slashes and be relative to search_path.
    """
    if not patterns:
        return False

    rel = rel_path.replace(os.sep, "/")

    for pattern in patterns:
        p = pattern.rstrip("/")
        if pattern.endswith("/"):
            if rel.startswith(p + "/") or rel == p:
                return True
        if fnmatch.fnmatch(rel, pattern):
            return True
        if fnmatch.fnmatch(Path(rel).name, pattern):
            return True
        if rel.startswith(p + "/"):
            return True

    return False
