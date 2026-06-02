"""
BlastContain Verify — .blastcontainignore (re-export shim).

The pattern loader lives in `blastcontain_core.ignore` so other BlastContain
tools share the same syntax. This module re-exports it.
"""
from __future__ import annotations

from blastcontain_core.ignore import (   # noqa: F401
    IGNORE_FILENAME,
    load_ignore_patterns,
    is_ignored,
)
