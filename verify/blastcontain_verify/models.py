"""
BlastContain Verify — models (re-export shim).

All scan result types live in `blastcontain_core.models`. This module
re-exports them so existing `from .models import InfraFinding` imports
keep working without code changes.
"""
from __future__ import annotations

# noqa-imports — public re-exports
from blastcontain_core.models import (   # noqa: F401
    InfraFinding,
    ScanResult,
    ScanStatus,
    Severity,
)
