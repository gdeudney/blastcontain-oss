"""
BlastContain Verify — SARIF output (thin wrapper around blastcontain_core).

The SARIF builder lives in `blastcontain_core.sarif` so all BlastContain
tools emit identical SARIF format. This wrapper sets the tool metadata
appropriate for verify (name, version, info URI, help URI).
"""
from __future__ import annotations

from blastcontain_core.models import ScanResult
from blastcontain_core.sarif import write_sarif as _write_sarif


_TOOL_NAME      = "blastcontain-verify"
_TOOL_INFO_URI  = "https://github.com/blastcontain/verify"
_HELP_URI       = "https://github.com/blastcontain/verify/blob/main/docs/spec.md"


def write_sarif(scan: ScanResult, path: str) -> dict:
    """Write SARIF 2.1.0 output for a verify ScanResult."""
    from . import __version__  # avoid circular import at module load
    return _write_sarif(
        scan,
        path,
        tool_name=_TOOL_NAME,
        tool_version=__version__,
        tool_info_uri=_TOOL_INFO_URI,
        help_uri=_HELP_URI,
    )
