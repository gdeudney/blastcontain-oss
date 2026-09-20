"""
BlastContain Verify — SARIF output (thin wrapper around blastcontain_core).

The SARIF builder lives in `blastcontain_core.sarif` so all BlastContain
tools emit identical SARIF format. This wrapper sets the tool metadata
appropriate for verify (name, version, info URI, help URI).
"""
from __future__ import annotations

import json

from blastcontain_core.models import ScanResult
from blastcontain_core.sarif import write_sarif as _write_sarif


_TOOL_NAME      = "blastcontain-verify"
_TOOL_INFO_URI  = "https://github.com/blastcontain/verify"
_HELP_URI       = "https://github.com/blastcontain/verify/blob/main/docs/spec.md"


def write_sarif(scan: ScanResult, path: str) -> dict:
    """Write SARIF 2.1.0 output for a verify ScanResult."""
    from . import __version__  # avoid circular import at module load
    sarif = _write_sarif(
        scan,
        path,
        tool_name=_TOOL_NAME,
        tool_version=__version__,
        tool_info_uri=_TOOL_INFO_URI,
        help_uri=_HELP_URI,
    )

    if hasattr(scan, "target"):
        properties = sarif["runs"][0]["invocations"][0]["properties"]
        properties.pop("agent_id", None)
        properties.update(target=scan.target, inventory=scan.inventory, coverage=scan.coverage)
        if scan.validation is not None:
            properties["control_validation"] = scan.validation
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(sarif, handle, indent=2)
    if hasattr(scan, "sandbox_validation"):
        sarif["runs"][0]["invocations"][0]["properties"]["sandbox_validation"] = scan.sandbox_validation
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(sarif, handle, indent=2)
    return sarif
