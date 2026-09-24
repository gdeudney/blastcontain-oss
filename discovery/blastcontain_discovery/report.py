"""
Sign and emit a Discovery report.

Same Audit-Packet envelope as Verify and Drill: ``{packet, signature}`` where
the signature is produced by ``blastcontain_core.signing``. A signed Discovery
report is tamper-evident evidence of "what we found and when" — and the
Ledger ingests it the same way it ingests scans.
"""
from __future__ import annotations

import json
from pathlib import Path

from blastcontain_core.signing import sign_packet

from .models import DiscoveryReport


def sign_report(report: DiscoveryReport, key_id: str | None = None) -> dict:
    """Return a signed ``{packet, signature}`` bundle for the report."""
    packet = report.as_packet()
    signature = sign_packet(packet, signed_at=report.scanned_at, key_id=key_id)
    return {"packet": packet, "signature": signature}


def write_report(report: DiscoveryReport, path: str, sign: bool = True) -> None:
    """Write the report to `path` as JSON — signed bundle by default."""
    payload = sign_report(report) if sign else report.as_packet()
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
