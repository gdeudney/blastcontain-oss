"""
blastcontain_guard.reporter — the signed decision-log packet.

The decision *stream* is the live audit trail (telemetry, §10). The decision
*log* is its at-rest, tamper-evident form: a batch of decision CloudEvents
wrapped in the same Audit-Packet envelope Verify and Drill produce, signed by
``blastcontain_core.signing`` (Ed25519, HMAC fallback). It is EU AI Act Art. 12/14
evidence and drops into the Ledger through the same verifier.
"""
from __future__ import annotations

import datetime
import json
import os
from collections import Counter

from blastcontain_core.signing import sign_packet, verify_packet  # noqa: F401 (re-export)

from . import __version__


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _summarize(events: list[dict]) -> dict:
    decisions = Counter()
    finals = Counter()
    for event in events:
        data = event.get("data", {})
        decisions[data.get("decision", "unknown")] += 1
        finals[data.get("final", "unknown")] += 1
    return {
        "total": len(events),
        "by_decision": dict(decisions),     # allow / ask / deny (evaluated)
        "by_outcome": dict(finals),          # allow / deny (after resolution)
    }


def build_decision_log(agent_id: str, environment: str, events: list[dict]) -> dict:
    """Build the unsigned decision-log payload."""
    return {
        "agent_id": agent_id,
        "environment": environment,
        "generated_at": _utc_now_iso(),
        "generator": "blastcontain-guard",
        "generator_version": __version__,
        "summary": _summarize(events),
        "decisions": events,
    }


def write_decision_log(agent_id: str, environment: str, events: list[dict], path: str) -> dict:
    """Write and return a signed JSON decision-log packet (schema_version 1.1)."""
    payload = build_decision_log(agent_id, environment, events)
    signature = sign_packet(payload, signed_at=_utc_now_iso())
    packet = {"schema_version": "1.1", "packet": payload, "signature": signature}

    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(packet, f, indent=2)
    return packet
