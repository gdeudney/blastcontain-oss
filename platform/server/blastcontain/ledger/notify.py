"""
Human-alert sink (roadmap P2) — the enforcement plane for agents you can't gate.

For side-of-desk copilots BlastContain doesn't sit in the tool-call path of,
"enforcement" is **detect + tell a human** — a quarantine, a CRITICAL finding,
a shadow-AI discovery, or traffic to a retired agent has to reach someone, or
the governance is silent. This module is that reach: a single fire-and-forget
webhook.

Deliberately minimal and dependency-light:
  * one generic JSON webhook (`BLASTCONTAIN_WEBHOOK_URL`) — Slack/Teams/PagerDuty
    all accept an inbound JSON POST, so this is the universal adapter;
  * **never raises** — an alerting failure must not break ingestion or a
    lifecycle transition. Failures increment a counter and are swallowed;
  * no-op when unconfigured, so dev and tests stay quiet.

Richer routing (per-owner, escalation ladders, dedupe) is a later concern; the
point here is that governance events stop being invisible.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Optional

# Event types (stable strings — a downstream router can filter on these).
QUARANTINE = "quarantine"
TOMBSTONE = "tombstone_traffic"
CRITICAL_FINDING = "critical_finding"
SHADOW_DISCOVERED = "shadow_discovered"

_SEVERITY = {
    QUARANTINE: "critical",
    TOMBSTONE: "high",
    CRITICAL_FINDING: "critical",
    SHADOW_DISCOVERED: "warning",
}


@dataclass
class Notifier:
    """Fire-and-forget webhook alerting. Safe to construct always; no-op when
    no URL is set."""

    webhook_url: Optional[str] = None
    timeout: float = 5.0
    sent: int = 0
    dropped: int = 0

    @classmethod
    def from_env(cls) -> "Notifier":
        return cls(webhook_url=os.environ.get("BLASTCONTAIN_WEBHOOK_URL") or None)

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def notify(self, event_type: str, agent_id: str, environment: str,
               summary: str, at: str, **extra) -> bool:
        """Post one alert. Returns True if delivered, False otherwise (never raises)."""
        if not self.webhook_url:
            return False
        payload = {
            "source": "blastcontain-ledger",
            "event": event_type,
            "severity": _SEVERITY.get(event_type, "info"),
            "agent_id": agent_id,
            "environment": environment,
            "summary": summary,
            "at": at,
            **extra,
        }
        try:
            import httpx

            resp = httpx.post(self.webhook_url, json=payload, timeout=self.timeout)
            if resp.status_code >= 400:
                raise RuntimeError(f"webhook returned {resp.status_code}")
            self.sent += 1
            return True
        except Exception as exc:  # noqa: BLE001 — alerting must never break the caller
            self.dropped += 1
            print(
                f"Warning: alert webhook failed ({event_type} for {agent_id}): {exc}",
                file=sys.stderr,
            )
            return False


def summarize(event_type: str, agent_id: str, detail: str = "") -> str:
    """A one-line human summary for an event type."""
    base = {
        QUARANTINE: f"Agent {agent_id} auto-quarantined",
        TOMBSTONE: f"Traffic to decommissioned agent {agent_id}",
        CRITICAL_FINDING: f"CRITICAL finding on {agent_id}",
        SHADOW_DISCOVERED: f"Shadow agent discovered: {agent_id}",
    }.get(event_type, f"Governance event on {agent_id}")
    return f"{base} — {detail}" if detail else base


# Re-exported for callers that want the raw JSON without a Notifier instance.
def build_alert(event_type: str, agent_id: str, environment: str, summary: str,
                at: str, **extra) -> str:
    return json.dumps({
        "source": "blastcontain-ledger", "event": event_type,
        "severity": _SEVERITY.get(event_type, "info"), "agent_id": agent_id,
        "environment": environment, "summary": summary, "at": at, **extra,
    })
