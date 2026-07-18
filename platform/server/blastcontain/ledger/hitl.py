"""
HITL quality metrics (roadmap P2 ★) — is the human gate real?

For interactive copilots the approval gate IS the control, so its quality is a
first-class governance signal: approval latency, override rate, allow-always
pressure, and the rubber-stamp pattern (everything approved, instantly). Fed by
Guard's decision CloudEvents (guard-spec §10 — `decision`, `final`,
`ask_choice`, `latency_ms`, `concern`).

Post-hoc LLM-judge sampling of approvals is planned, not built.
"""
from __future__ import annotations

import statistics

# Heuristic thresholds for the rubber-stamp pattern (OWASP T10 adjacent):
# enough volume to mean something, near-total approval, near-instant decisions.
RUBBER_STAMP_MIN_ASKS = 20
RUBBER_STAMP_APPROVAL_RATE = 0.95
RUBBER_STAMP_MEDIAN_LATENCY_MS = 2000.0


def _data(event: dict) -> dict:
    data = event.get("data")
    return data if isinstance(data, dict) else event


def compute_hitl_metrics(events: list[dict]) -> dict:
    """Aggregate HITL quality from a window of decision events."""
    decisions = [_data(e) for e in events]
    total = len(decisions)
    by_decision = {"allow": 0, "ask": 0, "deny": 0}
    for d in decisions:
        key = str(d.get("decision", "")).lower()
        if key in by_decision:
            by_decision[key] += 1

    asks = [d for d in decisions if str(d.get("decision", "")).lower() == "ask"]
    approvals = [d for d in asks if str(d.get("final", "")).lower() == "allow"]
    overrides = [d for d in asks if str(d.get("final", "")).lower() == "deny"]
    allow_always = [d for d in asks if d.get("ask_choice") == "allow_always"]

    latencies = sorted(
        float(d.get("latency_ms") or 0.0) for d in asks if d.get("latency_ms") is not None
    )
    median_latency = statistics.median(latencies) if latencies else None
    p95_latency = latencies[max(0, int(len(latencies) * 0.95) - 1)] if latencies else None

    asks_total = len(asks)
    approval_rate = (len(approvals) / asks_total) if asks_total else None
    override_rate = (len(overrides) / asks_total) if asks_total else None

    rubber_stamp = bool(
        asks_total >= RUBBER_STAMP_MIN_ASKS
        and approval_rate is not None and approval_rate >= RUBBER_STAMP_APPROVAL_RATE
        and median_latency is not None and median_latency < RUBBER_STAMP_MEDIAN_LATENCY_MS
    )

    deny_concerns: dict[str, int] = {}
    for d in decisions:
        if str(d.get("final", "")).lower() == "deny" and d.get("concern"):
            deny_concerns[d["concern"]] = deny_concerns.get(d["concern"], 0) + 1

    return {
        "events_total": total,
        "by_decision": by_decision,
        "asks_total": asks_total,
        "approvals": len(approvals),
        "overrides": len(overrides),
        "approval_rate": round(approval_rate, 4) if approval_rate is not None else None,
        "override_rate": round(override_rate, 4) if override_rate is not None else None,
        "allow_always_count": len(allow_always),
        "approval_latency_ms": {
            "median": median_latency,
            "p95": p95_latency,
            "samples": len(latencies),
        },
        "rubber_stamp_risk": rubber_stamp,
        "top_denied_concerns": sorted(
            deny_concerns.items(), key=lambda kv: kv[1], reverse=True
        )[:5],
        "degraded_events": sum(1 for d in decisions if d.get("degraded")),
        "notes": "llm-judge sampling of approvals: planned (roadmap P2)",
    }
