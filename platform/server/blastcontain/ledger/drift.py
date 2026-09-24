"""
Pattern detection + Charter drift (roadmap P2) — declared vs observed.

The Charter says what the agent *may* do; the decision stream and the scans
say what it *does* and what its environment *is*. Divergence in either
direction is a governance signal:

  - **unused grants** — permitted tools with zero runtime use: right-sizing
    candidates ("tool unused → drop?", feeds P5);
  - **unlisted attempts** — tools invoked that the Charter never granted
    (denied by default-deny, but the pressure is the signal);
  - **learning candidates** — the same gated action repeatedly approved by the
    human: runtime derive-then-ratify, propose adding it to the allowlist
    (mirrors Guard's allow-always learning);
  - **scan contradictions** — a constraint the Charter declares that the
    latest Verify scan shows is not true of the deployment.
"""
from __future__ import annotations

LEARNING_CANDIDATE_MIN_APPROVALS = 3

# constraint field -> finding_types that contradict it in a Verify scan
_CONSTRAINT_CONTRADICTIONS: dict[str, tuple[str, ...]] = {
    "egress_blocked": ("blastcontain.env.egress_unrestricted",),
    "read_only_rootfs": ("blastcontain.env.rootfs_writable",),
}


def _data(event: dict) -> dict:
    data = event.get("data")
    return data if isinstance(data, dict) else event


def compute_drift(
    document: dict,
    decision_events: list[dict],
    latest_scan: dict | None = None,
) -> dict:
    """Declared-vs-observed drift for one (agent, environment)."""
    decisions = [_data(e) for e in decision_events]
    permitted = set(document.get("permitted_tools") or [])

    used: dict[str, int] = {}
    for d in decisions:
        tool = str(d.get("tool", "") or "")
        if tool:
            used[tool] = used.get(tool, 0) + 1

    unused_grants = sorted(permitted - set(used))

    unlisted: dict[str, dict] = {}
    for d in decisions:
        tool = str(d.get("tool", "") or "")
        if tool and tool not in permitted:
            entry = unlisted.setdefault(tool, {"attempts": 0, "denied": 0})
            entry["attempts"] += 1
            if str(d.get("final", "")).lower() == "deny":
                entry["denied"] += 1

    # Repeatedly human-approved gated actions -> allowlist proposals.
    approvals: dict[tuple[str, str], int] = {}
    for d in decisions:
        if (str(d.get("decision", "")).lower() == "ask"
                and str(d.get("final", "")).lower() == "allow"):
            key = (str(d.get("tool", "")), str(d.get("action_type", "")))
            approvals[key] = approvals.get(key, 0) + 1
    learning_candidates = [
        {"tool": tool, "action_type": action, "approvals": count,
         "proposal": f"add '{tool}' to permitted_tools (ratify runtime reality)"}
        for (tool, action), count in sorted(approvals.items(), key=lambda kv: -kv[1])
        if count >= LEARNING_CANDIDATE_MIN_APPROVALS
    ]

    scan_contradictions = []
    if latest_scan:
        constraints = document.get("environment_constraints") or {}
        scan_types = {f.get("finding_type") for f in latest_scan.get("findings", [])}
        for constraint_field, contradiction_types in _CONSTRAINT_CONTRADICTIONS.items():
            if constraints.get(constraint_field):
                hits = sorted(scan_types & set(contradiction_types))
                if hits:
                    scan_contradictions.append({
                        "constraint": constraint_field,
                        "declared": True,
                        "contradicted_by": hits,
                    })

    has_drift = bool(unused_grants or unlisted or learning_candidates or scan_contradictions)
    return {
        "decisions_analyzed": len(decisions),
        "unused_grants": unused_grants,
        "unlisted_attempts": [
            {"tool": tool, **stats} for tool, stats in sorted(unlisted.items())
        ],
        "learning_candidates": learning_candidates,
        "scan_contradictions": scan_contradictions,
        "drift_detected": has_drift,
    }
