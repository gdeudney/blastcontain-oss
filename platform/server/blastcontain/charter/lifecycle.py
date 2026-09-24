"""
Agent lifecycle (charter-spec §7) — states, signed operations, transitions.

The platform owns the governance record and the Charter state; runtime
suspend/kill mechanics are the enforcement plane's job (AGT Nexus / the Guard
deny-all path — a suspended state is served to enforcers, who deny-all on it).

Three suspends, deliberately distinct (§7.1): **pause** is operator-initiated
and graceful; **quarantine** is governance-initiated by a CRITICAL finding and
exits only via recertification; **kill** is break-glass — immediate, landing
in paused pending review.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

PAUSE_MODES = ("deny-all", "drain", "halt")

# operation -> (allowed source states, resulting state)
_TRANSITIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "register":      (("draft", "discovered"), "active"),
    "pause":         (("active",), "paused"),
    "resume":        (("paused",), "active"),
    "quarantine":    (("active", "paused"), "quarantined"),
    "recertify":     (("quarantined",), "active"),
    "kill":          (("active", "paused", "quarantined"), "paused"),
    "rollback":      (("active",), "active"),
    "decommission":  (("draft", "active", "paused", "quarantined"), "decommissioned"),
    "archive":       (("decommissioned",), "archived"),
    "recommission":  (("decommissioned", "archived"), "draft"),
}

# Logged governance actions that do not move the state machine.
_STATE_PRESERVING = ("transfer_owner", "promote", "exception", "sign")


class LifecycleError(ValueError):
    """An operation that the state machine does not permit."""


@dataclass
class Operation:
    """One signed, logged governance action (§7.1) — the decision-rights log."""

    op: str
    agent_id: str
    environment: str
    from_state: str
    to_state: str
    actor: str
    at: str
    reason: str = ""
    params: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def transition(
    op: str,
    current_state: str,
    agent_id: str,
    environment: str,
    actor: str,
    at: str,
    reason: str = "",
    params: dict | None = None,
) -> Operation:
    """Validate and record a lifecycle operation; raises LifecycleError."""
    params = dict(params or {})

    if op in _STATE_PRESERVING:
        return Operation(op, agent_id, environment, current_state, current_state,
                         actor, at, reason, params)

    if op not in _TRANSITIONS:
        raise LifecycleError(f"unknown lifecycle operation {op!r}")

    allowed_from, to_state = _TRANSITIONS[op]
    if current_state not in allowed_from:
        raise LifecycleError(
            f"cannot {op} an agent in state {current_state!r} "
            f"(requires one of: {', '.join(allowed_from)})"
        )

    if op == "pause":
        mode = str(params.get("mode", "deny-all"))
        if mode not in PAUSE_MODES:
            raise LifecycleError(f"pause mode must be one of {PAUSE_MODES}, got {mode!r}")
        params["mode"] = mode
    if op == "quarantine" and not params.get("finding_type"):
        raise LifecycleError("quarantine requires params.finding_type (the CRITICAL trigger)")
    if op == "kill":
        params["break_glass"] = True

    return Operation(op, agent_id, environment, current_state, to_state,
                     actor, at, reason, params)
