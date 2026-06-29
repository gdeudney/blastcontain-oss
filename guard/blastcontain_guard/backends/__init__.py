"""
blastcontain_guard.backends — native primary, AGT as the deeper front (§8).

Native and AGT are **not either/or**; they are the two fronts enforcing the
*same* compiled policy. Guard-native always owns interception, the decision, and
the *ask* UX (AGT can't render the copilot prompt). When AGT is enabled it
*backs* native out-of-process, so the policy still holds even if the in-process
library is bypassed.

Availability: if AGT is enabled but unreachable, Guard **fails closed** — never a
silent downgrade to the weaker in-process layer. For a native *allow* with no
second-front confirmation, that means deny; a native *deny*/*ask* is already
strict, so it stands (flagged degraded). An opt-in ``degrade_to_native`` serves
the native decision instead, but always alerts.
"""
from __future__ import annotations

import dataclasses

from ..models import Action, Decision, EvalInput, stricter
from ..policy import Ruleset
from .agt import AgtBackend, AgtUnavailable
from .native import NativeBackend

__all__ = [
    "NativeBackend",
    "AgtBackend",
    "AgtUnavailable",
    "combine_with_agt",
]


def _stricter_decision(native: Decision, other: Decision) -> Decision:
    """Pick the stricter of two decisions (the second front can only tighten)."""
    if stricter(native.action, other.action) == other.action and other.action != native.action:
        return dataclasses.replace(
            other, reason=f"AGT (out-of-process) is stricter — {other.reason}"
        )
    return native


def combine_with_agt(
    native: Decision, ruleset: Ruleset, inp: EvalInput, agt: AgtBackend
) -> tuple[Decision, bool]:
    """Fold an optional AGT second front into the native decision.

    Returns ``(decision, degraded)``. ``degraded`` is True when AGT was enabled
    but unreachable — a logged degradation, never a silent downgrade.
    """
    if not agt.enabled:
        return native, False

    if agt.available():
        try:
            agt_decision = agt.evaluate(ruleset, inp)
        except AgtUnavailable:
            return _fail_closed(native, agt)
        if getattr(agt, "sole", False):
            # AGT is the only decider; native is pass-through (the thin-shim config).
            return agt_decision, False
        return _stricter_decision(native, agt_decision), False

    return _fail_closed(native, agt)


def _fail_closed(native: Decision, agt: AgtBackend) -> tuple[Decision, bool]:
    if native.action is Action.ALLOW and not agt.degrade_to_native:
        denied = dataclasses.replace(
            native,
            action=Action.DENY,
            approvers=["central"],
            reason=(
                "AGT backend enabled but unreachable — failing closed "
                f"(in-process front said {native.action.value}: {native.reason})"
            ),
        )
        return denied, True
    # deny/ask already strict, or degrade-to-native opted in: serve native, flag it.
    note = " [degraded: AGT unreachable, served by in-process front]"
    return dataclasses.replace(native, reason=native.reason + note), True
