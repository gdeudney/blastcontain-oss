"""
blastcontain_guard.evaluator — the deterministic allow/ask/deny decision.

A small, pure function over a compiled ruleset (mirrors AGT's ``condition ->
action``, guard-spec §5):

  * **first matching rule wins**; otherwise ``default_action`` (deny-by-default);
  * ``require_approval`` resolves to ``ask``; the rule's ``approvers`` ride along
    so resolution can honour the **honesty line** — ``[self]`` is the user's to
    lift, ``[central]`` is a mandatory Standard no user can override (§3.7);
  * **single-hop delegation** (optional): if a parent context is present, the
    call is evaluated against both rulesets and the **stricter** decision wins —
    a parent ``deny`` is immutable (the weakest-link rule, charter-spec §2.4).

Sub-millisecond, no network, no side effects — telemetry and the *ask* round-trip
happen above this layer (in ``guard``), so the decision itself stays a pure
function you can unit-test exhaustively.
"""
from __future__ import annotations

import dataclasses

from .concerns import risk_tag_for
from .models import Action, Decision, EvalInput, stricter
from .policy import Rule, RuleAction, Ruleset

_RULE_TO_ACTION: dict[RuleAction, Action] = {
    RuleAction.ALLOW: Action.ALLOW,
    RuleAction.DENY: Action.DENY,
    RuleAction.REQUIRE_APPROVAL: Action.ASK,
}


def build_context(inp: EvalInput, environment: str = "") -> dict:
    """Assemble the namespace a condition is evaluated against (condition.py)."""
    dctx = inp.delegation_ctx
    return {
        "tool_name": inp.tool_name,
        "action": {"type": inp.action_type},
        "args": inp.args or {},
        "identity": inp.identity or {},
        "agent_id": inp.agent_id,
        "environment": environment,
        "delegation": (
            {"parent_agent_id": dctx.parent_agent_id, "depth": dctx.depth} if dctx else {}
        ),
    }


def _decision_from_rule(rule: Rule) -> Decision:
    action = _RULE_TO_ACTION[rule.action]
    return Decision(
        action=action,
        reason=f"matched rule '{rule.name}' (action={rule.action.value})",
        rule=rule.name,
        approvers=list(rule.approvers) if action is not Action.ALLOW else [],
        matched=True,
        risk_tag=risk_tag_for(rule.concern),
        concern=rule.concern,
    )


def _decision_from_default(ruleset: Ruleset) -> Decision:
    action = _RULE_TO_ACTION[ruleset.default_action]
    approvers: list[str] = []
    if action is Action.DENY:
        approvers = ["central"]
    elif action is Action.ASK:
        approvers = ["self"]
    return Decision(
        action=action,
        reason=f"no rule matched; default_action={ruleset.default_action.value}",
        rule=None,
        approvers=approvers,
        matched=False,
    )


def _evaluate_single(ruleset: Ruleset, inp: EvalInput) -> Decision:
    ctx = build_context(inp, environment=ruleset.environment or "")
    for rule in ruleset.rules:
        if rule.matches(ctx):
            return _decision_from_rule(rule)
    return _decision_from_default(ruleset)


def evaluate(ruleset: Ruleset, inp: EvalInput) -> Decision:
    """Resolve a tool call to allow / ask / deny against ``ruleset``.

    Honours single-hop delegation when ``inp.delegation_ctx`` carries a parent
    ruleset. Multi-hop is out of scope in v1 and fails closed (guard-spec §11).
    """
    own = _evaluate_single(ruleset, inp)

    dctx = inp.delegation_ctx
    if dctx is None:
        return own

    if dctx.depth > 1:
        # Single-hop only in v1 — a deeper chain we cannot reason about denies.
        return Decision(
            action=Action.DENY,
            reason=(
                f"multi-hop delegation (depth={dctx.depth}) is not supported in v1; "
                "single-hop only — failing closed"
            ),
            rule=None,
            approvers=["central"],
            matched=False,
        )

    if dctx.parent_ruleset is None:
        return own

    parent = _evaluate_single(dctx.parent_ruleset, inp)
    return _merge_stricter(own, parent, dctx.parent_agent_id)


def _merge_stricter(own: Decision, parent: Decision, parent_agent_id: str) -> Decision:
    """Weakest-link: the stricter of child/parent wins; parent deny is immutable."""
    if stricter(own.action, parent.action) == parent.action and parent.action != own.action:
        return dataclasses.replace(
            parent,
            reason=(
                f"delegation weakest-link: parent '{parent_agent_id}' is stricter "
                f"— {parent.reason}"
            ),
        )
    return own
