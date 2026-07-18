"""The Charter compiler — objectives → governance.toolkit/v1 (charter-spec §6)."""
from __future__ import annotations

import pytest
from blastcontain.charter.compiler import compile_document
from blastcontain.charter.schema import (
    CharterDocument,
    CharterSchema,
    EnvironmentConstraints,
    ExceptionRecord,
    Objective,
    Standard,
)

NOW = "2026-06-11T12:00:00Z"


def _doc(objectives=None, autonomy="interactive", egress_blocked=False, **control_kwargs):
    control = CharterSchema(
        agent_id="invoice-bot", environment="prod", version="1.0.0", trust_tier=1,
        permitted_tools=["query_invoice", "send_receipt"],
        environment_constraints=EnvironmentConstraints(egress_blocked=egress_blocked),
        **control_kwargs,
    )
    return CharterDocument(
        control=control,
        autonomy_mode=autonomy,
        objectives=[Objective(id=o) if isinstance(o, str) else o for o in (objectives or [])],
    )


def _rule(policy: dict, name: str) -> dict:
    matches = [r for r in policy["rules"] if r["name"] == name]
    assert matches, f"rule {name} not in {[r['name'] for r in policy['rules']]}"
    return matches[0]


def test_compiles_to_governance_toolkit_v1():
    result = compile_document(_doc(["no-prod-data-mutation"]), now_iso=NOW)
    policy = result.policy
    assert policy["apiVersion"] == "governance.toolkit/v1"
    assert policy["default_action"] == "deny"
    assert policy["agent_id"] == "invoice-bot"
    assert policy["autonomy_mode"] == "interactive"


def test_interactive_objective_compiles_to_ask():
    result = compile_document(_doc(["no-prod-data-mutation"]), now_iso=NOW)
    rule = _rule(result.policy, "no-prod-data-mutation-destructive")
    assert rule["action"] == "require_approval"
    assert rule["approvers"] == ["self"]
    assert rule["concern"] == "no-prod-data-mutation"


def test_autonomy_switch_flips_ask_to_deny():
    result = compile_document(
        _doc(["no-prod-data-mutation"], autonomy="autonomous"), now_iso=NOW
    )
    rule = _rule(result.policy, "no-prod-data-mutation-destructive")
    assert rule["action"] == "deny"
    assert rule["approvers"] == ["central"]


def test_mandatory_standard_never_degrades_to_ask():
    # §3.7: a mandatory Standard hard-denies even for interactive copilots.
    standard = Standard.from_dict({
        "id": "org-baseline", "name": "Org baseline", "version": "1",
        "objectives": [{"id": "no-pii-egress", "enforcement_level": "mandatory"}],
    })
    result = compile_document(_doc([]), standards=(standard,), now_iso=NOW)
    rule = _rule(result.policy, "no-pii-egress-send")
    assert rule["action"] == "deny"
    assert rule["approvers"] == ["central"]


def test_active_exception_lifts_objective():
    standard = Standard.from_dict({
        "id": "org-baseline", "name": "x", "version": "1",
        "objectives": [{"id": "no-pii-egress", "enforcement_level": "mandatory"}],
    })
    exception = ExceptionRecord(
        objective_id="no-pii-egress", agent_id="invoice-bot", environment="prod",
        justification="migration window", granted_by="ciso@example.com",
        granted_at=NOW, expires_at="2027-01-01T00:00:00Z",
    )
    result = compile_document(
        _doc([]), standards=(standard,), exceptions=(exception,), now_iso=NOW
    )
    assert "no-pii-egress" in result.exceptions_applied
    assert not any(r["name"].startswith("no-pii-egress") for r in result.policy["rules"])


def test_expired_exception_does_not_lift():
    standard = Standard.from_dict({
        "id": "org-baseline", "name": "x", "version": "1",
        "objectives": [{"id": "no-pii-egress", "enforcement_level": "mandatory"}],
    })
    exception = ExceptionRecord(
        objective_id="no-pii-egress", agent_id="invoice-bot", environment="prod",
        justification="expired", granted_by="ciso@example.com",
        granted_at="2026-01-01T00:00:00Z", expires_at="2026-02-01T00:00:00Z",
    )
    result = compile_document(
        _doc([]), standards=(standard,), exceptions=(exception,), now_iso=NOW
    )
    assert result.exceptions_applied == []
    assert _rule(result.policy, "no-pii-egress-send")["action"] == "deny"


def test_unknown_objective_blocks_signing():
    result = compile_document(_doc(["no-such-concern"]), now_iso=NOW)
    assert any(c.blocking and c.objective_id == "no-such-concern" for c in result.conflicts)


def test_constraint_mismatch_is_a_conflict():
    # block-exfiltration mandates egress_blocked=True; the control layer says False.
    result = compile_document(_doc(["block-exfiltration"]), now_iso=NOW)
    conflict = [c for c in result.conflicts if c.objective_id == "block-exfiltration"]
    assert conflict and not conflict[0].blocking      # self-selected → reconcile, not block

    standard = Standard.from_dict({
        "id": "org", "name": "x", "version": "1",
        "objectives": [{"id": "block-exfiltration", "enforcement_level": "mandatory"}],
    })
    result = compile_document(_doc([]), standards=(standard,), now_iso=NOW)
    conflict = [c for c in result.conflicts if c.objective_id == "block-exfiltration"]
    assert conflict and conflict[0].blocking          # mandatory → blocks signing (§3.6)


def test_allowlist_and_default_deny():
    result = compile_document(_doc([]), now_iso=NOW)
    rule = _rule(result.policy, "allow-permitted-tools")
    assert rule["action"] == "allow"
    assert "query_invoice" in rule["condition"]
    assert result.policy["rules"][-1] == rule          # allows sort last
    assert result.policy["default_action"] == "deny"


def test_overlapping_send_rules_dedupe_to_most_restrictive():
    # block-exfiltration (deny send) + no-pii-egress (ask send): deny survives.
    doc = _doc(["block-exfiltration", "no-pii-egress"], egress_blocked=True)
    result = compile_document(doc, now_iso=NOW)
    send_rules = [r for r in result.policy["rules"]
                  if r["condition"] == "action.type == 'send'"]
    assert len(send_rules) == 1
    assert send_rules[0]["action"] == "deny"
    # the lifted objective's refs point at the surviving rule
    pii = next(o for o in result.resolved_objectives if o.id == "no-pii-egress")
    assert pii.compiled_refs == [send_rules[0]["name"]]


def test_param_gated_objective_is_skipped_without_param():
    result = compile_document(_doc(["model-weights-attested"]), now_iso=NOW)
    assert not any(o.id == "model-weights-attested" for o in result.resolved_objectives)
    assert any(c.objective_id == "model-weights-attested" for c in result.conflicts)

    doc = _doc([Objective(id="model-weights-attested", params={"self_hosted": True})])
    result = compile_document(doc, now_iso=NOW)
    assert any(o.id == "model-weights-attested" for o in result.resolved_objectives)


def test_legacy_hitl_tokens_still_compile():
    doc = _doc([])
    doc.control.hitl_config.required_for = ["destructive_apis", "my_custom_tool"]
    result = compile_document(doc, now_iso=NOW)
    destructive = _rule(result.policy, "hitl-destructive-apis")
    assert destructive["action"] == "require_approval"
    custom = _rule(result.policy, "hitl-my-custom-tool")
    assert custom["condition"] == "tool_name == 'my_custom_tool'"


def test_oss_guard_parses_and_enforces_the_compiled_policy():
    """Cross-validation: the OSS reference enforcer accepts the platform compile."""
    pytest.importorskip("blastcontain_guard")
    from blastcontain_guard.evaluator import evaluate
    from blastcontain_guard.models import Action, EvalInput
    from blastcontain_guard.policy import parse_ruleset

    doc = _doc(["no-prod-data-mutation", "no-pii-egress", "no-dangerous-code-exec"])
    result = compile_document(doc, now_iso=NOW)
    ruleset = parse_ruleset(result.policy)

    assert evaluate(ruleset, EvalInput("query_invoice", action_type="read")).action is Action.ALLOW
    assert evaluate(ruleset, EvalInput("x", action_type="delete")).action is Action.ASK
    assert evaluate(ruleset, EvalInput("x", action_type="exec")).action is Action.DENY
    assert evaluate(ruleset, EvalInput("unknown_tool", action_type="read")).action is Action.DENY
