"""Compiling a core CharterSchema into a governance.toolkit/v1 ruleset."""
from blastcontain_core.charter import CharterSchema, EnvironmentConstraints, HitlConfig

from blastcontain_guard.compile import compile_charter
from blastcontain_guard.evaluator import evaluate
from blastcontain_guard.models import Action, EvalInput
from blastcontain_guard.policy import RuleAction


def _charter():
    return CharterSchema(
        agent_id="invoice-bot", environment="prod", version="1.0", trust_tier=1,
        permitted_tools=["query_invoice", "send_receipt"],
        environment_constraints=EnvironmentConstraints(egress_blocked=True),
        hitl_config=HitlConfig(required_for=["destructive_apis"]),
    )


def test_interactive_compile():
    rs = compile_charter(_charter(), autonomy_mode="interactive")
    assert rs.agent_id == "invoice-bot"
    assert rs.autonomy_mode == "interactive"

    # permitted tool -> allow
    assert evaluate(rs, EvalInput("query_invoice", action_type="read")).action is Action.ALLOW
    # destructive -> ask (interactive)
    assert evaluate(rs, EvalInput("x", action_type="delete")).action is Action.ASK
    # egress_blocked -> deny sends
    assert evaluate(rs, EvalInput("anything", action_type="send")).action is Action.DENY
    # unknown tool -> default deny
    assert evaluate(rs, EvalInput("rm_rf", action_type="exec")).action is Action.DENY


def test_autonomy_switch_flips_ask_to_deny():
    rs = compile_charter(_charter(), autonomy_mode="autonomous")
    # the HITL gate compiles to deny when no human is present
    decision = evaluate(rs, EvalInput("x", action_type="delete"))
    assert decision.action is Action.DENY


def test_rule_order_is_deny_then_ask_then_allow():
    rs = compile_charter(_charter(), autonomy_mode="interactive")
    actions = [r.action for r in rs.rules]
    # first the env deny, then the hitl gate, then the permitted-tools allow
    assert actions[0] is RuleAction.DENY
    assert RuleAction.ALLOW in actions
    assert actions.index(RuleAction.ALLOW) == len(actions) - 1
