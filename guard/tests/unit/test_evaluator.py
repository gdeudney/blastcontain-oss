"""The allow/ask/deny decision: first-match, default-deny, approver split, risk tags."""
from blastcontain_guard.evaluator import evaluate
from blastcontain_guard.models import Action, EvalInput
from blastcontain_guard.policy import parse_ruleset

RULESET = parse_ruleset({
    "default_action": "deny",
    "rules": [
        {"name": "allow-a", "condition": "tool_name == 'a'", "action": "allow"},
        {"name": "ask-delete", "condition": "action.type == 'delete'",
         "action": "require_approval", "approvers": ["self"], "concern": "no-prod-data-mutation"},
        {"name": "deny-send", "condition": "action.type == 'send'",
         "action": "deny", "approvers": ["central"], "concern": "block-exfiltration"},
    ],
})


def test_allow_first_match():
    d = evaluate(RULESET, EvalInput("a"))
    assert d.action is Action.ALLOW
    assert d.rule == "allow-a"
    assert d.matched


def test_ask_carries_self_approver_and_risk_tag():
    d = evaluate(RULESET, EvalInput("anything", action_type="delete"))
    assert d.action is Action.ASK
    assert d.approvers == ["self"]
    assert d.risk_tag and "OWASP" in d.risk_tag
    assert d.concern == "no-prod-data-mutation"


def test_deny_carries_central_approver():
    d = evaluate(RULESET, EvalInput("anything", action_type="send"))
    assert d.action is Action.DENY
    assert d.approvers == ["central"]


def test_default_deny_when_no_rule_matches():
    d = evaluate(RULESET, EvalInput("unknown-tool"))
    assert d.action is Action.DENY
    assert not d.matched
    assert d.rule is None


def test_first_match_wins_over_later_rules():
    rs = parse_ruleset({
        "default_action": "deny",
        "rules": [
            {"name": "broad-allow", "condition": "action.type == 'read'", "action": "allow"},
            {"name": "specific-deny", "condition": "tool_name == 'peek'", "action": "deny"},
        ],
    })
    # 'peek' is also a read; the earlier allow wins (rule order is the contract).
    d = evaluate(rs, EvalInput("peek", action_type="read"))
    assert d.action is Action.ALLOW
