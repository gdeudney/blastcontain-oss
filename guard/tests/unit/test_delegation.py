"""Single-hop delegation: the weakest-link rule (charter-spec §2.4)."""
from blastcontain_guard.evaluator import evaluate
from blastcontain_guard.models import Action, DelegationContext, EvalInput
from blastcontain_guard.policy import parse_ruleset


def test_parent_deny_overrides_child_allow():
    child = parse_ruleset({"default_action": "allow", "rules": []})
    parent = parse_ruleset({
        "default_action": "deny",
        "rules": [{"name": "no-send", "condition": "action.type == 'send'", "action": "deny"}],
    })
    inp = EvalInput("exfil", action_type="send",
                    delegation_ctx=DelegationContext("parent-agent", parent))
    d = evaluate(child, inp)
    assert d.action is Action.DENY
    assert "weakest-link" in d.reason


def test_child_may_be_stricter_than_parent():
    child = parse_ruleset({"default_action": "deny", "rules": []})
    parent = parse_ruleset({"default_action": "allow", "rules": []})
    d = evaluate(child, EvalInput("t", delegation_ctx=DelegationContext("p", parent)))
    assert d.action is Action.DENY   # child's own deny stands


def test_multi_hop_fails_closed():
    child = parse_ruleset({"default_action": "allow", "rules": []})
    parent = parse_ruleset({"default_action": "allow", "rules": []})
    d = evaluate(child, EvalInput("t", delegation_ctx=DelegationContext("p", parent, depth=2)))
    assert d.action is Action.DENY
    assert "multi-hop" in d.reason


def test_no_parent_ruleset_uses_own():
    child = parse_ruleset({"default_action": "allow", "rules": []})
    d = evaluate(child, EvalInput("t", delegation_ctx=DelegationContext("p", None)))
    assert d.action is Action.ALLOW
