"""Ruleset parsing/validation for the governance.toolkit/v1 format."""
import pytest

from blastcontain_guard.policy import PolicyError, RuleAction, load_ruleset, parse_ruleset


def test_basic_parse():
    rs = parse_ruleset({
        "name": "p", "default_action": "deny",
        "rules": [{"name": "r", "condition": "tool_name == 'a'", "action": "allow"}],
    })
    assert rs.default_action is RuleAction.DENY
    assert len(rs.rules) == 1
    assert rs.rules[0].action is RuleAction.ALLOW


def test_default_action_defaults_to_deny():
    rs = parse_ruleset({"rules": []})
    assert rs.default_action is RuleAction.DENY


def test_approver_defaults_encode_the_honesty_line():
    rs = parse_ruleset({"rules": [
        {"name": "d", "condition": "tool_name == 'x'", "action": "deny"},
        {"name": "a", "condition": "tool_name == 'y'", "action": "require_approval"},
    ]})
    assert rs.rules[0].approvers == ["central"]   # a deny is centrally owned
    assert rs.rules[1].approvers == ["self"]      # a bare ask is the user's own


def test_central_only_alias_normalizes():
    rs = parse_ruleset({"rules": [
        {"name": "d", "condition": "tool_name == 'x'", "action": "deny", "approvers": ["central-only"]},
    ]})
    assert rs.rules[0].approvers == ["central"]


def test_duplicate_rule_name_rejected():
    with pytest.raises(PolicyError):
        parse_ruleset({"rules": [
            {"name": "x", "condition": "tool_name == 'a'", "action": "allow"},
            {"name": "x", "condition": "tool_name == 'b'", "action": "allow"},
        ]})


def test_bad_action_rejected():
    with pytest.raises(PolicyError):
        parse_ruleset({"rules": [{"name": "y", "condition": "tool_name == 'a'", "action": "maybe"}]})


def test_bad_condition_rejected_with_rule_context():
    with pytest.raises(PolicyError) as exc:
        parse_ruleset({"rules": [{"name": "z", "condition": "os.system('x')", "action": "allow"}]})
    assert "z" in str(exc.value)


def test_missing_condition_rejected():
    with pytest.raises(PolicyError):
        parse_ruleset({"rules": [{"name": "z", "action": "allow"}]})


def test_bad_autonomy_mode_rejected():
    with pytest.raises(PolicyError):
        parse_ruleset({"autonomy_mode": "semi", "rules": []})


def test_roundtrip_via_yaml(tmp_path):
    rs = parse_ruleset({
        "name": "p", "default_action": "deny", "agent_id": "a", "environment": "prod",
        "rules": [{"name": "r", "condition": "tool_name == 'a'", "action": "allow"}],
    })
    p = tmp_path / "p.yaml"
    p.write_text(rs.to_yaml(), encoding="utf-8")
    rs2 = load_ruleset(str(p))
    assert rs2.name == "p"
    assert rs2.agent_id == "a"
    assert len(rs2.rules) == 1


def test_load_missing_file():
    with pytest.raises(FileNotFoundError):
        load_ruleset("does-not-exist.yaml")
