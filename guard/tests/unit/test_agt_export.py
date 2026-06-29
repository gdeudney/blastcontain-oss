"""Emitting and pushing AGT policy — Guard and AGT enforce the same compiled rules."""
import yaml

from blastcontain_guard.agt_export import (
    AGT_API_VERSION,
    push_to_agt,
    to_agt_policy,
    to_agt_yaml,
)
from blastcontain_guard.policy import parse_ruleset

RS = parse_ruleset({
    "name": "bot-prod", "default_action": "deny",
    "agent_id": "bot", "environment": "prod", "autonomy_mode": "interactive",
    "rules": [
        {"name": "ask-del", "condition": "action.type == 'delete'",
         "action": "require_approval", "approvers": ["self"], "concern": "no-prod-data-mutation"},
        {"name": "allow-q", "condition": "tool_name == 'query'", "action": "allow"},
        {"name": "deny-send", "condition": "action.type == 'send'",
         "action": "deny", "approvers": ["central"]},
    ],
})


def test_clean_agt_doc_strips_extensions():
    doc = to_agt_policy(RS, include_metadata=False)
    assert set(doc) == {"apiVersion", "name", "default_action", "rules"}
    assert doc["apiVersion"] == AGT_API_VERSION
    assert doc["default_action"] == "deny"
    assert [r["name"] for r in doc["rules"]] == ["ask-del", "allow-q", "deny-send"]


def test_rule_vocabulary_is_agt_native():
    doc = to_agt_policy(RS, include_metadata=False)
    ask, allow, deny = doc["rules"]
    assert ask["action"] == "require_approval" and ask["approvers"] == ["self"]
    assert "concern" not in ask                 # Guard annotation, not an AGT field
    assert "approvers" not in allow             # allow carries none
    assert deny["action"] == "deny" and deny["approvers"] == ["central"]


def test_metadata_preserves_provenance():
    doc = to_agt_policy(RS, include_metadata=True)
    assert doc["metadata"]["agent_id"] == "bot"
    assert doc["metadata"]["autonomy_mode"] == "interactive"
    assert doc["metadata"]["generator"] == "blastcontain-guard"


def test_autonomy_switch_collapses_require_approval_to_deny():
    doc = to_agt_policy(RS, autonomy_mode="autonomous")
    ask = next(r for r in doc["rules"] if r["name"] == "ask-del")
    assert ask["action"] == "deny"             # no human to ask when unattended
    assert ask["approvers"] == ["central"]     # central exception only


def test_yaml_is_governance_toolkit():
    text = to_agt_yaml(RS)
    assert "apiVersion: governance.toolkit/v1" in text


def test_push_via_client_receives_policy():
    captured = {}
    result = push_to_agt(RS, client=lambda doc: captured.update(doc))
    assert result.delivered and result.transport == "client"
    assert captured["apiVersion"] == AGT_API_VERSION


def test_push_to_file(tmp_path):
    out = tmp_path / "agt-policy.yaml"
    result = push_to_agt(RS, path=str(out))
    assert result.delivered and result.transport == "file"
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert doc["name"] == "bot-prod"


def test_dry_run_renders_without_delivery():
    result = push_to_agt(RS, dry_run=True, path="/should-not-write")
    assert not result.delivered and result.transport == "none"
    assert result.policy["apiVersion"] == AGT_API_VERSION


def test_no_transport_renders_only():
    result = push_to_agt(RS)
    assert not result.delivered and result.transport == "none"


def test_guard_facade_push_applies_autonomy(tmp_path):
    from blastcontain_guard import Guard

    g = Guard.from_dict(
        {"default_action": "deny", "autonomy_mode": "autonomous",
         "rules": [{"name": "ask", "condition": "action.type == 'delete'",
                    "action": "require_approval", "approvers": ["self"]}]},
        agent_id="a",
    )
    out = tmp_path / "p.yaml"
    result = g.push_to_agt(path=str(out))
    assert result.delivered
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    # the facade passed autonomy_mode=autonomous -> the ask collapsed to deny
    assert doc["rules"][0]["action"] == "deny"
