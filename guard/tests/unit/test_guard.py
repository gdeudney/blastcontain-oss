"""The Guard facade: check, @tool, the ask round-trip, learning, signed log."""
import pytest
from blastcontain_core.signing import verify_packet

from blastcontain_guard import Guard, GuardDenied
from blastcontain_guard.models import AskChoice, AskResult

ALLOW_ALL = {"default_action": "allow", "rules": []}
DENY_ALL = {"default_action": "deny", "rules": []}
ASK_SEND = {
    "default_action": "deny",
    "rules": [{"name": "ask-send", "condition": "action.type == 'send'",
               "action": "require_approval", "approvers": ["self"], "concern": "no-pii-egress"}],
}


def test_check_allow_and_deny():
    g = Guard.from_dict(ALLOW_ALL, agent_id="a")
    allowed = g.check("anything")
    assert allowed.allowed and not allowed.denied

    g2 = Guard.from_dict(DENY_ALL, agent_id="a")
    blocked = g2.check("anything")
    assert blocked.denied and not blocked.allowed


def test_decorator_allows_and_denies():
    g = Guard.from_dict(ALLOW_ALL)

    @g.tool
    def add(x, y):
        return x + y

    assert add(2, 3) == 5

    g2 = Guard.from_dict(DENY_ALL)

    @g2.tool
    def danger():
        return "ran"

    with pytest.raises(GuardDenied):
        danger()


def test_decorator_action_type_override_drives_rule():
    rs = {"default_action": "allow",
          "rules": [{"name": "no-del", "condition": "action.type == 'delete'", "action": "deny"}]}
    g = Guard.from_dict(rs)

    @g.tool(action_type="delete")
    def wipe():
        return "gone"

    with pytest.raises(GuardDenied):
        wipe()


def test_ask_allow_always_emits_learning_proposal():
    g = Guard.from_dict(ASK_SEND, agent_id="a", on_ask=lambda req: AskChoice.ALLOW_ALWAYS)
    result = g.check("send_mail", action_type="send")
    assert result.allowed
    assert result.learning is not None
    assert g.learning_proposals[0].tool_name == "send_mail"
    # both a decision event and a learning event were emitted
    types = {e["type"] for e in g.decisions}
    assert "com.blastcontain.guard.decision" in types
    assert "com.blastcontain.guard.learning_proposal" in types


def test_ask_deny_blocks():
    g = Guard.from_dict(ASK_SEND, agent_id="a", on_ask=lambda req: AskResult(AskChoice.DENY))
    assert not g.check("send_mail", action_type="send").allowed


def test_explain_is_pure_no_telemetry():
    g = Guard.from_dict(ASK_SEND, agent_id="a")
    d = g.explain("send_mail", action_type="send")
    assert d.action.value == "ask"
    assert g.decisions == []   # explain must not emit


def test_decision_event_records_risk_tag():
    g = Guard.from_dict(ASK_SEND, agent_id="a", on_ask=lambda req: "deny")
    g.check("send_mail", action_type="send")
    event = g.decisions[-1]
    assert event["data"]["risk_tag"] is not None
    assert event["data"]["concern"] == "no-pii-egress"


def test_signed_decision_log(tmp_path):
    g = Guard.from_dict(ALLOW_ALL, agent_id="a", environment="prod")
    g.check("t1")
    g.check("t2")
    packet = g.write_decision_log(str(tmp_path / "log.json"))
    assert verify_packet(packet)
    assert packet["packet"]["summary"]["total"] == 2
    assert packet["packet"]["agent_id"] == "a"


def test_context_manager_closes():
    with Guard.from_dict(ALLOW_ALL, agent_id="a") as g:
        g.check("t")
    assert g.decisions  # buffered before close
