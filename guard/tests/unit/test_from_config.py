"""Config-driven modes: the same code runs guard-only / dual / sole by config."""
from blastcontain_guard import Guard
from blastcontain_guard.backends import AgtBackend, combine_with_agt
from blastcontain_guard.backends.agt import decision_from_agt_response
from blastcontain_guard.config import load_config
from blastcontain_guard.models import Action, Decision, EvalInput
from blastcontain_guard.policy import parse_ruleset

POLICY = """\
apiVersion: governance.toolkit/v1
name: t
default_action: deny
rules:
  - name: allow-read
    condition: "action.type == 'read'"
    action: allow
  - name: deny-send
    condition: "action.type == 'send'"
    action: deny
"""


def _config(tmp_path, agt_block=""):
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY, encoding="utf-8")
    cfg = tmp_path / "guard.yaml"
    body = f"agent_id: a\npolicy: {str(policy).replace(chr(92), '/')}\n{agt_block}"
    cfg.write_text(body, encoding="utf-8")
    return str(cfg)


class TestConfigParsing:
    def test_nested_agt_block(self, tmp_path):
        path = _config(tmp_path, "agt:\n  enabled: true\n  mode: sole\n  endpoint: http://h/eval\n")
        cfg = load_config(config_file=path)
        assert cfg.agt_enabled is True
        assert cfg.agt_mode == "sole"
        assert cfg.agt_endpoint == "http://h/eval"

    def test_guard_only_has_no_agt(self, tmp_path):
        cfg = load_config(config_file=_config(tmp_path))
        assert cfg.agt_enabled is False


class TestFromConfig:
    def test_guard_only_mode(self, tmp_path):
        guard = Guard.from_config(_config(tmp_path))
        assert guard.agt is None
        assert "guard-only" in guard.describe_mode()
        assert guard.check("read_thing", action_type="read").allowed
        assert not guard.check("send_thing", action_type="send").allowed

    def test_dual_mode(self, tmp_path):
        path = _config(tmp_path, "agt:\n  enabled: true\n  mode: dual\n  endpoint: http://127.0.0.1:9/e\n")
        guard = Guard.from_config(path)
        assert guard.agt is not None and guard.agt.sole is False
        assert "dual" in guard.describe_mode()

    def test_sole_mode(self, tmp_path):
        path = _config(tmp_path, "agt:\n  enabled: true\n  mode: sole\n  endpoint: http://127.0.0.1:9/e\n")
        guard = Guard.from_config(path)
        assert guard.agt is not None and guard.agt.sole is True
        assert "sole" in guard.describe_mode()


class TestAgtResponseMapping:
    def test_action_mapping(self):
        assert decision_from_agt_response({"action": "allow"}).action is Action.ALLOW
        assert decision_from_agt_response({"action": "deny"}).action is Action.DENY
        assert decision_from_agt_response({"action": "require_approval"}).action is Action.ASK
        assert decision_from_agt_response({}).action is Action.DENY   # default-deny


class TestSoleBackend:
    def test_sole_agt_is_the_only_decider(self):
        # In sole mode AGT can even LOOSEN relative to native (native is ignored).
        native = Decision(Action.DENY, "native would deny")
        agt = AgtBackend(
            enabled=True, reachable=True, sole=True,
            evaluator_fn=lambda r, i: Decision(Action.ALLOW, "AGT allows"),
        )
        decision, degraded = combine_with_agt(
            native, parse_ruleset({"default_action": "deny"}), EvalInput("t", action_type="send"), agt
        )
        assert decision.action is Action.ALLOW
        assert not degraded

    def test_sole_unavailable_still_fails_closed(self):
        native = Decision(Action.ALLOW, "native allows")
        agt = AgtBackend(enabled=True, reachable=False, sole=True)  # no endpoint/fn -> unavailable
        decision, degraded = combine_with_agt(
            native, parse_ruleset({"default_action": "allow"}), EvalInput("t"), agt
        )
        assert decision.action is Action.DENY
        assert degraded
