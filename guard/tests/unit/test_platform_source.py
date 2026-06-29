"""The Platform Charter source: fetch, verify signature, gate on lifecycle state."""
from __future__ import annotations

import os

import pytest

from blastcontain_core.signing import sign_packet

from blastcontain_guard import platform_source
from blastcontain_guard.errors import GuardError
from blastcontain_guard.evaluator import evaluate
from blastcontain_guard.guard import Guard
from blastcontain_guard.models import Action, EvalInput
from blastcontain_guard.platform_source import fetch_ruleset
from blastcontain_guard.policy import RuleAction

BASE = "https://platform.example"

COMPILED_POLICY = {
    "apiVersion": "governance.toolkit/v1",
    "name": "invoice-bot-prod",
    "agent_id": "invoice-bot",
    "environment": "prod",
    "autonomy_mode": "interactive",
    "default_action": "deny",
    "rules": [
        {
            "name": "allow-permitted-tools",
            "condition": "tool_name in ['query_invoice']",
            "action": "allow",
        },
    ],
}


@pytest.fixture
def signing_env(monkeypatch):
    """A real (non-default) HMAC key so signatures are non-advisory."""
    for key in list(os.environ):
        if key.startswith("BLASTCONTAIN_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("BLASTCONTAIN_SIGNING_KEY", "platform-test-key")
    return monkeypatch


def _packet(**overrides) -> dict:
    packet = {
        "agent_id": "invoice-bot",
        "environment": "prod",
        "version": "1.0.0",
        "trust_tier": 1,
        "permitted_tools": ["query_invoice"],
        "autonomy_mode": "interactive",
        "state": "active",
        "draft": False,
        "compiled_policy": COMPILED_POLICY,
    }
    packet.update(overrides)
    return packet


def _bundle(packet: dict) -> dict:
    return {
        "packet": packet,
        "signature": sign_packet(packet, signed_at="2026-06-11T00:00:00Z"),
    }


def _serve(monkeypatch, bundle: dict) -> None:
    monkeypatch.setattr(
        platform_source, "_fetch_json", lambda url, token, timeout: bundle
    )


def test_fetch_verifies_and_uses_embedded_policy(signing_env):
    _serve(signing_env, _bundle(_packet()))
    rs = fetch_ruleset("invoice-bot", "prod", base_url=BASE)
    assert rs.autonomy_mode == "interactive"
    assert rs.default_action is RuleAction.DENY
    assert rs.source == f"platform:{BASE}/invoice-bot@prod"
    assert evaluate(rs, EvalInput("query_invoice", action_type="read")).action is Action.ALLOW
    assert evaluate(rs, EvalInput("rm_rf", action_type="exec")).action is Action.DENY


def test_fetch_falls_back_to_local_compile(signing_env):
    _serve(signing_env, _bundle(_packet(compiled_policy=None)))
    rs = fetch_ruleset("invoice-bot", "prod", base_url=BASE)
    # The OSS bridge compiled the control layer: allowlist enforced, default deny.
    assert evaluate(rs, EvalInput("query_invoice", action_type="read")).action is Action.ALLOW
    assert evaluate(rs, EvalInput("unlisted", action_type="read")).action is Action.DENY


def test_tampered_packet_is_rejected(signing_env):
    bundle = _bundle(_packet())
    bundle["packet"]["permitted_tools"] = ["query_invoice", "drop_database"]
    _serve(signing_env, bundle)
    with pytest.raises(GuardError, match="verification FAILED"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)


def test_advisory_signature_rejected_by_default(signing_env):
    # The default dev key makes sign_packet mark the signature advisory.
    signing_env.delenv("BLASTCONTAIN_SIGNING_KEY", raising=False)
    _serve(signing_env, _bundle(_packet()))
    with pytest.raises(GuardError, match="advisory"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)


def test_advisory_signature_accepted_with_opt_in(signing_env):
    signing_env.delenv("BLASTCONTAIN_SIGNING_KEY", raising=False)
    _serve(signing_env, _bundle(_packet()))
    rs = fetch_ruleset("invoice-bot", "prod", base_url=BASE, allow_advisory=True)
    assert rs.agent_id == "invoice-bot"


def test_draft_charter_is_not_enforceable(signing_env):
    _serve(signing_env, _bundle(_packet(draft=True, state="draft")))
    with pytest.raises(GuardError, match="draft"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)


def test_paused_agent_enforces_deny_all(signing_env):
    _serve(signing_env, _bundle(_packet(state="paused")))
    rs = fetch_ruleset("invoice-bot", "prod", base_url=BASE)
    assert rs.rules == []
    assert rs.default_action is RuleAction.DENY
    # Even the previously permitted tool is denied while paused.
    assert evaluate(rs, EvalInput("query_invoice", action_type="read")).action is Action.DENY


def test_quarantined_agent_enforces_deny_all(signing_env):
    _serve(signing_env, _bundle(_packet(state="quarantined")))
    rs = fetch_ruleset("invoice-bot", "prod", base_url=BASE)
    assert rs.rules == [] and rs.default_action is RuleAction.DENY


def test_decommissioned_agent_is_an_error(signing_env):
    _serve(signing_env, _bundle(_packet(state="decommissioned")))
    with pytest.raises(GuardError, match="decommissioned"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)


def test_identity_mismatch_is_rejected(signing_env):
    _serve(signing_env, _bundle(_packet(agent_id="other-bot")))
    with pytest.raises(GuardError, match="identity mismatch"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)


def test_unsigned_bundle_is_rejected(signing_env):
    _serve(signing_env, {"packet": _packet()})
    with pytest.raises(GuardError, match="signed Charter bundle"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)


def test_no_platform_configured_gives_guidance(signing_env):
    signing_env.delenv("BLASTCONTAIN_URL", raising=False)
    with pytest.raises(GuardError, match="Guard.from_yaml"):
        fetch_ruleset("invoice-bot", "prod")


def test_base_url_falls_back_to_env(signing_env):
    seen: dict = {}

    def fake(url, token, timeout):
        seen["url"] = url
        return _bundle(_packet())

    signing_env.setenv("BLASTCONTAIN_URL", BASE)
    signing_env.setattr(platform_source, "_fetch_json", fake)
    fetch_ruleset("invoice-bot", "prod")
    assert seen["url"] == f"{BASE}/v1/charters/invoice-bot?env=prod"


def test_guard_from_charter_end_to_end(signing_env):
    _serve(signing_env, _bundle(_packet()))
    guard = Guard.from_charter("invoice-bot", env="prod", base_url=BASE)
    assert guard.autonomy_mode == "interactive"
    assert guard.agent_id == "invoice-bot"
    assert guard.evaluate(EvalInput("query_invoice", action_type="read")).action is Action.ALLOW
    assert guard.evaluate(EvalInput("drop_database", action_type="delete")).action is Action.DENY


def test_http_404_maps_to_guard_error(signing_env):
    class FakeResponse:
        status_code = 404

    class FakeHttpx:
        class HTTPError(Exception):
            pass

        @staticmethod
        def get(url, headers=None, timeout=None):
            return FakeResponse()

    import sys

    signing_env.setitem(sys.modules, "httpx", FakeHttpx)
    with pytest.raises(GuardError, match="no Charter"):
        fetch_ruleset("invoice-bot", "prod", base_url=BASE)
