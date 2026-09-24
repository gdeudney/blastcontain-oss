"""The human-alert webhook sink + its four ingest triggers."""
from __future__ import annotations

import httpx

import blastcontain.ledger.notify as notify_mod
from blastcontain.ledger.notify import Notifier


class _Resp:
    def __init__(self, status_code=200):
        self.status_code = status_code


def _capture(monkeypatch):
    """Patch the real httpx.post to capture payloads (leaves the module intact
    so Starlette's TestClient still works). Returns the captured list."""
    posted = []

    def fake_post(url, json=None, timeout=None):
        posted.append({"url": url, "json": json})
        return _Resp(200)

    monkeypatch.setattr(httpx, "post", fake_post)
    return posted


# ── the Notifier unit ────────────────────────────────────────────────────────────


def test_notifier_no_op_when_unconfigured():
    n = Notifier(webhook_url=None)
    assert n.enabled is False
    assert n.notify(notify_mod.QUARANTINE, "bot", "prod", "x", "2026-07-06T00:00:00Z") is False


def test_notifier_posts_when_configured(monkeypatch):
    posted = _capture(monkeypatch)
    n = Notifier(webhook_url="https://hooks.example/x")
    ok = n.notify(notify_mod.QUARANTINE, "bot", "prod", "Agent bot quarantined",
                  "2026-07-06T00:00:00Z", finding_type="env.x")
    assert ok is True and n.sent == 1
    body = posted[0]["json"]
    assert body["event"] == "quarantine"
    assert body["severity"] == "critical"
    assert body["agent_id"] == "bot"
    assert body["finding_type"] == "env.x"


def test_notifier_swallows_failures(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(httpx, "post", boom)
    n = Notifier(webhook_url="https://x")
    assert n.notify(notify_mod.TOMBSTONE, "bot", "prod", "x", "t") is False
    assert n.dropped == 1        # counted, not raised


def test_notifier_4xx_is_a_drop(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(404))
    n = Notifier(webhook_url="https://x")
    assert n.notify(notify_mod.CRITICAL_FINDING, "bot", "prod", "x", "t") is False
    assert n.dropped == 1


# ── wired into the app ───────────────────────────────────────────────────────────

CRITICAL_PACKET = {
    "environment": "prod",
    "status": "REJECTED",
    "summary": {"critical": 1},
    "findings": [{
        "finding_type": "blastcontain.env.model_weights_writable",
        "severity": "CRITICAL", "title": "Writable weights",
    }],
}


def _charter():
    return {
        "agent_id": "invoice-bot", "environment": "prod", "version": "1.0.0",
        "trust_tier": 1, "permitted_tools": ["query_invoice"],
        "autonomy_mode": "interactive", "base_strictness": "balanced",
        "objectives": [{"id": "no-pii-egress"}],
        "environment_constraints": {"read_only_rootfs": True, "egress_blocked": False,
                                    "max_trust_tier": 1, "verify_required": True},
        "owner": "alice@example.com",
    }


def _sign(client):
    assert client.post("/v1/charters", json=_charter()).status_code == 201
    r = client.post("/v1/charters/invoice-bot/sign?env=prod", json={"actor": "alice@example.com"})
    assert r.status_code == 200, r.text


def test_critical_and_quarantine_both_alert(app, client, monkeypatch):
    posted = _capture(monkeypatch)
    app.state.notifier.webhook_url = "https://hooks.example/x"
    _sign(client)
    resp = client.post("/v1/agents/invoice-bot/findings", json=CRITICAL_PACKET)
    assert resp.json()["quarantined"] is True
    events = [p["json"]["event"] for p in posted]
    assert "critical_finding" in events
    assert "quarantine" in events


def test_shadow_discovery_alerts(app, client, monkeypatch):
    posted = _capture(monkeypatch)
    app.state.notifier.webhook_url = "https://hooks.example/x"
    report = {
        "environment": "prod",
        "assets": [
            {"asset_id": "copilot-cursor", "asset_type": "copilot",
             "location": "/home/.cursor/mcp.json", "classification": "UNKNOWN_SHADOW_AI"},
            {"asset_id": "known", "asset_type": "process",
             "location": "pid:9", "classification": "REGISTERED"},
        ],
    }
    client.post("/v1/agents/discovery-scan/findings", json=report)
    shadow_alerts = [p["json"] for p in posted if p["json"]["event"] == "shadow_discovered"]
    assert len(shadow_alerts) == 1
    assert shadow_alerts[0]["agent_id"] == "copilot-cursor"


def test_tombstone_alerts(app, client, monkeypatch):
    posted = _capture(monkeypatch)
    app.state.notifier.webhook_url = "https://hooks.example/x"
    _sign(client)
    client.post("/v1/agents/invoice-bot/decommission?env=prod", json={"actor": "alice"})
    client.post("/v1/agents/invoice-bot/decisions", json={
        "data": {"agent_id": "invoice-bot", "environment": "prod", "tool": "query",
                 "decision": "allow", "final": "allow"}})
    assert any(p["json"]["event"] == "tombstone_traffic" for p in posted)


def test_no_alerts_when_webhook_unset(app, client, monkeypatch):
    posted = _capture(monkeypatch)
    # default notifier has no URL (BLASTCONTAIN_WEBHOOK_URL stripped by signing_env)
    _sign(client)
    client.post("/v1/agents/invoice-bot/findings", json=CRITICAL_PACKET)
    assert posted == []
