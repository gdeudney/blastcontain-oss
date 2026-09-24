"""Registry cross-reference + Charter bootstrap (with mocked HTTP)."""
from __future__ import annotations

import sys
import types
from pathlib import Path

from blastcontain_discovery.models import AssetClassification, DiscoveredAsset
from blastcontain_discovery.scanners import bootstrap, registry


def _asset(asset_id="copilot-x", candidate_ids=None, tools=None, mcp=None):
    return DiscoveredAsset(
        asset_id=asset_id,
        asset_type="copilot",
        location="/x",
        candidate_ids=candidate_ids or [],
        tools_detected=tools or [],
        mcp_servers=mcp or [],
        scanner="copilot",
    )


def _fake_httpx(monkeypatch, *, get=None, post=None):
    mod = types.ModuleType("httpx")
    if get is not None:
        mod.get = get
    if post is not None:
        mod.post = post
    monkeypatch.setitem(sys.modules, "httpx", mod)


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


# ── registry classification ──────────────────────────────────────────────────────


def test_registry_matches_by_candidate_id_and_state(monkeypatch):
    payload = {"agents": [
        {"agent_id": "invoice-bot", "state": "active"},
        {"agent_id": "old-bot", "state": "quarantined"},
    ]}
    _fake_httpx(monkeypatch, get=lambda *a, **k: _Resp(200, payload))

    active = _asset("proc-1", candidate_ids=["invoice-bot"])
    stale = _asset("proc-2", candidate_ids=["old-bot"])
    unknown = _asset("proc-3", candidate_ids=["ghost"])

    out = registry.classify_against_registry(
        [active, stale, unknown], "https://platform", "prod")

    assert out[0].classification is AssetClassification.REGISTERED
    assert out[1].classification is AssetClassification.KNOWN_UNVERIFIED
    assert any("state=quarantined" in r for r in out[1].risk_indicators)
    assert out[2].classification is AssetClassification.UNKNOWN_SHADOW_AI


def test_registry_unreachable_leaves_assets_shadow(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("connection refused")

    _fake_httpx(monkeypatch, get=boom)
    out = registry.classify_against_registry([_asset()], "https://x", "prod")
    assert out[0].classification is AssetClassification.UNKNOWN_SHADOW_AI


def test_registry_no_url_is_noop():
    a = _asset()
    assert registry.classify_against_registry([a], "", "prod")[0] is a


# ── bootstrap ────────────────────────────────────────────────────────────────────


def test_bootstrap_local_writes_tight_draft(tmp_path):
    import yaml

    asset = _asset(tools=["query_db"], mcp=["github"])
    path = bootstrap.bootstrap_local(asset, output_dir=str(tmp_path), environment="dev")
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    assert doc["draft"] is True
    assert doc["trust_tier"] == 0                       # tight, not the legacy tier-3
    assert doc["permitted_tools"] == ["query_db"]
    assert doc["environment_constraints"]["egress_blocked"] is True


def test_bootstrap_local_is_loadable_by_core(tmp_path):
    # The draft must round-trip through the core Charter loader (lenient of the
    # _discovery sidecar key).
    import yaml
    from blastcontain_core.charter import charter_from_mapping

    path = bootstrap.bootstrap_local(_asset(tools=["t"]), output_dir=str(tmp_path))
    doc = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    charter = charter_from_mapping(doc, strict=False)
    assert charter.trust_tier == 0
    assert charter.permitted_tools == ["t"]


def test_bootstrap_platform_posts_derive(monkeypatch):
    seen = {}

    def fake_post(url, **kwargs):
        seen["url"] = url
        seen["params"] = kwargs.get("params")
        return _Resp(201)

    _fake_httpx(monkeypatch, post=fake_post)
    ref = bootstrap.bootstrap_platform(
        _asset("invoice-bot", tools=["t"]), "https://platform", environment="prod")
    assert ref == "invoice-bot@prod"
    assert seen["url"].endswith("/v1/charters/invoice-bot/derive")
    assert seen["params"] == {"env": "prod"}


def test_bootstrap_platform_failure_returns_none(monkeypatch):
    _fake_httpx(monkeypatch, post=lambda *a, **k: _Resp(500))
    assert bootstrap.bootstrap_platform(_asset(), "https://x") is None
