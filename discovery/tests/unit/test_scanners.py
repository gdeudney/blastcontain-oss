"""Discovery scanners — copilot, process, repo."""
from __future__ import annotations

import json
from pathlib import Path

from blastcontain_discovery.models import AssetClassification
from blastcontain_discovery.scanners import copilot, process, repo

# ── copilot (the side-of-desk scanner) ───────────────────────────────────────────


def _write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj), encoding="utf-8")


def test_copilot_finds_claude_desktop_and_extracts_mcp(tmp_path):
    _write(tmp_path / "AppData/Roaming/Claude/claude_desktop_config.json",
           {"mcpServers": {"github": {"command": "npx"}, "fs": {"command": "npx"}}})
    assets = copilot.scan(home=tmp_path)
    assert len(assets) == 1
    asset = assets[0]
    assert asset.asset_type == "copilot"
    assert asset.mcp_servers == ["fs", "github"]
    assert asset.tools_detected == ["fs", "github"]
    assert "Claude Desktop" in asset.candidate_ids
    assert asset.classification is AssetClassification.UNKNOWN_SHADOW_AI


def test_copilot_finds_multiple_copilots(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"db": {}}})
    _write(tmp_path / ".continue/config.json", {"models": []})
    assets = copilot.scan(home=tmp_path)
    types = {a.candidate_ids[0] for a in assets}
    assert "Cursor" in types
    assert "Continue" in types


def test_copilot_detects_ide_extensions(tmp_path):
    (tmp_path / ".vscode/extensions/github.copilot-1.2.3").mkdir(parents=True)
    (tmp_path / ".vscode/extensions/saoudrizwan.claude-dev-2.0.0").mkdir(parents=True)
    (tmp_path / ".vscode/extensions/ms-python.python-2024.1").mkdir(parents=True)
    assets = copilot.scan(home=tmp_path)
    labels = {a.risk_indicators[0] for a in assets}
    assert any("GitHub Copilot" in x for x in labels)
    assert any("Cline" in x for x in labels)
    assert not any("python" in x.lower() for x in labels)   # non-AI ext ignored


def test_copilot_finds_loose_mcp_configs_in_search_path(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    proj = tmp_path / "proj"
    _write(proj / ".mcp.json", {"mcpServers": {"weather": {}}})
    assets = copilot.scan(home=home, search_path=str(proj))
    assert len(assets) == 1
    assert assets[0].asset_type == "mcp_server"
    assert assets[0].mcp_servers == ["weather"]


def test_copilot_handles_malformed_json(tmp_path):
    bad = tmp_path / ".cursor/mcp.json"
    bad.parent.mkdir(parents=True)
    bad.write_text("{not valid json", encoding="utf-8")
    assets = copilot.scan(home=tmp_path)
    assert len(assets) == 1            # still reported as a copilot…
    assert assets[0].mcp_servers == []  # …just with no servers extracted


def test_copilot_empty_home(tmp_path):
    assert copilot.scan(home=tmp_path) == []


# ── process ──────────────────────────────────────────────────────────────────────


class _Proc:
    def __init__(self, pid, name, cmdline):
        self.info = {"pid": pid, "name": name, "cmdline": cmdline}


def test_process_matches_framework_signatures():
    procs = [
        _Proc(1, "python", ["python", "-m", "langchain.agents", "run"]),
        _Proc(2, "python", ["python", "app.py"]),           # no signature
        _Proc(3, "node", ["node", "crewai-server.js"]),
    ]
    assets = process.scan(process_iter=lambda: procs)
    ids = {a.asset_id for a in assets}
    assert ids == {"process-1", "process-3"}
    langchain = next(a for a in assets if a.asset_id == "process-1")
    assert "LangChain" in langchain.risk_indicators[0]
    assert langchain.candidate_ids == ["python"]


def test_process_empty_cmdline_skipped():
    assert process.scan(process_iter=lambda: [_Proc(1, "x", [])]) == []


def test_process_no_psutil_returns_empty(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_psutil(name, *a, **k):
        if name == "psutil":
            raise ImportError("no psutil")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_psutil)
    assert process.scan() == []


# ── repo ─────────────────────────────────────────────────────────────────────────


def test_repo_finds_model_files_and_agent_configs(tmp_path):
    (tmp_path / "weights.safetensors").write_bytes(b"x")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub/agent.yaml").write_text("name: bot", encoding="utf-8")
    (tmp_path / "readme.md").write_text("hi", encoding="utf-8")
    assets = repo.scan(search_path=str(tmp_path))
    types = {a.asset_type for a in assets}
    assert types == {"model_file", "agent_config"}


def test_repo_skips_heavy_dirs(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules/model.bin").write_bytes(b"x")
    assert repo.scan(search_path=str(tmp_path)) == []


def test_repo_missing_path():
    assert repo.scan(search_path="/no/such/path/xyz") == []
