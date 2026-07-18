"""
Discovery scanner: side-of-desk copilots + their MCP servers.

This is the scanner that matters for the interactive/copilot thesis: the
assistants that live in IDEs and desktop apps don't show up as network
services or long-running framework processes — they leave **config files**.
A pure filesystem scan (no browser automation, no process hooks) finds them
and, crucially, reads the MCP servers each copilot is wired to — which is
exactly the tool surface a Charter needs to govern.

Two fingerprints:
  1. **Known copilot configs** — Claude Desktop / Claude Code / Cursor /
     Continue / Windsurf / Zed / VS Code, at their platform-standard paths.
     Each config is parsed for an ``mcpServers`` block.
  2. **Loose MCP configs** — ``.mcp.json`` / ``mcp.json`` / ``mcp-config.json``
     anywhere under the search path (a project-local MCP wiring).

Everything is injectable (``home``, ``search_path``) so tests point it at a
temp dir instead of the real machine.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import AssetClassification, DiscoveredAsset

# copilot -> config paths relative to the user's home dir (cross-platform; we
# probe all candidates and report whichever exist).
_COPILOT_CONFIGS: dict[str, tuple[str, ...]] = {
    "Claude Desktop": (
        "AppData/Roaming/Claude/claude_desktop_config.json",                 # Windows
        "Library/Application Support/Claude/claude_desktop_config.json",      # macOS
        ".config/Claude/claude_desktop_config.json",                         # Linux
    ),
    "Claude Code": (".claude.json", ".claude/settings.json", ".claude/mcp.json"),
    "Cursor": (".cursor/mcp.json",),
    "Continue": (".continue/config.json",),
    "Windsurf": (".codeium/windsurf/mcp_config.json",),
    "Zed": (".config/zed/settings.json",),
    "VS Code (user MCP)": (
        "AppData/Roaming/Code/User/mcp.json",
        "Library/Application Support/Code/User/mcp.json",
        ".config/Code/User/mcp.json",
    ),
}

# VS Code / IDE AI-assistant extensions, matched as a substring of the
# extension folder name (publisher.name-version).
_AI_EXTENSION_MARKERS: dict[str, str] = {
    "github.copilot": "GitHub Copilot",
    "continue.continue": "Continue",
    "saoudrizwan.claude-dev": "Cline",
    "rooveterinaryinc.roo-cline": "Roo Code",
    "codeium.codeium": "Codeium",
    "sourcegraph.cody": "Sourcegraph Cody",
    "tabnine.tabnine": "Tabnine",
    "anthropic.": "Anthropic (VS Code)",
    "supermaven.supermaven": "Supermaven",
}

_LOOSE_MCP_NAMES = frozenset({".mcp.json", "mcp.json", "mcp-config.json", "mcp_config.json"})
_EXTENSION_DIRS = (".vscode/extensions", ".vscode-server/extensions", ".cursor/extensions")


def _extract_mcp_servers(data: object) -> list[str]:
    """Pull MCP server names from a parsed config (mcpServers or servers map)."""
    if not isinstance(data, dict):
        return []
    block = data.get("mcpServers")
    if not isinstance(block, dict):
        block = data.get("servers") if isinstance(data.get("servers"), dict) else None
    if not isinstance(block, dict):
        return []
    return sorted(str(name) for name in block)


def _read_json(path: Path) -> object | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _copilot_asset(name: str, path: Path) -> DiscoveredAsset:
    servers = _extract_mcp_servers(_read_json(path)) if path.suffix == ".json" else []
    risk = [f"{name} copilot config present"]
    if servers:
        risk.append(f"{len(servers)} MCP server(s) wired: {', '.join(servers)}")
    return DiscoveredAsset(
        asset_id=f"copilot-{name.lower().replace(' ', '-').replace('(', '').replace(')', '')}",
        asset_type="copilot",
        location=str(path),
        classification=AssetClassification.UNKNOWN_SHADOW_AI,
        tools_detected=servers,
        mcp_servers=servers,
        risk_indicators=risk,
        candidate_ids=[name],
        scanner="copilot",
    )


def scan(home: Path | None = None, search_path: str | None = None) -> list[DiscoveredAsset]:
    """Find side-of-desk copilots and MCP wirings.

    `home` defaults to the real user home; `search_path` (if given) is also
    walked for loose MCP config files.
    """
    home = Path(home) if home is not None else Path.home()
    assets: list[DiscoveredAsset] = []
    seen_locations: set[str] = set()

    # 1. Known copilot config files.
    for name, candidates in _COPILOT_CONFIGS.items():
        for rel in candidates:
            path = home / rel
            if path.is_file() and str(path) not in seen_locations:
                seen_locations.add(str(path))
                assets.append(_copilot_asset(name, path))

    # 2. Installed AI extensions.
    for ext_root_rel in _EXTENSION_DIRS:
        ext_root = home / ext_root_rel
        if not ext_root.is_dir():
            continue
        for child in sorted(ext_root.iterdir()):
            if not child.is_dir():
                continue
            folder = child.name.lower()
            for marker, label in _AI_EXTENSION_MARKERS.items():
                if folder.startswith(marker):
                    if str(child) in seen_locations:
                        break
                    seen_locations.add(str(child))
                    assets.append(DiscoveredAsset(
                        asset_id=f"copilot-ext-{marker.strip('.').replace('.', '-')}",
                        asset_type="copilot",
                        location=str(child),
                        classification=AssetClassification.UNKNOWN_SHADOW_AI,
                        risk_indicators=[f"{label} IDE extension installed"],
                        candidate_ids=[label],
                        scanner="copilot",
                    ))
                    break

    # 3. Loose MCP config files under the search path.
    if search_path:
        import os

        for root, dirs, files in os.walk(search_path):
            dirs[:] = [d for d in dirs if d not in {".git", "node_modules", ".venv"}]
            for filename in files:
                if filename.lower() in _LOOSE_MCP_NAMES:
                    path = Path(root) / filename
                    if str(path) in seen_locations:
                        continue
                    seen_locations.add(str(path))
                    servers = _extract_mcp_servers(_read_json(path))
                    assets.append(DiscoveredAsset(
                        asset_id=f"mcp-config-{path.name}-{Path(root).name}",
                        asset_type="mcp_server",
                        location=str(path),
                        classification=AssetClassification.UNKNOWN_SHADOW_AI,
                        tools_detected=servers,
                        mcp_servers=servers,
                        risk_indicators=[f"MCP config with {len(servers)} server(s)"]
                        if servers else ["MCP config file"],
                        scanner="copilot",
                    ))

    return assets
