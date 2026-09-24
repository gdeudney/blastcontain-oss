"""
Discovery scanner: running-process enumeration.

Finds live processes whose command line carries a known agent-framework
signature. psutil is used-if-present (availability-flag pattern) — without it
the scan returns nothing rather than failing.
"""
from __future__ import annotations

from ..models import AssetClassification, DiscoveredAsset

# command-line substring -> human framework name
_FRAMEWORK_SIGNATURES: dict[str, str] = {
    "langchain": "LangChain",
    "langgraph": "LangGraph",
    "autogen": "AutoGen",
    "crewai": "CrewAI",
    "semantic_kernel": "Semantic Kernel",
    "llama_index": "LlamaIndex",
    "llamaindex": "LlamaIndex",
    "haystack": "Haystack",
    "dspy": "DSPy",
    "pydantic_ai": "Pydantic AI",
    "smolagents": "smolagents",
    "openai_agents": "OpenAI Agents SDK",
    "claude_agent_sdk": "Claude Agent SDK",
    "mcp.server": "MCP server",
}


def scan(process_iter=None) -> list[DiscoveredAsset]:
    """Enumerate processes for agent-framework signatures.

    `process_iter` is injectable for testing — an iterable of objects exposing
    ``.info`` (dict with pid/name/cmdline). Defaults to ``psutil.process_iter``.
    """
    if process_iter is None:
        try:
            import psutil
        except ImportError:
            return []
        process_iter = lambda: psutil.process_iter(["pid", "name", "cmdline"])  # noqa: E731
        no_such = _psutil_errors()
    else:
        no_such = ()

    assets: list[DiscoveredAsset] = []
    for proc in process_iter():
        try:
            info = proc.info
            cmdline = " ".join(info.get("cmdline") or []).lower()
            if not cmdline:
                continue
            for sig, framework in _FRAMEWORK_SIGNATURES.items():
                if sig in cmdline:
                    pid = info.get("pid")
                    name = info.get("name") or f"process-{pid}"
                    assets.append(DiscoveredAsset(
                        asset_id=f"process-{pid}",
                        asset_type="process",
                        location=f"pid:{pid}",
                        classification=AssetClassification.UNKNOWN_SHADOW_AI,
                        risk_indicators=[f"agent framework signature: {framework}"],
                        candidate_ids=[str(name)],
                        scanner="process",
                    ))
                    break
        except no_such:
            continue
    return assets


def _psutil_errors() -> tuple:
    try:
        import psutil

        return (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess)
    except ImportError:  # pragma: no cover
        return ()
