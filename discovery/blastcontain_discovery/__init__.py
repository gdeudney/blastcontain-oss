"""
blastcontain-discovery — find the agents you didn't register (shadow AI).

The inventory front of BlastContain: enumerate agents, copilots, MCP servers,
and model artifacts on a host, cross-reference them against the platform
registry, and classify each as registered / known-unverified / shadow. For
shadow finds it can bootstrap a draft Charter (derive-then-ratify) and emit a
signed Discovery report in the same Audit-Packet envelope Verify and Drill use.

Scope is **interactive / side-of-desk**: the copilots that live in IDEs,
desktop apps, and MCP configs — not network-range host scanning.

    from blastcontain_discovery import run_discovery
    report = run_discovery(environment="prod", blastcontain_url="https://...")
    print(report.summary())
"""
from __future__ import annotations

__version__ = "0.1.0"

from .models import AssetClassification, DiscoveredAsset, DiscoveryReport
from .scanner import run_discovery

__all__ = [
    "AssetClassification",
    "DiscoveredAsset",
    "DiscoveryReport",
    "run_discovery",
]
