"""blastcontain_discovery — data models."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class AssetClassification(str, Enum):
    REGISTERED = "REGISTERED"                 # in the registry, Charter valid
    KNOWN_UNVERIFIED = "KNOWN_UNVERIFIED"     # in the registry, but not Active/verified
    UNKNOWN_SHADOW_AI = "UNKNOWN_SHADOW_AI"   # not in the registry at all


@dataclass
class DiscoveredAsset:
    """One thing a scanner found. `candidate_ids` are the identities to match
    against the registry (an asset may be known by more than one name — a
    process pid, but also the framework, or a copilot's declared agent_id)."""

    asset_id: str
    asset_type: str                          # process | model_file | agent_config | copilot | mcp_server
    location: str                            # pid, file path, config path
    classification: AssetClassification = AssetClassification.UNKNOWN_SHADOW_AI
    tools_detected: list[str] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
    candidate_ids: list[str] = field(default_factory=list)
    draft_charter_ref: str | None = None  # path (local) or "agent_id@env" (platform)
    scanner: str | None = None

    def identities(self) -> list[str]:
        """asset_id plus any candidate ids — what the registry match tries."""
        seen: list[str] = []
        for ident in [self.asset_id, *self.candidate_ids]:
            if ident and ident not in seen:
                seen.append(ident)
        return seen

    def as_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "location": self.location,
            "classification": self.classification.value,
            "tools_detected": self.tools_detected,
            "mcp_servers": self.mcp_servers,
            "risk_indicators": self.risk_indicators,
            "candidate_ids": self.candidate_ids,
            "draft_charter_ref": self.draft_charter_ref,
            "scanner": self.scanner,
        }


@dataclass
class DiscoveryReport:
    environment: str
    discovery_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scanned_at: str = ""                      # ISO 8601, stamped by the orchestrator
    assets: list[DiscoveredAsset] = field(default_factory=list)
    generator: str = "blastcontain-discovery"
    generator_version: str = ""

    def _by(self, classification: AssetClassification) -> list[DiscoveredAsset]:
        return [a for a in self.assets if a.classification == classification]

    @property
    def shadow_ai(self) -> list[DiscoveredAsset]:
        return self._by(AssetClassification.UNKNOWN_SHADOW_AI)

    @property
    def known_unverified(self) -> list[DiscoveredAsset]:
        return self._by(AssetClassification.KNOWN_UNVERIFIED)

    @property
    def registered(self) -> list[DiscoveredAsset]:
        return self._by(AssetClassification.REGISTERED)

    def summary(self) -> dict:
        return {
            "total": len(self.assets),
            "registered": len(self.registered),
            "known_unverified": len(self.known_unverified),
            "shadow_ai": len(self.shadow_ai),
        }

    def as_packet(self) -> dict:
        """The signable payload (goes inside a {packet, signature} envelope)."""
        return {
            "discovery_id": self.discovery_id,
            "environment": self.environment,
            "scanned_at": self.scanned_at,
            "generator": self.generator,
            "generator_version": self.generator_version,
            "summary": self.summary(),
            "assets": [a.as_dict() for a in self.assets],
        }
