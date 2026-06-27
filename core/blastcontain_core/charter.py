"""
blastcontain_core.charter — Charter schema (the agent policy contract).

The Charter is the signed declaration of what an agent may do:
  - permitted_tools     (MCP tool allowlist; gates MCP-01)
  - permitted_apis      (API endpoint allowlist; gates API-01)
  - environment_constraints (must-have runtime properties)
  - delegation_rules    (whether sub-agents are permitted, at what tiers)
  - hitl_config         (which actions require human approval)
  - remediation_proofs  (signed evidence that prior findings are fixed)
  - transparency_label  (EU AI Act Art. 15 consumer-facing label)

This module defines the schema only. Storage, versioning, approval
workflows, and signed-Charter attestation live in the closed-source
BlastContain Platform.

OSS users can write a local `charter.yaml` and pass it via
`--charter charter.yaml` to any BlastContain tool that supports it
(verify uses `permitted_tools` to gate MCP-01).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EnvironmentConstraints:
    """Runtime properties the Charter requires of the deployment."""
    read_only_rootfs: bool = True
    egress_blocked: bool = True
    max_trust_tier: int = 1
    verify_required: bool = True


@dataclass
class DelegationRules:
    """Controls how this agent may delegate authority to sub-agents."""
    max_chain_depth: int = 0                # 0 = no delegation permitted
    allowed_tiers: list[int] = field(default_factory=list)
    require_parent_approval: bool = True    # sub-agent Charter must reference this one


@dataclass
class HitlConfig:
    """Human-in-the-loop requirements for this agent."""
    required_for: list[str] = field(default_factory=list)
    # e.g. ["destructive_apis", "tier_3_delegation", "ENV-01_finding"]
    timeout_sec: int = 300                  # max wait before auto-reject
    escalation_contact: Optional[str] = None  # email or Slack channel


@dataclass
class RemediationProof:
    """Evidence that a specific finding has been remediated."""
    finding_type: str                       # e.g. "blastcontain.env.kernel_isolation_missing"
    evidence_uri: str                       # link to artifact (PR, ticket, scan result)
    verified_by: Optional[str] = None       # DID or identity of verifier
    verified_at: Optional[str] = None       # ISO 8601


@dataclass
class CharterSchema:
    """The full Charter document — signed, stored, and enforced."""
    agent_id: str
    environment: str                        # (agent_id, environment) is unique
    version: str
    trust_tier: int
    signed_at: Optional[str] = None
    signed_by: Optional[str] = None         # DID or key ID of signer
    signing_key_id: Optional[str] = None    # identifies which key produced the signature
    permitted_tools: list[str] = field(default_factory=list)
    permitted_apis: list[dict] = field(default_factory=list)
    mcp_servers: list[dict] = field(default_factory=list)
    environment_constraints: EnvironmentConstraints = field(
        default_factory=EnvironmentConstraints
    )
    delegation_rules: DelegationRules = field(default_factory=DelegationRules)
    hitl_config: HitlConfig = field(default_factory=HitlConfig)
    remediation_proofs: list[RemediationProof] = field(default_factory=list)
    transparency_label: Optional[str] = None  # EU AI Act Art. 15
    draft: bool = False


_CHARTER_FIELDS = frozenset(CharterSchema.__dataclass_fields__)


def charter_from_mapping(raw: dict, strict: bool = True) -> CharterSchema:
    """
    Build a CharterSchema from a parsed mapping.

    With ``strict=True`` (the hand-authored-YAML path) unknown keys raise
    ValueError — a typo in a local charter.yaml should fail loudly, not
    silently drop a control. With ``strict=False`` unknown keys are ignored:
    a Platform-issued Charter packet carries Intent-layer and lifecycle
    fields (``autonomy_mode``, ``objectives``, ``state``, ``compiled_policy``,
    …) this control-layer schema doesn't model, and older clients must keep
    verifying newer packets.
    """
    if not isinstance(raw, dict):
        raise ValueError("Charter document is not a mapping")

    unknown = set(raw) - _CHARTER_FIELDS
    if unknown and strict:
        raise ValueError(f"Charter contains unknown fields: {sorted(unknown)}")

    data = {k: v for k, v in raw.items() if k in _CHARTER_FIELDS}

    # Nested dataclass fields need explicit construction
    if isinstance(data.get("environment_constraints"), dict):
        data["environment_constraints"] = EnvironmentConstraints(**data["environment_constraints"])
    if isinstance(data.get("delegation_rules"), dict):
        data["delegation_rules"] = DelegationRules(**data["delegation_rules"])
    if isinstance(data.get("hitl_config"), dict):
        data["hitl_config"] = HitlConfig(**data["hitl_config"])
    if isinstance(data.get("remediation_proofs"), list):
        data["remediation_proofs"] = [
            RemediationProof(**p) if isinstance(p, dict) else p
            for p in data["remediation_proofs"]
        ]

    try:
        return CharterSchema(**data)
    except TypeError as exc:
        raise ValueError(f"Charter document is not a valid CharterSchema: {exc}") from exc


def load_charter(path: str) -> CharterSchema:
    """
    Load a Charter from a YAML file. Raises FileNotFoundError if missing,
    ValueError if the file does not contain a parseable Charter.
    """
    import yaml  # type: ignore
    from pathlib import Path

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"Charter at {path} is not a mapping")
    return charter_from_mapping(raw, strict=True)
