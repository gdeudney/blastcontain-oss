"""
Charter schema — the Intent layer over the core Control layer (charter-spec §5).

The Control layer (``CharterSchema`` and friends) is owned by the OSS
``blastcontain-core`` package — it is the contract Verify reads and Guard
enforces, so the platform imports it rather than redefining it. This module
adds what only the platform stores:

  - the **Intent layer** (§5.2): ``autonomy_mode``, ``base_strictness``, and
    the human's selected ``objectives`` — the source of truth for authoring,
    diffing, and recertification;
  - the **lifecycle envelope** (§7): state, owner, provenance;
  - the **Standard** and **Exception** entities (§5.3).
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from blastcontain_core.charter import (  # noqa: F401  (re-exported: the platform's control layer IS core's)
    CharterSchema,
    DelegationRules,
    EnvironmentConstraints,
    HitlConfig,
    RemediationProof,
    charter_from_mapping,
)

AUTONOMY_MODES = ("interactive", "autonomous")
STRICTNESS_LEVELS = ("locked", "balanced", "permissive")
# mandatory/recommended/optional are inherited Standard levels (§3.1);
# "self" marks an owner-selected objective (§3.7 — its asks resolve to [self]).
ENFORCEMENT_LEVELS = ("mandatory", "recommended", "optional", "self")

LIFECYCLE_STATES = (
    "discovered", "draft", "active", "paused",
    "quarantined", "decommissioned", "archived",
)


@dataclass
class Objective:
    """A selected plain-language concern (catalog id) with its provenance."""

    id: str
    params: dict = field(default_factory=dict)
    enforcement_level: str = "self"
    inherited_from: str | None = None          # Standard id, when inherited
    compiled_refs: list[str] = field(default_factory=list)  # rule names (compiler fills)

    def to_dict(self) -> dict:
        out: dict = {"id": self.id, "enforcement_level": self.enforcement_level}
        if self.params:
            out["params"] = dict(self.params)
        if self.inherited_from:
            out["inherited_from"] = self.inherited_from
        if self.compiled_refs:
            out["compiled_refs"] = list(self.compiled_refs)
        return out

    @classmethod
    def from_dict(cls, raw: dict) -> Objective:
        if not isinstance(raw, dict) or not raw.get("id"):
            raise ValueError(f"objective must be a mapping with an 'id': {raw!r}")
        level = raw.get("enforcement_level", "self")
        if level not in ENFORCEMENT_LEVELS:
            raise ValueError(f"objective {raw['id']}: unknown enforcement_level {level!r}")
        return cls(
            id=str(raw["id"]),
            params=dict(raw.get("params") or {}),
            enforcement_level=level,
            inherited_from=raw.get("inherited_from"),
            compiled_refs=list(raw.get("compiled_refs") or []),
        )


@dataclass
class CharterDocument:
    """What the platform stores: Intent + Control + lifecycle envelope.

    Serializes to/from the flat *packet* shape Guard consumes — control-layer
    fields at the top level, intent and lifecycle fields alongside them
    (``charter_from_mapping(strict=False)`` on the OSS side ignores what it
    doesn't model).
    """

    control: CharterSchema
    autonomy_mode: str = "interactive"
    base_strictness: str = "balanced"
    objectives: list[Objective] = field(default_factory=list)
    state: str = "draft"
    owner: str | None = None                   # Technical Owner (findings route here)
    derived_from_scan: str | None = None       # scan_id provenance (derive-then-ratify)
    created_at: str | None = None
    updated_at: str | None = None

    @property
    def agent_id(self) -> str:
        return self.control.agent_id

    @property
    def environment(self) -> str:
        return self.control.environment

    @property
    def version(self) -> str:
        return self.control.version

    def validate(self) -> list[str]:
        problems = []
        if not self.agent_id:
            problems.append("agent_id is required")
        if not self.environment:
            problems.append("environment is required")
        if not self.version:
            problems.append("version is required")
        if self.autonomy_mode not in AUTONOMY_MODES:
            problems.append(f"autonomy_mode must be one of {AUTONOMY_MODES}")
        if self.base_strictness not in STRICTNESS_LEVELS:
            problems.append(f"base_strictness must be one of {STRICTNESS_LEVELS}")
        if self.state not in LIFECYCLE_STATES:
            problems.append(f"state must be one of {LIFECYCLE_STATES}")
        seen: set[str] = set()
        for obj in self.objectives:
            if obj.id in seen:
                problems.append(f"duplicate objective: {obj.id}")
            seen.add(obj.id)
        return problems

    def to_packet(self, compiled_policy: dict | None = None) -> dict:
        """The flat dict the platform signs and serves (the Guard contract)."""
        packet = dataclasses.asdict(self.control)
        packet["autonomy_mode"] = self.autonomy_mode
        packet["base_strictness"] = self.base_strictness
        packet["objectives"] = [o.to_dict() for o in self.objectives]
        packet["state"] = self.state
        if self.owner:
            packet["owner"] = self.owner
        if self.derived_from_scan:
            packet["derived_from_scan"] = self.derived_from_scan
        if compiled_policy is not None:
            packet["compiled_policy"] = compiled_policy
        return packet

    @classmethod
    def from_dict(cls, raw: dict) -> CharterDocument:
        """Parse a flat packet-shaped mapping (the POST /v1/charters body)."""
        if not isinstance(raw, dict):
            raise ValueError("charter document must be a mapping")
        control = charter_from_mapping(raw, strict=False)
        objectives = [Objective.from_dict(o) for o in (raw.get("objectives") or [])]
        return cls(
            control=control,
            autonomy_mode=str(raw.get("autonomy_mode", "interactive")),
            base_strictness=str(raw.get("base_strictness", "balanced")),
            objectives=objectives,
            state=str(raw.get("state", "draft")),
            owner=raw.get("owner"),
            derived_from_scan=raw.get("derived_from_scan"),
            created_at=raw.get("created_at"),
            updated_at=raw.get("updated_at"),
        )


@dataclass
class Standard:
    """An org-level guardrail set every Charter in the tenant inherits (§3.1)."""

    id: str
    name: str
    version: str
    objectives: list[Objective] = field(default_factory=list)
    updated_at: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "objectives": [o.to_dict() for o in self.objectives],
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> Standard:
        if not isinstance(raw, dict) or not raw.get("id"):
            raise ValueError("standard must be a mapping with an 'id'")
        objectives = [Objective.from_dict(o) for o in (raw.get("objectives") or [])]
        for obj in objectives:
            if obj.enforcement_level not in ("mandatory", "recommended", "optional"):
                raise ValueError(
                    f"standard objective {obj.id}: enforcement_level must be "
                    "mandatory|recommended|optional"
                )
            obj.inherited_from = str(raw["id"])
        return cls(
            id=str(raw["id"]),
            name=str(raw.get("name", raw["id"])),
            version=str(raw.get("version", "1")),
            objectives=objectives,
            updated_at=raw.get("updated_at"),
        )


@dataclass
class ExceptionRecord:
    """A break-glass deviation from a mandatory objective (§3.6) — it expires."""

    objective_id: str
    agent_id: str
    environment: str
    justification: str
    granted_by: str
    granted_at: str
    expires_at: str
    scope: str = ""

    def is_active(self, now_iso: str) -> bool:
        return bool(self.expires_at) and now_iso < self.expires_at

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> ExceptionRecord:
        required = ("objective_id", "agent_id", "environment", "justification",
                    "granted_by", "granted_at", "expires_at")
        missing = [k for k in required if not raw.get(k)]
        if missing:
            raise ValueError(f"exception missing required fields: {missing}")
        return cls(
            objective_id=str(raw["objective_id"]),
            agent_id=str(raw["agent_id"]),
            environment=str(raw["environment"]),
            justification=str(raw["justification"]),
            granted_by=str(raw["granted_by"]),
            granted_at=str(raw["granted_at"]),
            expires_at=str(raw["expires_at"]),
            scope=str(raw.get("scope", "")),
        )
