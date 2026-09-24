"""
Derive-then-ratify (charter-spec §3.5 step 3, roadmap P3 ★) — auto-draft a
tight Charter from observed reality so nobody authors from a blank form.

Input is a Verify audit packet (and, when Discovery provides one, an
``observed`` capability mapping: tools / APIs / MCP servers actually seen).
Output is a **draft** CharterDocument: tight constraints, the strictness
level's pre-selected objectives, and an allowlist seeded from observation.
The human's job is step 5 — review and sign — not data entry.
"""
from __future__ import annotations

from blastcontain_core.charter import CharterSchema, EnvironmentConstraints

from .catalog import defaults_for
from .schema import CharterDocument, Objective


def derive_document(
    agent_id: str,
    environment: str,
    audit_packet: dict | None = None,
    observed: dict | None = None,
    autonomy_mode: str = "interactive",
    base_strictness: str = "balanced",
    owner: str | None = None,
) -> CharterDocument:
    """Draft a Charter from a Verify scan + observed capability."""
    audit = audit_packet or {}
    observed = observed or {}

    # Seed the allowlists from observation (Discovery / Verify evidence). An
    # empty observation means an empty allowlist — tight, ratified open later.
    permitted_tools = sorted({str(t) for t in observed.get("tools", [])})
    permitted_apis = [a for a in observed.get("apis", []) if isinstance(a, dict)]
    mcp_servers = [m for m in observed.get("mcp_servers", []) if isinstance(m, dict)]

    # Constraints start tight (the secure default); the scan records reality —
    # divergence surfaces at compile as a conflict for the human to reconcile.
    constraints = EnvironmentConstraints(
        read_only_rootfs=True,
        egress_blocked=(base_strictness != "permissive"),
        max_trust_tier=int(audit.get("max_tier", 1) or 1),
        verify_required=True,
    )

    trust_tier = int(observed.get("trust_tier", min(constraints.max_trust_tier, 1)))

    control = CharterSchema(
        agent_id=agent_id,
        environment=environment,
        version="0.1.0",
        trust_tier=trust_tier,
        permitted_tools=permitted_tools,
        permitted_apis=permitted_apis,
        mcp_servers=mcp_servers,
        environment_constraints=constraints,
        draft=True,
    )

    objectives = [Objective(id=obj_id) for obj_id in defaults_for(base_strictness)]

    return CharterDocument(
        control=control,
        autonomy_mode=autonomy_mode,
        base_strictness=base_strictness,
        objectives=objectives,
        state="draft",
        owner=owner,
        derived_from_scan=audit.get("scan_id"),
    )
