"""
BlastContain Verify — check-group registry.

The single ordered inventory of check groups the scanner runs. Order matters
and is part of the contract: groups that feed composites run before their
consumers (environment before memory — MEM-05 reads ENV-02 from
``ScanState.fired``).

Third-party groups register through the ``blastcontain_verify.checks`` entry
point (see docs/plugins.md). Plugins are arbitrary in-process code — installing
one means trusting it; the hardened container is the blast-radius control for
the scanner itself. A plugin that fails to load, collides with existing check
IDs, or crashes mid-scan degrades to a synthetic SCAN-* finding — it can never
kill the scan (same quarantine as built-ins).
"""
from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import Callable

from .contract import CheckContext, CheckGroup, CheckGroupResult
from .checks import (
    api,
    code,
    credentials,
    environment,
    filesystem,
    local,
    mcp,
    memory,
    network,
    persistence,
    process,
    skills,
    supply_chain,
    tls,
)

ENTRY_POINT_GROUP = "blastcontain_verify.checks"


@dataclass(frozen=True)
class CheckGroupSpec:
    """Adapter giving a module-based built-in group the CheckGroup shape."""
    name: str
    provides: frozenset[str]
    run: Callable[[CheckContext], CheckGroupResult]


# Ordered: dependency order is load-bearing (see module docstring).
BUILTIN_GROUPS: tuple[CheckGroupSpec, ...] = (
    CheckGroupSpec("process",      frozenset({"PRIV-01", "CAP-01"}),            process.run),
    CheckGroupSpec("environment",  frozenset({"ENV-01", "ENV-02", "ENV-03"}),   environment.run),
    CheckGroupSpec("filesystem",   frozenset({"DISK-01", "DISK-02"}),           filesystem.run),
    CheckGroupSpec("network",      frozenset({"NET-01", "NET-02"}),             network.run),
    CheckGroupSpec("persistence",  frozenset({"PERM-01"}),                      persistence.run),
    CheckGroupSpec("local",        frozenset({"LOCAL-01"}),                     local.run),
    CheckGroupSpec("credentials",  frozenset({"CRED-01", "CRED-02", "CRED-03"}), credentials.run),
    CheckGroupSpec("memory",       frozenset({"MEM-01", "MEM-03", "MEM-05"}),   memory.run),
    CheckGroupSpec("code",         frozenset({"CODE-01"}),                      code.run),
    CheckGroupSpec("supply_chain", frozenset({"SUP-01"}),                       supply_chain.run),
    CheckGroupSpec("tls",          frozenset({"TLS-01"}),                       tls.run),
    CheckGroupSpec("skills",       frozenset({"SKILL-01", "SKILL-02"}),         skills.run),
    CheckGroupSpec("api",          frozenset({"API-01", "API-02"}),             api.run),
    CheckGroupSpec("mcp",          frozenset({"MCP-01", "MCP-02", "MCP-03"}),   mcp.run),
)


def load_plugin_groups() -> tuple[list[CheckGroup], list[str]]:
    """Discover third-party check groups from entry points.

    Returns ``(groups, errors)``. Error strings describe plugins that failed
    to load, don't satisfy the CheckGroup protocol, or claim check IDs already
    owned — the scanner surfaces each as a SCAN-PLUGIN finding rather than
    raising. An entry point may resolve to a CheckGroup instance or to a class
    (instantiated with no arguments).
    """
    groups: list[CheckGroup] = []
    errors: list[str] = []
    claimed: set[str] = set()
    for spec in BUILTIN_GROUPS:
        claimed |= spec.provides

    for ep in importlib.metadata.entry_points(group=ENTRY_POINT_GROUP):
        try:
            loaded = ep.load()
            group = loaded() if isinstance(loaded, type) else loaded
        except Exception as exc:  # noqa: BLE001 — a broken plugin must not kill the scan
            errors.append(f"plugin '{ep.name}' failed to load: {exc}")
            continue

        provides = frozenset(getattr(group, "provides", ()) or ())
        if not provides or not callable(getattr(group, "run", None)):
            errors.append(
                f"plugin '{ep.name}' does not satisfy the CheckGroup protocol "
                "(needs a non-empty `provides` and a callable `run(ctx)`)"
            )
            continue

        collisions = provides & claimed
        if collisions:
            errors.append(
                f"plugin '{ep.name}' claims check IDs that are already owned: "
                f"{', '.join(sorted(collisions))}"
            )
            continue

        claimed |= provides
        groups.append(group)

    return groups, errors
