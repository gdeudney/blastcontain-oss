"""
The Objective Catalog (charter-spec §4) — plain-language concerns, encoded.

Each entry maps a concern a human can reason about to: the AGT rules it
compiles to (with the interactive/autonomous action split — the autonomy
switch, §3.2), the environment constraints it mandates (deploy-time Verify
pass conditions, not per-call rules), the Verify/Drill evidence that *proves*
it, and a validated risk tag (MIT AI Risk subdomain · OWASP Agentic T#).

Three kinds of entry:
  - **rule** objectives emit per-call AGT rules;
  - **constraint** objectives tighten ``environment_constraints`` / are gated
    by Verify before the agent runs (impossible, not tedious — tenet 4);
  - **runtime** objectives are enforced by a guardrail layer (Cisco / NeMo /
    gateway) and carried for audit + plugin wiring, compiling to no AGT rule.

``default_in`` says which ``base_strictness`` levels pre-select the objective
(the secure default is the pre-selected default, §3.5).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CatalogRule:
    """One AGT rule template; the autonomy answer picks the action (§3.2)."""

    suffix: str                      # rule-name suffix (objective id prefixes it)
    condition: str                   # guard/AGT condition language
    interactive: str                 # allow | deny | require_approval
    autonomous: str


@dataclass(frozen=True)
class CatalogObjective:
    id: str
    label: str
    category: str
    risk: str                        # "MIT <subdomain> · OWASP <T#>"
    proven_by: tuple[str, ...]       # Verify check ids / Drill scenario names
    kind: str                        # rule | constraint | runtime
    rules: tuple[CatalogRule, ...] = ()
    constraints: tuple[tuple[str, object], ...] = ()  # EnvironmentConstraints tightenings
    enforcers: tuple[str, ...] = ("agt",)
    default_in: tuple[str, ...] = ("locked",)
    requires_param: str = ""         # objective only applies when this param is truthy


_DESTRUCTIVE = "action.type in ['delete', 'drop', 'truncate']"

CATALOG: dict[str, CatalogObjective] = {o.id: o for o in (
    # ── ① Data integrity & exfiltration ─────────────────────────────────────────
    CatalogObjective(
        id="no-prod-data-mutation",
        label="Never change (delete/mutate) production data",
        category="data-integrity",
        risk="MIT 2.2 · OWASP T2",
        proven_by=("API-01", "MCP-03"),
        kind="rule",
        rules=(CatalogRule("destructive", _DESTRUCTIVE, "require_approval", "deny"),),
        default_in=("locked", "balanced"),
    ),
    CatalogObjective(
        id="block-exfiltration",
        label="Block all data-exfiltration paths",
        category="data-integrity",
        risk="MIT 2.1 · OWASP T2",
        proven_by=("ENV-02", "NET-01", "SKILL-01", "MCP-03"),
        kind="rule",
        rules=(CatalogRule("send", "action.type == 'send'", "deny", "deny"),),
        constraints=(("egress_blocked", True),),
        default_in=("locked",),
    ),
    CatalogObjective(
        id="no-pii-egress",
        label="No PII/PHI may leave the agent",
        category="data-integrity",
        risk="MIT 2.1 · OWASP T2",
        proven_by=("MEM-01", "MEM-05"),
        kind="rule",
        rules=(CatalogRule("send", "action.type == 'send'", "require_approval", "deny"),),
        enforcers=("agt", "cisco", "nemo"),
        default_in=("locked", "balanced"),
    ),
    # ── ② Secrets & identity ────────────────────────────────────────────────────
    CatalogObjective(
        id="no-readable-secrets",
        label="The agent holds no readable secrets",
        category="secrets",
        risk="MIT 2.2 · OWASP T3",
        proven_by=("CRED-01", "CRED-02"),
        kind="rule",
        rules=(CatalogRule(
            "credential-access", "action.type == 'credential_access'", "deny", "deny"
        ),),
        default_in=("locked", "balanced"),
    ),
    CatalogObjective(
        id="no-wildcard-capabilities",
        label="No wildcard / over-broad capabilities",
        category="secrets",
        risk="MIT 2.2 · OWASP T3",
        proven_by=("CRED-03",),
        kind="constraint",
        default_in=("locked",),
    ),
    # ── ③ Tool & MCP control ────────────────────────────────────────────────────
    CatalogObjective(
        id="approved-tools-only",
        label="Only approved tools may run",
        category="tools",
        risk="MIT 2.2 · OWASP T2",
        proven_by=("MCP-01", "SKILL-01"),
        kind="rule",   # structural: permitted_tools allowlist + default deny (compiler emits)
        default_in=("locked", "balanced", "permissive"),
    ),
    CatalogObjective(
        id="no-dangerous-tool-combos",
        label="No dangerous tool combinations (Read+Send, Credential+Send, Execute+Write)",
        category="tools",
        risk="MIT 2.2 · OWASP T2",
        proven_by=("MCP-03",),
        kind="constraint",
        default_in=("locked",),
    ),
    CatalogObjective(
        id="mcp-auth-required",
        label="Every MCP server authenticated & encrypted",
        category="tools",
        risk="MIT 2.2 · OWASP T12",
        proven_by=("MCP-02", "TLS-01"),
        kind="constraint",
        default_in=("locked", "balanced"),
    ),
    # ── ④ Code & runtime isolation ──────────────────────────────────────────────
    CatalogObjective(
        id="no-dangerous-code-exec",
        label="No dangerous code execution",
        category="runtime",
        risk="MIT 2.2 · OWASP T11",
        proven_by=("CODE-01",),
        kind="rule",
        rules=(CatalogRule("exec", "action.type == 'exec'", "deny", "deny"),),
        default_in=("locked", "balanced"),
    ),
    CatalogObjective(
        id="isolated-least-privilege",
        label="The agent runs isolated & least-privilege",
        category="runtime",
        risk="MIT 2.2 · OWASP T3",
        proven_by=("ENV-01", "PRIV-01", "CAP-01", "DISK-02", "PERM-01"),
        kind="constraint",
        constraints=(("read_only_rootfs", True),),
        default_in=("locked",),
    ),
    CatalogObjective(
        id="no-workstation-prod",
        label="Never run a prod agent on a developer workstation",
        category="runtime",
        risk="MIT 6.5 · OWASP T8",
        proven_by=("LOCAL-01", "DISK-01"),
        kind="constraint",
        default_in=("locked",),   # informational for side-of-desk copilots (roadmap P0)
    ),
    # ── ⑤ Memory & model integrity ──────────────────────────────────────────────
    CatalogObjective(
        id="tenant-memory-isolation",
        label="Tenant memory is namespace-isolated",
        category="memory",
        risk="MIT 2.1 · OWASP T1",
        proven_by=("MEM-03",),
        kind="constraint",
        default_in=("locked",),
    ),
    CatalogObjective(
        id="model-weights-attested",
        label="Model weights attested & immutable (self-hosted only)",
        category="memory",
        risk="MIT 2.2 · supply-chain",
        proven_by=("SUP-01", "ENV-03"),
        kind="constraint",
        default_in=(),                       # off by default (§4 ⑤ conditional)
        requires_param="self_hosted",
    ),
    # ── ⑥ Delegation, identity & content safety ─────────────────────────────────
    CatalogObjective(
        id="no-delegation-escalation",
        label="No autonomous privilege escalation via delegation",
        category="delegation",
        risk="MIT 7.6 · OWASP T3/T13",
        proven_by=("ledger:blast-radius",),
        kind="rule",
        rules=(CatalogRule("delegate", "action.type == 'delegate'", "require_approval", "deny"),),
        default_in=("locked",),
    ),
    CatalogObjective(
        id="injection-resistant",
        label="The agent resists jailbreak & prompt injection",
        category="content",
        risk="MIT 7.1 · OWASP T6",
        proven_by=("drill:prompt_injection", "drill:jailbreak"),
        kind="runtime",
        enforcers=("agt", "cisco", "nemo"),
        default_in=("locked", "balanced"),
    ),
    CatalogObjective(
        id="content-safe-outputs",
        label="Agent outputs are content-safe",
        category="content",
        risk="MIT 1.2 · OWASP T7",
        proven_by=("runtime:content-filter",),
        kind="runtime",
        enforcers=("nemo", "cisco"),
        default_in=("locked", "balanced"),
    ),
    CatalogObjective(
        id="validate-upstream-output",
        label="Don't blindly trust upstream agent output",
        category="content",
        risk="MIT 7.6 · OWASP T5",
        proven_by=("drill:cascading",),
        kind="runtime",
        default_in=("locked",),
    ),
    CatalogObjective(
        id="inter-agent-auth",
        label="Inter-agent messages authenticated & integrity-checked",
        category="delegation",
        risk="MIT 7.6 · OWASP T14",
        proven_by=("drill:trust_boundary",),
        kind="runtime",
        default_in=("locked",),
    ),
    CatalogObjective(
        id="no-user-manipulation",
        label="The agent must not manipulate the user; discloses it is AI",
        category="content",
        risk="MIT 5.2 · OWASP T15",
        proven_by=("drill:manipulation",),
        kind="constraint",   # transparency_label is the control; checked at compile
        default_in=("locked",),
    ),
)}


def defaults_for(strictness: str) -> list[str]:
    """The objective ids pre-selected for a base_strictness level (§3.4)."""
    return [o.id for o in CATALOG.values() if strictness in o.default_in]
