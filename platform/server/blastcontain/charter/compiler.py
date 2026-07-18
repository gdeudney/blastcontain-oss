"""
Charter Compiler — objectives → controls → ``governance.toolkit/v1`` (charter-spec §6).

The primary target is AGT's native YAML governance DSL (§6.2) — the same format
the OSS Guard enforces, so the platform's compiled policy is enforceable by
either engine. Rego remains available as an optional pluggable backend.

Pipeline:
  1. **resolve** — union the inherited Standard objectives with the owner's own
     (§3.1 inheritance), apply active Exceptions (§3.6), drop objectives whose
     gating param is unset;
  2. **emit** — each objective's catalog rules, action set by the autonomy
     switch (§3.2) and hardened by enforcement level (§3.7: a mandatory
     Standard never degrades to a user prompt — it hard-denies, central-owned);
  3. **order** — most-restrictive first (denies → asks → allows → default deny),
     mirroring the OSS bridge so both compilers agree by construction.

``push_to_agt()`` stays a Phase-5 stub: today a violation becomes a Ledger
finding after the fact; when it lands, a deny means the action never executes.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field

from .catalog import CATALOG, CatalogObjective
from .schema import CharterDocument, CharterSchema, ExceptionRecord, Objective, Standard

API_VERSION = "governance.toolkit/v1"

# hitl_config.required_for tokens → (condition, concern); unrecognised tokens are
# treated as literal tool names. Kept aligned with the OSS bridge (guard/compile.py).
_HITL_MAP: dict[str, tuple[str, str | None]] = {
    "destructive_apis": ("action.type in ['delete', 'drop', 'truncate']", "no-prod-data-mutation"),
    "destructive": ("action.type in ['delete', 'drop', 'truncate']", "no-prod-data-mutation"),
    "delete": ("action.type in ['delete', 'drop', 'truncate']", "no-prod-data-mutation"),
    "send": ("action.type == 'send'", "no-pii-egress"),
    "egress": ("action.type == 'send'", "no-pii-egress"),
    "exfiltration": ("action.type == 'send'", "block-exfiltration"),
    "pii": ("action.type == 'send'", "no-pii-egress"),
    "code_execution": ("action.type == 'exec'", "no-dangerous-code-exec"),
    "exec": ("action.type == 'exec'", "no-dangerous-code-exec"),
    "admin": ("action.type == 'admin'", "no-wildcard-capabilities"),
}

_ACTION_ORDER = {"deny": 0, "require_approval": 1, "allow": 2}


@dataclass
class CompileConflict:
    """A reconciliation item (§3.6). Blocking conflicts stop signing."""

    objective_id: str
    reason: str
    blocking: bool = False

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclass
class CompileResult:
    policy: dict                                   # the governance.toolkit/v1 document
    conflicts: list[CompileConflict] = field(default_factory=list)
    resolved_objectives: list[Objective] = field(default_factory=list)
    exceptions_applied: list[str] = field(default_factory=list)  # objective ids lifted

    @property
    def blocking_conflicts(self) -> list[CompileConflict]:
        return [c for c in self.conflicts if c.blocking]

    def to_yaml(self) -> str:
        import yaml  # type: ignore

        return yaml.safe_dump(self.policy, sort_keys=False, default_flow_style=False)


def _slug(token: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in token.strip().lower()).strip("-") or "rule"


def resolve_objectives(
    doc: CharterDocument,
    standards: tuple[Standard, ...] = (),
    exceptions: tuple[ExceptionRecord, ...] = (),
    now_iso: str = "",
) -> tuple[list[Objective], list[CompileConflict], list[str]]:
    """Union inherited Standard objectives with the Charter's own (§3.1).

    Per inherited objective: ``mandatory`` cannot be loosened or removed by the
    owner (only an active Exception lifts it); ``recommended``/``optional`` may
    be overridden by an owner objective of the same id.
    """
    conflicts: list[CompileConflict] = []
    lifted: list[str] = []

    active_exceptions = {
        e.objective_id
        for e in exceptions
        if e.agent_id == doc.agent_id
        and e.environment == doc.environment
        and e.is_active(now_iso)
    }

    own = {o.id: o for o in doc.objectives}
    resolved: dict[str, Objective] = {}

    for standard in standards:
        for inherited in standard.objectives:
            obj = Objective(
                id=inherited.id,
                params=dict(inherited.params),
                enforcement_level=inherited.enforcement_level,
                inherited_from=standard.id,
            )
            if inherited.id in own and inherited.enforcement_level != "mandatory":
                # recommended/optional: the owner's selection wins (loosening of a
                # recommended objective is a logged justification, not a block).
                continue
            if inherited.id in own and inherited.enforcement_level == "mandatory":
                conflicts.append(CompileConflict(
                    inherited.id,
                    f"objective is mandatory (Standard {standard.id}); the owner's "
                    "override is ignored",
                ))
            resolved[obj.id] = obj

    for obj_id, obj in own.items():
        if obj_id not in resolved:
            resolved[obj_id] = obj

    final: list[Objective] = []
    for obj in resolved.values():
        entry = CATALOG.get(obj.id)
        if entry is None:
            conflicts.append(CompileConflict(
                obj.id, f"unknown objective id {obj.id!r} — not in the catalog", blocking=True
            ))
            continue
        if entry.requires_param and not obj.params.get(entry.requires_param):
            conflicts.append(CompileConflict(
                obj.id,
                f"skipped: requires param {entry.requires_param!r} "
                "(off by default — charter-spec §4)",
            ))
            continue
        if obj.id in active_exceptions:
            lifted.append(obj.id)
            conflicts.append(CompileConflict(
                obj.id, "lifted by an active Exception (break-glass, expires)",
            ))
            continue
        final.append(obj)

    return final, conflicts, lifted


def _objective_rules(obj: Objective, entry: CatalogObjective, autonomy_mode: str) -> list[dict]:
    rules = []
    for template in entry.rules:
        action = template.interactive if autonomy_mode == "interactive" else template.autonomous
        # The honesty line (§3.7): a mandatory Standard never degrades to a user
        # prompt — it hard-denies, and only a central Exception lifts it.
        if obj.enforcement_level == "mandatory" and action == "require_approval":
            action = "deny"
        rule: dict = {
            "name": f"{obj.id}-{template.suffix}",
            "condition": template.condition,
            "action": action,
            "concern": obj.id,
        }
        if action == "require_approval":
            rule["approvers"] = ["self"]
        elif action == "deny":
            rule["approvers"] = ["central"]
        rules.append(rule)
    return rules


def compile_document(
    doc: CharterDocument,
    standards: tuple[Standard, ...] = (),
    exceptions: tuple[ExceptionRecord, ...] = (),
    now_iso: str = "",
) -> CompileResult:
    """Compile a CharterDocument to a ``governance.toolkit/v1`` policy."""
    conflicts: list[CompileConflict] = []
    for problem in doc.validate():
        conflicts.append(CompileConflict("document", problem, blocking=True))

    resolved, resolve_conflicts, lifted = resolve_objectives(doc, standards, exceptions, now_iso)
    conflicts.extend(resolve_conflicts)

    autonomy = doc.autonomy_mode
    control = doc.control
    rules: list[dict] = []
    refs: dict[str, list[str]] = {}

    # 1. Objective-derived rules (the Intent layer front-end, §5.2).
    for obj in resolved:
        entry = CATALOG[obj.id]
        obj_rules = _objective_rules(obj, entry, autonomy)
        rules.extend(obj_rules)
        refs[obj.id] = [r["name"] for r in obj_rules]

        # Constraint objectives must agree with the control layer; a mandatory
        # mismatch blocks signing (§3.6).
        for constraint_field, required in entry.constraints:
            actual = getattr(control.environment_constraints, constraint_field, None)
            if actual != required:
                conflicts.append(CompileConflict(
                    obj.id,
                    f"environment_constraints.{constraint_field} is {actual!r} but the "
                    f"objective requires {required!r}",
                    blocking=(obj.enforcement_level == "mandatory"),
                ))
        if obj.id == "no-user-manipulation" and not control.transparency_label:
            conflicts.append(CompileConflict(
                obj.id, "transparency_label is unset (EU AI Act Art. 50 disclosure)",
            ))

    # 2. Environment-derived hard denies (control layer, kept aligned with the
    #    OSS bridge): an egress-blocked deployment denies sends outright.
    if control.environment_constraints.egress_blocked and not any(
        r["condition"] == "action.type == 'send'" and r["action"] == "deny" for r in rules
    ):
        rules.append({
            "name": "env-egress-blocked",
            "condition": "action.type == 'send'",
            "action": "deny",
            "approvers": ["central"],
            "concern": "block-exfiltration",
        })

    # 3. Legacy hitl_config.required_for gates (pre-Intent-layer Charters).
    approval_action = "require_approval" if autonomy == "interactive" else "deny"
    for token in control.hitl_config.required_for:
        condition, concern = _HITL_MAP.get(
            str(token).strip().lower(), (f"tool_name == {str(token)!r}", None)
        )
        if any(r["condition"] == condition for r in rules):
            continue   # an objective already covers this gate
        rule = {
            "name": f"hitl-{_slug(str(token))}",
            "condition": condition,
            "action": approval_action,
            "approvers": ["self"] if approval_action == "require_approval" else ["central"],
        }
        if concern:
            rule["concern"] = concern
        rules.append(rule)

    # 4. The tool allowlist (approved-tools-only is structural: allowlist on top
    #    of default-deny — tenet 3, the secure default).
    if control.permitted_tools:
        allow_rule = {
            "name": "allow-permitted-tools",
            "condition": f"tool_name in {sorted(control.permitted_tools)!r}",
            "action": "allow",
            "concern": "approved-tools-only",
        }
        rules.append(allow_rule)
        refs.setdefault("approved-tools-only", []).append("allow-permitted-tools")

    # 5. Order most-restrictive first; first match wins in the evaluator.
    rules.sort(key=lambda r: _ACTION_ORDER.get(r["action"], 1))

    # Dedupe by condition: with denies sorted first, any later rule on a
    # condition already gated is shadowed (overlapping objectives like
    # block-exfiltration + no-pii-egress both gate sends). Re-point the
    # objective's compiled_refs at the surviving rule.
    surviving: dict[str, str] = {}     # condition -> surviving rule name
    replaced: dict[str, str] = {}      # dropped rule name -> surviving rule name
    deduped: list[dict] = []
    for rule in rules:
        survivor = surviving.get(rule["condition"])
        if survivor is not None:
            replaced[rule["name"]] = survivor
            continue
        surviving[rule["condition"]] = rule["name"]
        deduped.append(rule)
    for obj_id, names in refs.items():
        refs[obj_id] = list(dict.fromkeys(replaced.get(n, n) for n in names))

    for obj in resolved:
        obj.compiled_refs = refs.get(obj.id, [])

    policy = {
        "apiVersion": API_VERSION,
        "name": f"{doc.agent_id}-{doc.environment}",
        "agent_id": doc.agent_id,
        "environment": doc.environment,
        "autonomy_mode": autonomy,
        "default_action": "deny",
        "rules": deduped,
    }
    return CompileResult(
        policy=policy,
        conflicts=conflicts,
        resolved_objectives=resolved,
        exceptions_applied=lifted,
    )


# ── optional backends ────────────────────────────────────────────────────────────

def compile_to_rego(charter: CharterSchema) -> str:
    """Optional OPA backend (§6.2 — Rego is pluggable, not primary)."""
    tools = [f'  "{t}"' for t in charter.permitted_tools]
    tools_block = ",\n".join(tools) if tools else "  # no tools permitted"

    return f"""# BlastContain Charter Policy — auto-generated, do not edit manually
# Agent: {charter.agent_id} | Env: {charter.environment} | Version: {charter.version}

package blastcontain.charter.{charter.agent_id.replace("-", "_")}

default allow = false

# Trust tier
trust_tier := {charter.trust_tier}

# Permitted tools
permitted_tools := {{
{tools_block}
}}

allow {{
    input.tool_name in permitted_tools
}}

# Block all other tool invocations
deny {{
    not allow
}}
"""


def push_to_agt(charter: CharterSchema, agt_url: str = "") -> bool:
    """
    Phase 5 stub: Push compiled Charter policy to AGT PolicyEngine.

    When implemented: Charter deny decisions prevent tool execution before
    it occurs — not log it after. This is the difference between BlastContain
    being a governance record and a governance control.
    """
    # TODO Phase 5: POST compiled_policy to AGT PolicyEngine endpoint
    return False
