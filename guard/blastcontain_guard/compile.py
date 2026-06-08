"""
blastcontain_guard.compile — CharterSchema -> a compiled ruleset (the OSS bridge).

The authoritative compiler lives in the commercial Platform (charter-spec §6).
This is the *open, offline* path: turn a hand-authored ``charter.yaml`` (the
``blastcontain_core.CharterSchema`` that Verify already reads) into a
``governance.toolkit/v1`` ruleset Guard can enforce — so a team can graduate from
"no policy" to "a real Charter" without a Platform account.

Rule order matters (first match wins), so we emit most-restrictive first:

  1. **environment-derived hard denies** — e.g. ``egress_blocked`` -> deny sends;
  2. **HITL gates** from ``hitl_config.required_for`` -> ``require_approval``
     (interactive) or ``deny`` (autonomous — the autonomy switch, §3.2);
  3. **allow** the ``permitted_tools`` allowlist;
  4. **default deny**.

The autonomy switch is the only thing that differs between an interactive and an
autonomous build — exactly as the spec promises.
"""
from __future__ import annotations

from typing import Optional

from blastcontain_core.charter import CharterSchema, load_charter

from .policy import API_VERSION, Ruleset, parse_ruleset

# Known HITL tokens -> (condition, concern). Anything unrecognised is treated as
# a literal tool name that needs approval.
_HITL_MAP: dict[str, tuple[str, Optional[str]]] = {
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


def _slug(token: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in token.strip().lower()).strip("-") or "rule"


def compile_charter(charter: CharterSchema, autonomy_mode: str = "interactive") -> Ruleset:
    """Compile a CharterSchema into a ``governance.toolkit/v1`` ruleset."""
    if autonomy_mode not in ("interactive", "autonomous"):
        raise ValueError(f"autonomy_mode must be interactive|autonomous, got {autonomy_mode!r}")

    approval_action = "deny" if autonomy_mode == "autonomous" else "require_approval"
    rules: list[dict] = []

    # 1. environment-derived hard denies
    constraints = charter.environment_constraints
    if getattr(constraints, "egress_blocked", False):
        rules.append({
            "name": "env-egress-blocked",
            "condition": "action.type == 'send'",
            "action": "deny",
            "approvers": ["central"],
            "concern": "block-exfiltration",
        })

    # 2. HITL gates
    for token in charter.hitl_config.required_for:
        condition, concern = _HITL_MAP.get(
            str(token).strip().lower(), (f"tool_name == {str(token)!r}", None)
        )
        rule: dict = {
            "name": f"hitl-{_slug(str(token))}",
            "condition": condition,
            "action": approval_action,
        }
        if approval_action == "require_approval":
            rule["approvers"] = ["self"]
        else:
            rule["approvers"] = ["central"]
        if concern:
            rule["concern"] = concern
        rules.append(rule)

    # 3. allow the permitted_tools allowlist
    if charter.permitted_tools:
        rules.append({
            "name": "allow-permitted-tools",
            "condition": f"tool_name in {list(charter.permitted_tools)!r}",
            "action": "allow",
            "concern": "approved-tools-only",
        })

    doc = {
        "apiVersion": API_VERSION,
        "name": f"{charter.agent_id}-{charter.environment}",
        "agent_id": charter.agent_id,
        "environment": charter.environment,
        "autonomy_mode": autonomy_mode,
        "default_action": "deny",   # deny-by-default — the secure default (tenet 3)
        "rules": rules,
    }
    return parse_ruleset(doc, source=f"charter:{charter.agent_id}@{charter.environment}")


def compile_charter_file(path: str, autonomy_mode: str = "interactive") -> Ruleset:
    """Load a ``charter.yaml`` and compile it to a ruleset."""
    return compile_charter(load_charter(path), autonomy_mode=autonomy_mode)
