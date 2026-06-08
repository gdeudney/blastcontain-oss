"""
blastcontain_guard.policy — the compiled-Charter ruleset (``governance.toolkit/v1``).

This is the policy format Guard enforces and the OSS wedge: a hand-authored
``allow``/``deny``/``require_approval`` ruleset is *the same format the Charter
compiles to* (guard-spec §1.1). Graduating from a local YAML to a
Platform-issued signed Charter changes the *source*, not the enforcement.

    apiVersion: governance.toolkit/v1
    name: invoice-bot-prod
    default_action: deny                 # deny-by-default — the secure default
    rules:
      - name: allow-approved-tools
        condition: "tool_name in ['query_db', 'send_notification']"
        action: allow
      - name: confirm-sends
        condition: "action.type == 'send'"
        action: require_approval
        approvers: [self]
        concern: no-pii-egress
      - name: block-destructive
        condition: "action.type in ['drop', 'delete', 'truncate']"
        action: deny                     # mandatory Standard — central exception only
        approvers: [central]

``agent_id``, ``environment`` and ``autonomy_mode`` are BlastContain extensions
to the base AGT schema (carried so a local YAML is self-describing); the base
``governance.toolkit/v1`` fields are ``apiVersion`` / ``name`` / ``default_action``
/ ``rules``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from .condition import CompiledCondition, ConditionError, compile_condition

API_VERSION = "governance.toolkit/v1"


class RuleAction(str, Enum):
    """The ruleset vocabulary — AGT's, so Guard and AGT agree by construction."""

    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


_APPROVER_ALIASES = {
    "self": "self",
    "[self]": "self",
    "central": "central",
    "central-only": "central",
    "[central]": "central",
    "[central-only]": "central",
}


class PolicyError(ValueError):
    """Raised when a ruleset document is structurally invalid."""


@dataclass
class Rule:
    name: str
    condition: str
    action: RuleAction
    approvers: list[str] = field(default_factory=list)
    concern: Optional[str] = None
    compiled: Optional[CompiledCondition] = field(default=None, repr=False, compare=False)

    def matches(self, context: dict) -> bool:
        if self.compiled is None:  # pragma: no cover - parse always compiles
            self.compiled = compile_condition(self.condition)
        return self.compiled.matches(context)

    def to_dict(self) -> dict:
        out: dict = {"name": self.name, "condition": self.condition, "action": self.action.value}
        if self.action is not RuleAction.ALLOW and self.approvers:
            out["approvers"] = list(self.approvers)
        if self.concern:
            out["concern"] = self.concern
        return out


@dataclass
class Ruleset:
    """An ordered ruleset with a default action. First matching rule wins."""

    name: str = "unnamed"
    default_action: RuleAction = RuleAction.DENY      # deny-by-default (tenet 3)
    rules: list[Rule] = field(default_factory=list)
    api_version: str = API_VERSION
    agent_id: Optional[str] = None                    # extension
    environment: Optional[str] = None                 # extension
    autonomy_mode: Optional[str] = None               # extension: interactive | autonomous
    source: Optional[str] = None                      # where it was loaded from (provenance)

    def to_dict(self) -> dict:
        out: dict = {
            "apiVersion": self.api_version,
            "name": self.name,
            "default_action": self.default_action.value,
        }
        if self.agent_id:
            out["agent_id"] = self.agent_id
        if self.environment:
            out["environment"] = self.environment
        if self.autonomy_mode:
            out["autonomy_mode"] = self.autonomy_mode
        out["rules"] = [r.to_dict() for r in self.rules]
        return out

    def to_yaml(self) -> str:
        import yaml  # type: ignore

        return yaml.safe_dump(self.to_dict(), sort_keys=False, default_flow_style=False)


# ── parsing & validation ───────────────────────────────────────────────────────

def _parse_action(raw: object, where: str) -> RuleAction:
    try:
        return RuleAction(str(raw).strip().lower())
    except ValueError:
        valid = ", ".join(a.value for a in RuleAction)
        raise PolicyError(f"{where}: unknown action {raw!r} (expected one of: {valid})")


def _normalize_approvers(raw: object, where: str) -> list[str]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else [raw]
    out: list[str] = []
    for item in items:
        key = str(item).strip().lower()
        approver = _APPROVER_ALIASES.get(key)
        if approver is None:
            raise PolicyError(
                f"{where}: unknown approver {item!r} (expected 'self' or 'central')"
            )
        if approver not in out:
            out.append(approver)
    return out


def parse_ruleset(data: dict, source: Optional[str] = None) -> Ruleset:
    """Build and validate a Ruleset from a parsed mapping."""
    if not isinstance(data, dict):
        raise PolicyError("ruleset must be a mapping")

    api_version = str(data.get("apiVersion", API_VERSION))
    if api_version != API_VERSION:
        # Forward-compatible: accept but flag. Enforcement is the same shape.
        pass

    default_action = _parse_action(data.get("default_action", "deny"), "default_action")

    raw_rules = data.get("rules", []) or []
    if not isinstance(raw_rules, list):
        raise PolicyError("'rules' must be a list")

    rules: list[Rule] = []
    seen_names: set[str] = set()
    for i, raw in enumerate(raw_rules):
        where = f"rules[{i}]"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where}: each rule must be a mapping")
        name = str(raw.get("name") or f"rule-{i}")
        if name in seen_names:
            raise PolicyError(f"{where}: duplicate rule name {name!r}")
        seen_names.add(name)

        condition = raw.get("condition")
        if not condition:
            raise PolicyError(f"{where} ({name}): missing 'condition'")
        action = _parse_action(raw.get("action"), f"{where} ({name})")
        try:
            compiled = compile_condition(str(condition))
        except ConditionError as exc:
            raise PolicyError(f"{where} ({name}): {exc}") from exc

        approvers = _normalize_approvers(raw.get("approvers"), f"{where} ({name})")
        # The honesty line, baked into defaults: a require_approval with no stated
        # approver is the user's own (ask [self]); a deny is centrally owned.
        if action is RuleAction.REQUIRE_APPROVAL and not approvers:
            approvers = ["self"]
        elif action is RuleAction.DENY and not approvers:
            approvers = ["central"]

        rules.append(
            Rule(
                name=name,
                condition=str(condition),
                action=action,
                approvers=approvers,
                concern=raw.get("concern"),
                compiled=compiled,
            )
        )

    autonomy = data.get("autonomy_mode")
    if autonomy is not None and str(autonomy) not in ("interactive", "autonomous"):
        raise PolicyError(
            f"autonomy_mode must be 'interactive' or 'autonomous', got {autonomy!r}"
        )

    return Ruleset(
        name=str(data.get("name", "unnamed")),
        default_action=default_action,
        rules=rules,
        api_version=api_version,
        agent_id=data.get("agent_id"),
        environment=data.get("environment"),
        autonomy_mode=str(autonomy) if autonomy is not None else None,
        source=source,
    )


def load_ruleset(path: str) -> Ruleset:
    """Load a ``governance.toolkit/v1`` ruleset from a YAML file."""
    import yaml  # type: ignore

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"ruleset not found: {path}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"cannot parse ruleset {path}: {exc}") from exc
    return parse_ruleset(data, source=str(p))
