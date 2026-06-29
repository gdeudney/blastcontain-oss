"""
blastcontain_guard.models — the runtime decision vocabulary.

These are the types that flow through an enforcement: the input Guard evaluates,
the Decision it reaches, and the approval round-trip (*ask*) when a human is in
the loop. Policy-document types (Rule, Ruleset) live in ``policy``; the
mapping between the two vocabularies happens in ``evaluator``.

Two vocabularies, deliberately:
  * the **ruleset** speaks AGT's language — ``allow | deny | require_approval``
    (see policy.RuleAction), because the same Charter compiles to Guard rules
    *and* to AGT ``governance.toolkit/v1`` and they must agree by construction;
  * the **decision** Guard surfaces speaks the product language — ``allow | ask
    | deny`` (Action). ``require_approval`` resolves to ``ask``.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # avoid a runtime import cycle (policy imports this module)
    from .policy import Ruleset


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


class Action(str, Enum):
    """The resolved decision Guard surfaces to the host."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class Approver(str, Enum):
    """Who may lift an ``ask`` — the honesty line (charter-spec §3.7).

    ``SELF``    — the user has authority over their own side-of-desk action.
    ``CENTRAL`` — a mandatory Standard; no user override. Only a central
                  Exception lifts it. In open local-YAML mode there is no
                  central authority, so a central ask collapses to deny.
    """

    SELF = "self"
    CENTRAL = "central"


# Strictness lattice — used to merge decisions along a delegation chain and to
# pick the safe default. deny > ask > allow (the stricter constraint wins).
_STRICTNESS: dict[Action, int] = {Action.ALLOW: 0, Action.ASK: 1, Action.DENY: 2}


def stricter(a: Action, b: Action) -> Action:
    """Return the stricter of two actions (the weakest-link rule, §2.4)."""
    return a if _STRICTNESS[a] >= _STRICTNESS[b] else b


@dataclass
class DelegationContext:
    """Single-hop delegation context (guard-spec §5).

    When present, the call is evaluated against the *intersection* of this
    agent's ruleset and the parent's: the stricter constraint wins, and a
    parent ``deny`` is immutable (charter-spec §2.4, ADR-0014/0016).
    """

    parent_agent_id: str
    parent_ruleset: "Optional[Ruleset]" = None
    depth: int = 1


@dataclass
class EvalInput:
    """What the evaluator decides over (guard-spec §4, §5).

    ``action_type`` is the verb the call performs (``read`` / ``write`` /
    ``delete`` / ``send`` / ``exec`` / ``drop`` ...). Adapters classify it from
    the tool, or the caller supplies it; ``constants.infer_action_type`` is the
    fallback heuristic so policies written against ``action.type`` still fire.
    """

    tool_name: str
    action_type: str = ""
    args: dict = field(default_factory=dict)
    agent_id: str = ""
    identity: dict = field(default_factory=dict)
    delegation_ctx: Optional[DelegationContext] = None


@dataclass
class Decision:
    """The pure result of evaluating an EvalInput against a ruleset.

    This is *evaluation*, not *resolution*: an ``ASK`` here still has to be put
    to a human (or an autonomous escalation) by the AskResolver. ``approvers``
    records who is allowed to lift it.
    """

    action: Action
    reason: str
    rule: Optional[str] = None          # name of the matching rule, or None (default)
    approvers: list[str] = field(default_factory=list)
    matched: bool = False               # True if a rule matched; False = default_action
    risk_tag: Optional[str] = None      # e.g. "MIT 2.2 · OWASP T2", for the ask UI
    concern: Optional[str] = None       # the concern this rule enforces, if any

    @property
    def requires_central(self) -> bool:
        return Approver.CENTRAL.value in self.approvers

    def as_dict(self) -> dict:
        return {
            "action": self.action.value,
            "reason": self.reason,
            "rule": self.rule,
            "approvers": list(self.approvers),
            "matched": self.matched,
            "risk_tag": self.risk_tag,
            "concern": self.concern,
        }


class AskChoice(str, Enum):
    """The host user's answer to an ``ask`` prompt (guard-spec §7)."""

    ALLOW_ONCE = "allow_once"      # this call only
    ALLOW_ALWAYS = "allow_always"  # run + emit a learning signal (derive-then-ratify)
    DENY = "deny"                  # block; recorded


@dataclass
class AskRequest:
    """What the host renders when Guard needs approval (guard-spec §7)."""

    description: str                    # plain-language "what it wants to do"
    tool_name: str
    action_type: str = ""
    approvers: list[str] = field(default_factory=list)
    risk_tag: Optional[str] = None      # MIT · OWASP, for context
    concern: Optional[str] = None
    agent_id: str = ""
    environment: str = ""
    options: list[str] = field(
        default_factory=lambda: ["Allow once", "Allow always", "Deny"]
    )


@dataclass
class AskResult:
    """The host's answer back to Guard."""

    choice: AskChoice
    approver_id: Optional[str] = None   # who approved (for non-repudiation / audit)
    note: Optional[str] = None          # justification (logged for recommended Standards)


@dataclass
class LearningProposal:
    """A derive-then-ratify signal: ``allow always`` proposes a Charter change.

    Guard never mutates policy itself (tenet: derive then ratify). It records
    the proposal and emits it; a human ratifies the ``permitted_tools`` add
    later, logged (guard-spec §7).
    """

    agent_id: str
    tool_name: str
    action_type: str = ""
    kind: str = "permitted_tools_add"
    source: str = "allow_always"
    approver_id: Optional[str] = None
    proposed_at: str = field(default_factory=_utc_now_iso)

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "action_type": self.action_type,
            "kind": self.kind,
            "source": self.source,
            "approver_id": self.approver_id,
            "proposed_at": self.proposed_at,
        }


@dataclass
class EnforcementResult:
    """The end-to-end outcome of guarding one tool call: evaluation + resolution."""

    allowed: bool
    decision: Decision
    tool_name: str
    ask_result: Optional[AskResult] = None
    learning: Optional[LearningProposal] = None
    latency_ms: float = 0.0
    degraded: bool = False              # a backend was unreachable; see fail-closed (§8)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def denied(self) -> bool:
        return not self.allowed
