"""
blastcontain_guard.concerns — the named-concern catalog (charter-spec §4).

A *concern* is a human-stated outcome ("never change production data", "block
all exfiltration") that compiles to one or more allow/ask/deny rules. This is
the catalog Guard reads for two things:

  1. **Risk tags.** A rule may name the concern it enforces (``concern:`` in the
     YAML); Guard attaches the concern's MIT-Risk / OWASP-Agentic tag to the
     decision so the *ask* prompt can show "why this matters" (guard-spec §7).
  2. **Compilation.** ``compile.py`` turns a Charter's intent into rules using
     each concern's interactive/autonomous action — the autonomy switch *is*
     the action field (charter-spec §3.2): interactive -> ``require_approval``,
     autonomous -> ``deny``.

``runtime=True`` concerns compile to a per-tool-call Guard rule. ``runtime=False``
("constraint") concerns are environmental — read-only rootfs, egress blocked,
isolation, model attestation — which **Verify** checks before deployment, not
something Guard evaluates per call. They are catalogued here so a decision can
still cite them, but Guard does not enforce them at the tool-call boundary.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Concern:
    id: str
    label: str
    interactive: str   # require_approval | deny | allow | default-deny | constraint
    autonomous: str    # deny | constraint | default-deny
    mit: str           # MIT AI Risk Repository subdomain (e.g. "2.2")
    owasp: str         # OWASP Agentic threat id(s) (e.g. "T2")
    runtime: bool      # True -> compiles to a per-tool-call rule Guard enforces
    enforcement: str = "mandatory"   # mandatory | recommended | optional (default posture)

    @property
    def risk_tag(self) -> str:
        return f"MIT {self.mit} · OWASP {self.owasp}"


_CATALOG: tuple[Concern, ...] = (
    # ① Data integrity & exfiltration
    Concern("no-prod-data-mutation", "Never change (delete/mutate) production data",
            "require_approval", "deny", "2.2", "T2", runtime=True),
    Concern("block-exfiltration", "Block all data-exfiltration paths",
            "deny", "deny", "2.1", "T2", runtime=True),
    Concern("no-pii-egress", "No PII/PHI may leave the agent",
            "require_approval", "deny", "2.1", "T2", runtime=True),
    # ② Secrets & identity
    Concern("no-readable-secrets", "The agent holds no readable secrets",
            "deny", "deny", "2.2", "T3", runtime=True),
    Concern("no-wildcard-capabilities", "No wildcard / over-broad capabilities",
            "constraint", "constraint", "2.2", "T3", runtime=False),
    # ③ Tool & MCP control
    Concern("approved-tools-only", "Only approved tools may run",
            "default-deny", "default-deny", "2.2", "T2", runtime=True),
    Concern("no-dangerous-tool-combos", "No dangerous tool combinations",
            "deny", "deny", "2.2", "T2", runtime=True),
    Concern("mcp-authenticated", "Every MCP server authenticated & encrypted",
            "constraint", "constraint", "2.2", "T12", runtime=False),
    # ④ Code & runtime isolation
    Concern("no-dangerous-code-exec", "No dangerous code execution",
            "deny", "deny", "2.2", "T11", runtime=True),
    Concern("isolated-least-privilege", "The agent runs isolated & least-privilege",
            "constraint", "constraint", "2.2", "T3", runtime=False),
    Concern("no-prod-on-workstation", "Never run a prod agent on a developer workstation",
            "constraint", "constraint", "6.5", "T8", runtime=False),
    # ⑤ Memory & model integrity
    Concern("tenant-memory-isolation", "Tenant memory is namespace-isolated",
            "constraint", "constraint", "2.1", "T1", runtime=False),
    Concern("model-weights-attested", "Model weights attested & immutable (self-hosted)",
            "constraint", "constraint", "2.2", "supply-chain", runtime=False),
    # ⑥ Delegation, identity & content safety
    Concern("no-delegation-priv-escalation", "No autonomous privilege escalation via delegation",
            "require_approval", "deny", "7.6", "T3/T13", runtime=True),
    Concern("resist-jailbreak", "The agent resists jailbreak & prompt injection",
            "deny", "deny", "7.1", "T6", runtime=False),
    Concern("content-safe-outputs", "Agent outputs are content-safe",
            "require_approval", "deny", "1.2", "T7", runtime=False),
    Concern("verify-upstream-output", "Don't blindly trust upstream agent output",
            "deny", "deny", "7.6", "T5", runtime=False),
    Concern("signed-inter-agent-messages", "Inter-agent messages authenticated & integrity-checked",
            "deny", "deny", "7.6", "T14", runtime=False),
    Concern("no-user-manipulation", "The agent must not manipulate the user; discloses it is AI",
            "require_approval", "deny", "5.2", "T15", runtime=False),
)

CONCERNS: dict[str, Concern] = {c.id: c for c in _CATALOG}


def get_concern(concern_id: str | None) -> Concern | None:
    """Look up a concern by id; ``None`` if unknown or not given."""
    if not concern_id:
        return None
    return CONCERNS.get(concern_id)


def risk_tag_for(concern_id: str | None) -> str | None:
    """The MIT · OWASP risk tag for a concern, or ``None``."""
    concern = get_concern(concern_id)
    return concern.risk_tag if concern else None
