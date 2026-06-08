"""
blastcontain_guard.agt_export — emit and push the AGT second front's policy.

Guard and AGT agree *by construction* because they enforce the **same compiled
policy** (guard-spec §8). Guard's ruleset format already *is* AGT's
``governance.toolkit/v1``, so emitting AGT policy is mostly serialization — with
two transforms that make it a clean, faithful AGT document rather than just a
dump of Guard's local ruleset:

  1. **Strip BlastContain extensions.** ``agent_id`` / ``environment`` /
     ``autonomy_mode`` and per-rule ``concern`` are Guard's own annotations, not
     base AGT fields. They move into a ``metadata`` block (provenance preserved)
     so the core document is exactly ``apiVersion`` / ``name`` / ``default_action``
     / ``rules``.
  2. **Apply the autonomy switch** (charter-spec §3.2). For an *autonomous* agent
     there is no human to prompt, so ``require_approval`` is emitted as
     ``deny [central]`` — the same rule, resolved for the unattended case.

``push_to_agt`` is the deploy seam (roadmap P4 ``push_to_agt()``): render the
policy and hand it to a running AGT via an injected client, an admin endpoint, or
a file AGT loads. The live AGT SDK call is the planned piece; the render and the
transports are real and tested. This is the *deploy* path (ship policy to AGT);
the *runtime consult* path — Guard asking an enabled AGT at decision time — is
``backends.combine_with_agt``.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Optional

from . import __version__
from .policy import RuleAction, Ruleset

AGT_API_VERSION = "governance.toolkit/v1"

# An AGT client: given the rendered policy document, deliver it (truthy/raises).
# This is the integration point for the real AGT SDK; tests inject a fake.
AgtClient = Callable[[dict], object]


def to_agt_policy(
    ruleset: Ruleset,
    autonomy_mode: Optional[str] = None,
    include_metadata: bool = True,
) -> dict:
    """Render a clean AGT ``governance.toolkit/v1`` document from a ruleset."""
    effective = autonomy_mode or ruleset.autonomy_mode or "interactive"
    autonomous = effective == "autonomous"

    rules_out: list[dict] = []
    for rule in ruleset.rules:
        action = rule.action
        approvers = list(rule.approvers)
        if autonomous and action is RuleAction.REQUIRE_APPROVAL:
            # No human to ask when unattended -> hard deny, central exception only.
            action = RuleAction.DENY
            approvers = ["central"]
        emitted: dict = {"name": rule.name, "condition": rule.condition, "action": action.value}
        if action is not RuleAction.ALLOW and approvers:
            emitted["approvers"] = approvers
        rules_out.append(emitted)

    doc: dict = {
        "apiVersion": AGT_API_VERSION,
        "name": ruleset.name,
        "default_action": ruleset.default_action.value,
        "rules": rules_out,
    }
    if include_metadata:
        doc["metadata"] = {
            "agent_id": ruleset.agent_id,
            "environment": ruleset.environment,
            "autonomy_mode": effective,
            "generator": "blastcontain-guard",
            "generator_version": __version__,
            "source": ruleset.source,
        }
    return doc


def to_agt_yaml(ruleset: Ruleset, **kwargs) -> str:
    """The AGT policy document as YAML (what you hand to AGT)."""
    import yaml  # type: ignore

    return yaml.safe_dump(
        to_agt_policy(ruleset, **kwargs), sort_keys=False, default_flow_style=False
    )


@dataclass
class PushResult:
    delivered: bool
    transport: str            # "client" | "http" | "file" | "none"
    policy: dict
    detail: str = ""

    def as_dict(self) -> dict:
        return {"delivered": self.delivered, "transport": self.transport, "detail": self.detail}


def push_to_agt(
    ruleset: Ruleset,
    *,
    client: Optional[AgtClient] = None,
    endpoint: Optional[str] = None,
    path: Optional[str] = None,
    token: Optional[str] = None,
    autonomy_mode: Optional[str] = None,
    include_metadata: bool = True,
    dry_run: bool = False,
) -> PushResult:
    """Render the AGT policy and deliver it to a running AGT.

    Transport, in priority order: an injected ``client`` (the AGT SDK integration
    point), an admin ``endpoint`` (HTTP POST), or a ``path`` (a file AGT loads).
    ``dry_run`` renders without delivering. With no transport it renders and
    reports ``delivered=False`` (it never raises on the deploy path).
    """
    policy = to_agt_policy(ruleset, autonomy_mode=autonomy_mode, include_metadata=include_metadata)

    if dry_run:
        return PushResult(False, "none", policy, "dry run — rendered, not delivered")

    if client is not None:
        client(policy)
        return PushResult(True, "client", policy, "delivered via client")

    if endpoint:
        return _push_via_http(policy, endpoint, token)

    if path:
        _write_yaml(policy, path)
        return PushResult(True, "file", policy, f"written to {path}")

    return PushResult(
        False, "none", policy,
        "no transport configured (pass client=, endpoint=, or path=); rendered only",
    )


def _push_via_http(policy: dict, endpoint: str, token: Optional[str]) -> PushResult:
    try:
        import httpx

        headers = {"Authorization": f"Bearer {token}"} if token else {}
        resp = httpx.post(endpoint, json=policy, headers=headers, timeout=10)
        ok = resp.status_code in (200, 201, 202, 204)
        return PushResult(ok, "http", policy, f"POST {endpoint} -> {resp.status_code}")
    except Exception as exc:
        return PushResult(False, "http", policy, f"POST {endpoint} failed: {exc}")


def _write_yaml(policy: dict, path: str) -> None:
    import yaml  # type: ignore

    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(policy, f, sort_keys=False, default_flow_style=False)
