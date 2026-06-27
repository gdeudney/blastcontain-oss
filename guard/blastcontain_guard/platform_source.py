"""
blastcontain_guard.platform_source — the Charter-source adapter.

Guard takes policy from one of two sources (guard-spec §1.1): a **local YAML**
(open, standalone — ``policy``/``compile``) or a **signed Charter pulled from
the Platform**. This module is the latter: an API client that fetches a
Platform-issued Charter, verifies its signature, and returns the ruleset Guard
enforces. Graduating from local YAML to a Platform Charter changes the
*source*, not the enforcement (same evaluator, adapters, allow/ask/deny).

The contract (platform `GET /v1/charters/{agent_id}?env={environment}`):

    { "packet": { ...CharterSchema fields..., "autonomy_mode": "...",
                  "state": "active", "compiled_policy": { governance.toolkit/v1 } },
      "signature": { blastcontain_core.signing block } }

Trust rules, in order:
  1. The signature must verify (`blastcontain_core.signing.verify_packet`) —
     a packet that fails verification is rejected outright.
  2. An **advisory** signature (the platform signed with the shared default
     HMAC dev key — integrity, not attestation) is rejected unless the caller
     opts in with ``allow_advisory=True``.
  3. Lifecycle state gates enforcement: ``active`` enforces the Charter;
     ``paused`` / ``quarantined`` compile to **deny-all** (the suspend is
     enforced at the edge, not just recorded); drafts and decommissioned /
     archived agents are an error.

If the signed packet embeds ``compiled_policy`` (the Platform compiler's
authoritative output — covered by the signature) Guard enforces that; otherwise
it falls back to compiling the Charter's control layer locally via ``compile``.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from blastcontain_core.charter import charter_from_mapping
from blastcontain_core.signing import verify_packet

from .errors import GuardError
from .policy import API_VERSION, PolicyError, Ruleset, parse_ruleset

_SUSPENDED_STATES = ("paused", "quarantined")
_TERMINAL_STATES = ("decommissioned", "archived")


def _fetch_json(url: str, token: Optional[str], timeout: float) -> dict:
    """GET a JSON document from the Platform (separated for testability)."""
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - httpx is a hard guard dep
        raise GuardError("httpx is required for the Platform Charter source") from exc

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = httpx.get(url, headers=headers, timeout=timeout)
    except httpx.HTTPError as exc:
        raise GuardError(f"cannot reach the Platform at {url}: {exc}") from exc

    if response.status_code == 404:
        raise GuardError(f"the Platform has no Charter at {url}")
    if response.status_code in (401, 403):
        raise GuardError(
            f"the Platform rejected the request ({response.status_code}); "
            "set a token (BLASTCONTAIN_TOKEN or the token= parameter)"
        )
    if response.status_code != 200:
        raise GuardError(f"Platform error {response.status_code} fetching {url}")
    try:
        data = response.json()
    except ValueError as exc:
        raise GuardError(f"Platform returned non-JSON for {url}") from exc
    if not isinstance(data, dict):
        raise GuardError(f"Platform returned a non-object Charter document for {url}")
    return data


def _deny_all(packet: dict, source: str, state: str) -> Ruleset:
    """A suspended agent enforces as deny-everything, not as its old Charter."""
    return parse_ruleset(
        {
            "apiVersion": API_VERSION,
            "name": f"{packet.get('agent_id', 'agent')}-{state}",
            "agent_id": packet.get("agent_id"),
            "environment": packet.get("environment"),
            "default_action": "deny",
            "rules": [],
        },
        source=source,
    )


def fetch_ruleset(
    agent_id: str,
    environment: str = "prod",
    base_url: Optional[str] = None,
    token: Optional[str] = None,
    *,
    allow_advisory: bool = False,
    timeout: float = 10.0,
) -> Ruleset:
    """Fetch a signed Charter from the Platform and return its compiled ruleset.

    ``base_url`` defaults to ``$BLASTCONTAIN_URL`` and ``token`` to
    ``$BLASTCONTAIN_TOKEN`` — the same server the Ledger sink posts decisions to.
    """
    base = (base_url or os.environ.get("BLASTCONTAIN_URL") or "").rstrip("/")
    if not base:
        raise GuardError(
            "No Platform configured. Pass base_url= or set BLASTCONTAIN_URL — or "
            "use a local policy instead: Guard.from_yaml('policy.yaml') (a "
            "governance.toolkit/v1 ruleset) or Guard.from_charter_file('charter.yaml') "
            "(a core CharterSchema compiled offline)."
        )
    auth = token or os.environ.get("BLASTCONTAIN_TOKEN")

    url = f"{base}/v1/charters/{agent_id}?env={environment}"
    source = f"platform:{base}/{agent_id}@{environment}"
    document = _fetch_json(url, auth, timeout)

    packet = document.get("packet")
    signature = document.get("signature")
    if not isinstance(packet, dict) or not isinstance(signature, dict):
        raise GuardError(
            f"the Platform response for {agent_id}@{environment} is not a signed "
            "Charter bundle (expected {packet, signature})"
        )

    if not verify_packet({"packet": packet, "signature": signature}):
        raise GuardError(
            f"signature verification FAILED for Charter {agent_id}@{environment} — "
            "refusing to enforce an unverifiable policy"
        )
    if signature.get("advisory") and not allow_advisory:
        raise GuardError(
            f"the Charter for {agent_id}@{environment} is signed with the shared "
            "default dev key (advisory — integrity only, anyone can forge it). "
            "Configure the Platform with a real signing key, or opt in for local "
            "development with allow_advisory=True."
        )

    if packet.get("agent_id") != agent_id or packet.get("environment") != environment:
        raise GuardError(
            f"Charter identity mismatch: asked for {agent_id}@{environment}, got "
            f"{packet.get('agent_id')}@{packet.get('environment')}"
        )

    state = str(packet.get("state", "active")).lower()
    if packet.get("draft") or state == "draft":
        raise GuardError(
            f"the Charter for {agent_id}@{environment} is a draft — drafts are not "
            "enforceable; sign it on the Platform first"
        )
    if state in _TERMINAL_STATES:
        raise GuardError(
            f"agent {agent_id}@{environment} is {state} — a retired agent must not "
            "run; recommission it on the Platform for a fresh Charter"
        )
    if state in _SUSPENDED_STATES:
        print(
            f"Warning: agent {agent_id}@{environment} is {state} on the Platform — "
            "enforcing deny-all until it is resumed/recertified.",
            file=sys.stderr,
        )
        return _deny_all(packet, source, state)

    compiled = packet.get("compiled_policy")
    if isinstance(compiled, dict) and compiled:
        # The Platform compiler is authoritative, and the compiled policy is
        # inside the signed packet — tamper-evident end to end.
        try:
            return parse_ruleset(compiled, source=source)
        except PolicyError as exc:
            raise GuardError(
                f"the Platform's compiled policy for {agent_id}@{environment} is "
                f"invalid: {exc}"
            ) from exc

    # No embedded policy — compile the control layer locally (the OSS bridge).
    from .compile import compile_charter

    charter = charter_from_mapping(packet, strict=False)
    autonomy = str(packet.get("autonomy_mode", "interactive"))
    ruleset = compile_charter(charter, autonomy_mode=autonomy)
    ruleset.source = source
    return ruleset
