"""
Discovery scanner: cross-reference finds against the platform registry.

Asks the platform which agents it already knows (``GET /v1/agents``) and
classifies each asset by whether any of its candidate identities match, and if
so what lifecycle state it's in:

  - match + Active                -> REGISTERED
  - match + any other state       -> KNOWN_UNVERIFIED (draft/paused/quarantined…)
  - no match                      -> UNKNOWN_SHADOW_AI (left as-is)

Best-effort: without a URL, or if the platform is unreachable, every asset
stays shadow — Discovery still reports, it just can't vouch for anything.
"""
from __future__ import annotations

from ..models import AssetClassification, DiscoveredAsset

_ACTIVE_STATES = frozenset({"active"})


def classify_against_registry(
    assets: list[DiscoveredAsset],
    blastcontain_url: str,
    environment: str,
    token: str | None = None,
    timeout: float = 10.0,
) -> list[DiscoveredAsset]:
    """Classify assets by matching their identities to the registry."""
    if not blastcontain_url:
        return assets

    known = _fetch_registry(blastcontain_url, environment, token, timeout)
    if known is None:
        return assets

    for asset in assets:
        for ident in asset.identities():
            if ident in known:
                state = known[ident]
                asset.classification = (
                    AssetClassification.REGISTERED
                    if state in _ACTIVE_STATES
                    else AssetClassification.KNOWN_UNVERIFIED
                )
                if state and state not in _ACTIVE_STATES:
                    asset.risk_indicators.append(f"registered but state={state}")
                break
    return assets


def _fetch_registry(
    blastcontain_url: str, environment: str, token: str | None, timeout: float
) -> dict[str, str] | None:
    """Return {agent_id: state} the platform knows, or None if unreachable."""
    try:
        import httpx
    except ImportError:
        return None

    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(
            f"{blastcontain_url.rstrip('/')}/v1/agents",
            params={"env": environment} if environment else None,
            headers=headers,
            timeout=timeout,
        )
    except Exception:
        return None
    if resp.status_code != 200:
        return None
    try:
        agents = resp.json().get("agents", [])
    except ValueError:
        return None
    return {
        str(a.get("agent_id")): str(a.get("state", ""))
        for a in agents
        if a.get("agent_id")
    }
