"""
Discovery scanner: bootstrap a draft Charter for a shadow find.

Two modes, matching the derive-then-ratify tenet:

  * **platform** — POST the observed capability to the platform's
    ``/v1/charters/{id}/derive`` endpoint; the platform drafts a tight Charter
    from the observation and its objective catalog. Returns ``agent_id@env``.
  * **local** — no platform: write a minimal draft ``charter.yaml`` (a
    ``blastcontain_core.CharterSchema``) to disk for a human to review, verify,
    and sign. Returns the file path.

Either way the output is a **draft** — never enforceable until a human ratifies
it (runs Verify, signs). We never auto-register.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..models import DiscoveredAsset


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


def bootstrap_local(asset: DiscoveredAsset, output_dir: str = "./charters",
                    environment: str = "dev") -> str:
    """Write a minimal draft charter.yaml for `asset`; return its path."""
    import yaml  # type: ignore

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"draft-{_safe(asset.asset_id)}.yaml"

    document = {
        "agent_id": asset.asset_id,
        "environment": environment,
        "version": "0.0.1-draft",
        "trust_tier": 0,                    # tight until proven — not the old tier-3 default
        "draft": True,
        "permitted_tools": sorted(set(asset.tools_detected)),
        "permitted_apis": [],
        "mcp_servers": [{"name": s} for s in asset.mcp_servers],
        "environment_constraints": {
            "read_only_rootfs": True,
            "egress_blocked": True,
            "max_trust_tier": 0,
            "verify_required": True,
        },
        # provenance (ignored by the strict core loader; kept as sidecar note)
        "_discovery": {
            "source": asset.scanner,
            "location": asset.location,
            "risk_indicators": asset.risk_indicators,
        },
    }
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return str(path)


def bootstrap_platform(
    asset: DiscoveredAsset,
    blastcontain_url: str,
    environment: str = "dev",
    token: str | None = None,
    timeout: float = 10.0,
) -> str | None:
    """Ask the platform to derive a draft Charter; return 'agent_id@env' or None."""
    try:
        import httpx
    except ImportError:
        return None

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {
        "base_strictness": "locked",
        "observed": {
            "tools": sorted(set(asset.tools_detected)),
            "mcp_servers": [{"name": s} for s in asset.mcp_servers],
        },
    }
    try:
        resp = httpx.post(
            f"{blastcontain_url.rstrip('/')}/v1/charters/{asset.asset_id}/derive",
            params={"env": environment},
            headers=headers,
            content=json.dumps(body),
            timeout=timeout,
        )
    except Exception:
        return None
    if resp.status_code not in (200, 201):
        return None
    return f"{asset.asset_id}@{environment}"
