"""
blastcontain_guard.chokepoint — the out-of-process front (guard-spec §9).

For the dangerous few, in-process trust isn't enough: a fully compromised agent
can skip the in-process library entirely (the cooperating-agent limit, §11). The
second front gates the genuinely dangerous capabilities — egress, secrets,
destructive APIs — so they hold even then.

**Status: the *policy* is implemented; the *transport* is planned.** Each helper
below is the default-deny allowlist a sidecar would enforce — pure, testable
logic you can drive from the same Charter. The running components (an egress
proxy process, an MCP gateway, a credential-broker daemon) are planned (§13);
they wrap these policies with the actual network/secret plumbing.
"""
from __future__ import annotations

from typing import Iterable, Optional


class EgressProxyPolicy:
    """Default-deny outbound: only allowlisted destinations pass (block exfil)."""

    def __init__(self, allowed_destinations: Iterable[str] = ()):
        self.allowed = {d.strip().lower() for d in allowed_destinations if d.strip()}

    def allows(self, destination: str) -> bool:
        if not destination:
            return False
        host = destination.strip().lower()
        # exact host or a parent-domain allow (api.example.com matches example.com)
        return any(host == a or host.endswith("." + a) for a in self.allowed)


class MCPGatewayPolicy:
    """Default-deny tool allowlist at the protocol boundary (mirrors AGT's gateway)."""

    def __init__(self, permitted_tools: Iterable[str] = ()):
        self.permitted = {t.strip() for t in permitted_tools if t.strip()}

    def allows_tool(self, tool_name: str) -> bool:
        return tool_name in self.permitted


class CredentialBrokerPolicy:
    """Release a secret only against a valid Guard decision token.

    So a compromised agent finds no cached secrets — it must present a token
    minted by an *allow* decision for the specific secret (aligns with the
    short-lived-credential / SPIFFE direction, §9/§10). Token minting/verification
    is delegated to the host's signer; this is the release gate.
    """

    def __init__(self, token_verifier: Optional[object] = None):
        # token_verifier: callable(secret_id, token) -> bool. None -> deny all.
        self._verify = token_verifier

    def release(self, secret_id: str, token: Optional[str]) -> bool:
        if self._verify is None or not token:
            return False
        try:
            return bool(self._verify(secret_id, token))  # type: ignore[operator]
        except Exception:
            return False
