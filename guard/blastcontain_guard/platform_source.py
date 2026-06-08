"""
blastcontain_guard.platform_source — the Charter-source adapter (planned).

Guard takes policy from one of two sources (guard-spec §1.1): a **local YAML**
(open, standalone — fully implemented in ``policy``/``compile``) or a **signed
Charter pulled from the commercial Platform**. This module is the latter: an API
client that fetches and verifies a Platform-issued Charter.

It is open code, but only useful pointed at a Platform — so v1 ships the seam,
not a live client. ``Guard.from_charter(agent_id, env=...)`` routes here; until a
Platform is configured it raises with guidance to use the local sources instead.
Graduating from local YAML to a Platform Charter changes the *source*, not the
enforcement (same evaluator, adapters, allow/ask/deny).
"""
from __future__ import annotations

from typing import Optional

from .errors import GuardError
from .policy import Ruleset


def fetch_ruleset(
    agent_id: str,
    environment: str = "prod",
    base_url: Optional[str] = None,
    token: Optional[str] = None,
) -> Ruleset:
    """Fetch a signed Charter from the Platform and return its compiled ruleset.

    Planned (guard-spec §13). The local sources — ``Guard.from_yaml`` and
    ``Guard.from_charter_file`` — are the complete, open path and need no Platform.
    """
    raise GuardError(
        "Platform Charter source is not available in this build. Use a local "
        "policy instead: Guard.from_yaml('policy.yaml') (a governance.toolkit/v1 "
        "ruleset) or Guard.from_charter_file('charter.yaml') (a core CharterSchema "
        "compiled offline). The signed-Charter Platform client is planned "
        "(guard-spec §1.1, §13)."
    )
