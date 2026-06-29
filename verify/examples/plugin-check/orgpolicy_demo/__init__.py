"""Example blastcontain-verify check plugin.

Demonstrates the minimal CheckGroup: a `name`, the `provides` set of check IDs
the group owns (must not collide with built-ins or other plugins), and
`run(ctx)` returning a CheckGroupResult. The scanner runs plugins after the
built-ins, under the same crash quarantine — an exception here becomes a
SCAN-ORGPOLICY finding, never a dead scan.

Check IDs: pick an org-specific prefix (`ORG-`, `ACME-`) so you can never
collide with upstream checks.
"""
from __future__ import annotations

from pathlib import Path

from blastcontain_core.models import InfraFinding, Severity
from blastcontain_verify.contract import CheckContext, CheckGroupResult


class OrgPolicyGroup:
    name = "orgpolicy"
    provides = frozenset({"ORG-01"})

    def run(self, ctx: CheckContext) -> CheckGroupResult:
        """ORG-01: every deployable agent repo must carry an OWNERS file."""
        owners = Path(ctx.cfg.search_path) / "OWNERS"
        if owners.exists():
            return CheckGroupResult(passed=["ORG-01"])

        return CheckGroupResult(findings=[InfraFinding(
            check_id="ORG-01",
            finding_type="org.policy.owners_missing",
            severity=Severity.MEDIUM,
            title="No OWNERS file in the agent repository",
            detail=(
                f"`{owners}` does not exist. Org policy requires every "
                "deployable agent to declare an owning team for incident routing."
            ),
            remediation="Add an OWNERS file listing the owning team and an escalation contact.",
        )])
