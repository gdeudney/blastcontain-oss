# Preserved product designs

These fourteen documents were extracted from PR #20, commit
`cf0d365938f9c53b61887a2c88edb4cb463e1346`, for a separate design review.
They describe historical intent; status checkmarks and security/governance claims
have not been reconciled with the current implementation. They are not release
evidence or a statement of compliance.

Current tool behavior is documented in [Verify](../verify/README.md),
[Drill](../drill/README.md), [Guard](../guard/README.md), and
[Scout](../tools/scout/README.md). The current technical control scope is in
[technical-security-checklist.md](technical-security-checklist.md).

Before merging this design set, reconcile the Charter, platform, and console
specifications with their focused implementation PRs; replace duplicated Verify
and Drill specifications with links to the maintained tool documentation; update
the roadmap to cover MCP targets, agent-to-agent relationships, and the limits of
human review. In particular, the historical assumption that a present human makes
HITL risk negligible must not be treated as a validated security control.

The implementation split keeps discovery, platform server, and console changes
independent of this design archive. Existing local databases and generated scan
reports are excluded.
