# Governance

## Maintainership

`blastcontain-drill` is maintained by BlastContain Contributors. The project is
community-driven; PRs are welcome from anyone who signs off under the
[DCO](CONTRIBUTING.md#dco-sign-off).

## Decision making

- **Bug fixes**: single maintainer approval
- **New attack scenarios / sources**: two maintainer approvals + an open issue
  documenting the threat model and the ATLAS mapping
- **Changing a pinned corpus version**: not permitted — ship a new version. A
  pinned corpus is a regression baseline.
- **Breaking CLI changes**: discussed in an issue, deprecation warning shipped one
  minor version before removal

## Threat model alignment

Findings are tagged with [MITRE ATLAS](https://atlas.mitre.org/) (primary), the
[MIT AI Risk Repository](https://airisk.mit.edu/) domain, and OWASP Agentic
T1–T15. New scenarios must map to an existing ATLAS technique or propose a new
one with justification.

## Relationship to other BlastContain projects

- **`blastcontain-core`**: shared types, taxonomy, signing — drill depends on this
- **`blastcontain-verify`**: pre-deployment scanner — sibling project
- **`blastcontain-guard`**: in-process runtime enforcer (allow/ask/deny) — sibling project
- **`tools/scout`**: arXiv corpus scout (opens draft PRs proposing new sources) — sibling tool
- **BlastContain Platform**: closed-source Ledger + Charter management — consumes
  DrillReports via the `--blastcontain-url` flag

## Trademark

"BlastContain" is a trademark of BlastContain Inc. The name may be used to refer
to this software in documentation, articles, and tutorials. Use as a project,
product, or service name requires explicit permission.
