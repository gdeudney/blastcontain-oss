# Governance

## Maintainership

`blastcontain-verify` is maintained by BlastContain Contributors. The project is community-driven; PRs are welcome from anyone who signs off under the [DCO](CONTRIBUTING.md#dco-sign-off).

## Decision making

- **Bug fixes**: single maintainer approval
- **New checks**: two maintainer approvals + an open issue documenting the threat model
- **Removing or weakening a check**: two maintainer approvals + a rationale in `CHANGELOG.md`
- **Breaking CLI changes**: must be discussed in an issue, deprecation warning shipped one minor version before removal

## Threat model alignment

This tool is mapped to the [MIT AI Risk Repository](https://airisk.mit.edu/). New checks must align with an existing MIT causal ID, or propose a new one with justification.

## Relationship to other BlastContain projects

- **`blastcontain-core`**: types, signing, SARIF — verify depends on this
- **`blastcontain-drill`**: runtime probing / red-team — sibling project
- **`blastcontain-discovery`**: shadow AI discovery — sibling project
- **BlastContain Platform**: closed-source Ledger + Charter management — consumes verify output via the `--blastcontain-url` flag

## Trademark

"BlastContain" is a trademark of BlastContain Inc. The name may be used to refer to this software in documentation, articles, and tutorials. Use as a project, product, or service name (e.g. "BlastContain Cloud", "BlastContain Pro") requires explicit permission.
