# Governance

## Maintainership

`blastcontain-core` is maintained by BlastContain Contributors. The project is community-driven; PRs are welcome from anyone who signs off under the [DCO](CONTRIBUTING.md#developer-certificate-of-origin).

Final say on API changes and releases rests with the project maintainers. As the project grows we may add a more formal governance structure (steering committee, technical oversight, etc.) — for now, decisions are made by consensus among maintainers with documented rationale on the relevant PR or issue.

## Decision making

- **Trivial changes** (typos, small bug fixes): single maintainer approval.
- **Non-trivial changes** (new APIs, refactors): two maintainer approvals and a justification on the issue.
- **Breaking changes**: must be discussed in an issue first, planned across a deprecation cycle, and have at least one major version bump documented in `CHANGELOG.md`.

## Compatibility commitment

This package is depended on by downstream tools and the closed-source BlastContain Platform. We commit to:

- Semver-compliant releases
- Deprecation warnings for at least one minor version before removal
- No silent behavior changes — every public-API change is documented in `CHANGELOG.md`

## Roadmap

Tracked in [GitHub Issues](https://github.com/blastcontain/core/issues) with the `roadmap` label. Major changes go through a public RFC issue before implementation.

## Trademark

"BlastContain" is a trademark of BlastContain Inc. Use of the name to refer to this software is permitted under the Apache 2.0 license. Use as a project or product name (e.g., a fork called "BlastContain Foo") requires explicit permission.
