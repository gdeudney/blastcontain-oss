# Contributing to blastcontain-core

Thanks for your interest. This repo is the keystone of the BlastContain tool family — every tool depends on the types and primitives defined here, so we keep the API surface small and the test coverage tight.

## Quick start

```
git clone https://github.com/gdeudney/blastcontain-oss.git
cd blastcontain-oss/core
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Developer Certificate of Origin

All commits must be signed off with `git commit -s`, which appends:

```
Signed-off-by: Your Name <you@example.com>
```

This certifies that you wrote the patch (or have the right to submit it) under the [DCO 1.1](https://developercertificate.org/). We do not require a CLA.

## Pull request guidelines

1. **Open an issue first** for anything bigger than a typo fix or one-file change. We want to know if the feature belongs here or in a downstream tool repo.
2. **Public API stability matters.** Anything in `blastcontain_core.models`, `.charter`, or `.signing` is imported by external tools and the platform — breaking changes need a major version bump and a deprecation cycle.
3. **Add tests.** New code must include unit tests. Test fixtures live in `tests/`.
4. **No untyped public functions.** Use type hints on everything exported.
5. **No platform-specific assumptions.** Code in `blastcontain_core` runs anywhere — Linux, macOS, Windows. If a feature needs platform branching, do it in the consuming tool, not in core.

## What belongs in core

✅ Types used by ≥ 2 BlastContain tools
✅ The MIT_RISK_MAP (the public taxonomy mapping)
✅ Charter schema (every tool may need to read it)
✅ Signing / SARIF (every tool produces signed packets and SARIF)
✅ `.blastcontainignore` parsing (every file-walking tool needs it)

❌ Specific checks (those belong in `verify` / `drill` / `discovery`)
❌ Tool-specific helpers
❌ Anything platform-only

## Style

- Run `ruff check .` and `ruff format .` before pushing
- Run `mypy blastcontain_core` if you touched types

## Releasing

Maintainers only. We follow [semver](https://semver.org) strictly because downstream tools pin compatibility ranges:

- `MAJOR.MINOR.PATCH`
- Major bump for any breaking change to a public API surface
- Minor bump for new functionality (additive)
- Patch bump for fixes

Tag a release with `git tag core-v0.2.0` and push (`git push origin core-v0.2.0`). The `core-` prefix selects this package in the monorepo; the release workflow then builds and publishes `blastcontain-core` to PyPI.
