# Contributing to blastcontain-drill

Thanks for your interest. Drill is a red-team — a scenario that reports a false
**HELD** is worse than useless, because it tells you a control works when it
doesn't. We hold attack scenarios and scorers to the same bar Verify holds checks.

## Quick start

```
git clone git@github.com:blastcontain/drill.git
cd drill
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/unit -m "not live and not podman"
```

The default unit suite needs **no model and no Podman**. Two extra markers gate
the environment-coupled tests:

```
pytest -m live      # needs an OpenAI-compatible server (e.g. LM Studio on :1234)
pytest -m podman    # needs Podman on the host
```

## DCO sign-off

All commits must be signed off with `git commit -s`. This certifies you wrote the
patch (or have the right to submit it) under the [DCO 1.1](https://developercertificate.org/).
No CLA required.

## Adding an attack category or scenario

1. **Open an issue first.** Describe the threat, the ATLAS technique it maps to,
   and the win/lose condition (what counts as BYPASS).
2. **Add the taxonomy in `blastcontain-core`.** ATLAS is the primary tag — add the
   technique to `ATLAS_TECHNIQUES` and the category to `DRILL_CATEGORY_TAXONOMY`.
   Public taxonomy → bump `core` first. Verify ATLAS IDs against atlas.mitre.org.
3. **Add seed attacks** to `blastcontain_drill/corpus/builtin.py` and bump the
   corpus version. The corpus is a regression suite — never silently mutate a
   pinned version.
4. **Wire the win/lose condition** into the scoring combine (`scoring/combine.py`)
   if the new category needs a distinct action probe.
5. **Add tests** to `tests/unit/` covering HELD and BYPASS over synthetic cage
   observations (no live model required).

## Adding an attack source or scorer (plugins)

Drill's attack sources and scorers follow the **availability-flag** pattern
(used-if-present, never required). Implement the `AttackSource` or `Scorer`
interface, degrade gracefully to the built-in fallback when the dependency or
service is absent, and declare honestly which plane is active in the report.

## What we don't accept

- Scenarios that can be tricked into a false HELD by the target
- An attack source that leaks its generated corpus to disk unencrypted by default
- New attack categories without an ATLAS mapping in `blastcontain-core`
- Scorers that require a network service with no offline/local fallback

## Style

- `ruff check . && ruff format .` before pushing
- `mypy blastcontain_drill` should not introduce new errors

## Security issues

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md).

## Releasing

Maintainers tag a release with `git tag v0.2.0` and push. The release workflow
handles PyPI publication.
