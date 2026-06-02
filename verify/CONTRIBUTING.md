# Contributing to blastcontain-verify

Thanks for your interest. Verify is a security scanner — false positives erode user trust, false negatives let real risks through. We're conservative about adding checks, but very open to fixing bugs in existing ones.

## Quick start

```
git clone git@github.com:blastcontain/verify.git
cd verify
python -m venv .venv && source .venv/bin/activate
pip install -e ".[full,dev]"
python -m spacy download en_core_web_lg
pytest tests/unit
```

For integration tests:

```
cd tests/integration
podman compose -f compose.yml up -d --build
SKIP_COMPOSE=1 pytest
```

## DCO sign-off

All commits must be signed off with `git commit -s`. This certifies you wrote the patch (or have the right to submit it) under the [DCO 1.1](https://developercertificate.org/). No CLA required.

## Adding a new check

1. **Open an issue first.** Describe the threat, why it's worth scanning for, and how the check would behave (FAIL/PASS/SKIP).
2. **Find a unique check ID.** Format: `<GROUP>-<NN>`. Increment within the group.
3. **Add a finding_type and MIT mapping in `blastcontain-core`.** Public taxonomy — bump `core` first.
4. **Write the check function** in `blastcontain_verify/checks/<group>.py`. Return `tuple[list[InfraFinding], str]` where the str is one of `"FAIL"`, `"PASS"`, `"SKIP"`.
5. **Wire it into the group's `run()`** function.
6. **Add tests** to `tests/unit/checks/` covering FAIL, PASS, and SKIP paths.
7. **Add a section** to `docs/spec.md` matching the existing check format.

## What we don't accept

- Checks that require live network calls (breaks the offline guarantee — see API-01 `--api-live-probe` for how to add opt-in network checks)
- Checks that scan binary file contents (we walk text and config only)
- Checks tightly coupled to a specific vendor product (use AGT/Cisco augmentation for vendor-specific logic)
- New finding_type strings without an MIT_RISK_MAP entry

## Style

- `ruff check . && ruff format .` before pushing
- `mypy blastcontain_verify` should not introduce new errors
- Pattern matches must be tested with both positive and negative fixture inputs

## Security issues

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md).

## Releasing

Maintainers tag a release with `git tag v0.4.0` and push. The release workflow handles PyPI publication and the container image push.
