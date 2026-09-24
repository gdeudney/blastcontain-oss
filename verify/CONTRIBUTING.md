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

## Refreshing dependencies

From the monorepo root, resolve the latest compatible stable dependencies for
the Python 3.12 container. Include Core's metadata so its dependencies are
pinned too; exclude the local Core package itself from the output:

```bash
uv pip compile core/pyproject.toml verify/pyproject.toml --extra full \
  --upgrade --python-version 3.12 --no-sources \
  --no-emit-package blastcontain-core -o verify/constraints-full.txt
uv pip compile core/pyproject.toml verify/pyproject.toml --extra validation-test \
  --upgrade --python-version 3.12 --no-sources \
  --no-emit-package blastcontain-core -o verify/constraints-validation.txt
```

`--no-sources` bypasses workspace source mappings during resolution. The
constraints describe the container's third-party runtime dependencies, not a
universal lock for all Python versions or the optional Cisco extra.

Regenerate each complete set instead of accepting independent transitive pin
bumps. Pydantic requires an exact `pydantic-core` version, and spaCy bounds Thinc;
newer versions of either dependency can make the set impossible to install.
Keep the Presidio Anonymizer exception documented in SECURITY.md until upstream
permits patched cryptography. Dependabot excludes only the known incompatible
2.2.364 release; later releases remain eligible for review.

In an isolated Python 3.12 virtual environment, validate both sets together:

```bash
pip install -e ./core -e './verify[full,validation-test,dev]' \
  -c verify/constraints-full.txt -c verify/constraints-validation.txt
pip install pip-audit build
python -m pytest core/tests verify/tests/unit
python -m pip check
ruff check core verify
pip-audit --no-deps --disable-pip -r verify/constraints-full.txt
pip-audit --no-deps --disable-pip -r verify/constraints-validation.txt
python -m build verify
```

Also test a fresh Python 3.11 environment with `pip install -e ./core
-e './verify[full,dev]'` (without the container constraints). Test
`[full,skill,dev]` separately: Cisco's transitive requirements may select
different versions, such as Rich, from the default container set. Run the
tests, `pip check`, and audit its resolved third-party dependencies as well.
The optional Cisco fixture tests skip when its package is absent and exercise
the real scanner when installed.

Finally, build the container and run `tests/integration` as described above.
Unit tests do not establish read-only/offline container compatibility. Presidio
NER also needs a compatible spaCy language model; installing the Python package
alone does not validate model-backed analysis.

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

## Adding an augmentation

Augmentations are optional third-party engines behind `augmentation.py` flags
(Presidio, AGT, the Cisco scanners). The cisco→litellm exact-pin chain cost the
default install its CVE-clean status once — the quarantine architecture
absorbed it, but selection is the cheaper control. A candidate package must
pass **all** of these before it lands in any extra:

1. **`pip-audit` clean** on its full resolved dependency tree, on the day of
   the PR. Run: `pip install <pkg> && pip-audit` in a fresh venv.
2. **No `==` pins of widely-shared libraries** in its dependency metadata
   (`aiohttp`, `requests`, `pydantic`, `click`, ...). Exact pins of common libs
   are how one package's CVE becomes unfixable for everyone (the litellm
   lesson — it exact-pins vulnerable `aiohttp` even in its own patched
   releases).
3. **Imports cleanly offline and read-only.** Under `--network none` with a
   non-writable `$HOME`, importing the package must not raise — no network
   fetches, no `~/.cache` writes at import time (the tldextract lesson). Test
   in the hardened container.
4. **Tree size budget:** fewer than ~25 transitive packages, or an explicit
   justification in the PR for why the coverage is worth the surface.
5. **A graceful-degradation path:** an availability flag in `augmentation.py`,
   `(Exception, SystemExit)` import guards, and dependent checks that SKIP
   with an enable hint when the package is absent — never crash, never
   silently pass.

CVE-bearing packages that clear the other gates go in an **opt-in extra**
(like `[cisco]`), never in `[full]`, with the accepted CVEs documented in
[SECURITY.md](SECURITY.md). The weekly Security workflow audits opt-in extras
non-gating so new CVEs in them stay visible.

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
