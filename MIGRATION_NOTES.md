# BlastContain OSS — Migration Notes

> ⚠️ **Historical record — this extraction is complete and the repo has moved on.** Written when only
> `core` (0.1.0) and `verify` were extracted. Current reality: a single `gdeudney/blastcontain-oss`
> monorepo with **five** built packages — `core` 0.2.0, `verify` 0.3.1, `drill` 0.1.0, `guard` 0.1.0,
> `tools/scout` 0.1.0 — and a **single** CI workflow (`.github/workflows/ci.yml`, with `import-policy`
> as a *job*, not a per-package workflow). The org/GHCR commands below still say `blastcontain/*`; the
> real remote is `gdeudney/blastcontain-oss`. The "Drill and Discovery … don't have implementations
> yet" section is obsolete (Drill and Guard are built; only Discovery remains unbuilt). Steps are kept
> for history.

Status of the local extraction and the manual steps left for you.

## What's done locally

Two new repos have been created at `C:\Users\deudn\blastcontain-oss\`:

```
blastcontain-oss/
├── core/      blastcontain-core 0.1.0  (Apache 2.0)
└── verify/    blastcontain-verify 0.3.0 (Apache 2.0, depends on core)
```

Both:
- Build cleanly (`pip install -e .` works in both)
- Import correctly — `verify.models.InfraFinding is core.models.InfraFinding` (type identity confirmed)
- Pass unit tests (`pytest tests/` in core: 11/11 green)
- End-to-end smoke test passes — verify scans a dirty fixture, emits SARIF 2.1.0 and a signed audit packet that verifies through `blastcontain_core.signing.verify_packet`

## What's in `core/`

| File | Purpose |
|---|---|
| `blastcontain_core/models.py` | `Severity`, `ScanStatus`, `InfraFinding`, `ScanResult` |
| `blastcontain_core/constants.py` | `MIT_RISK_MAP` (27 entries), `TIER_BLAST_WEIGHTS`, `mit_for()` |
| `blastcontain_core/charter.py` | `CharterSchema`, `DelegationRules`, `HitlConfig`, `RemediationProof`, `EnvironmentConstraints`, `load_charter()` |
| `blastcontain_core/signing.py` | `sign_packet()`, `verify_packet()` — Ed25519 + HMAC |
| `blastcontain_core/sarif.py` | `build_sarif()`, `write_sarif()` — SARIF 2.1.0 |
| `blastcontain_core/ignore.py` | `.blastcontainignore` loader |
| `tests/` | 11 unit tests covering models + signing round-trips |
| Apache 2.0 LICENSE, NOTICE, README, CONTRIBUTING, GOVERNANCE, SECURITY, CHANGELOG, CODE_OF_CONDUCT | |
| `.github/workflows/ci.yml`, `release.yml`, ISSUE_TEMPLATE/ | |

## What's in `verify/`

| File | Purpose |
|---|---|
| `blastcontain_verify/` | CLI, scanner, config, 14 check modules |
| `blastcontain_verify/models.py` | **Re-export shim** → `blastcontain_core.models` |
| `blastcontain_verify/ignore.py` | **Re-export shim** → `blastcontain_core.ignore` |
| `blastcontain_verify/reporter_sarif.py` | **Wrapper** — sets tool metadata, calls `blastcontain_core.sarif.write_sarif` |
| `blastcontain_verify/constants.py` | Verify-specific (SECRET_ENV_NAMES, CODE_*_PATTERNS, etc.); re-exports MIT_RISK_MAP from core |
| `blastcontain_verify/reporter.py` | Markdown report + audit packet (delegates signing to core) |
| `tests/integration/` | The 28 FAIL + 30 PASS Podman-based integration tests |
| `tests/unit/` | Pre-existing verify unit tests |
| `docs/spec.md` | The verify spec doc (moved from `docs/BlastContain-verify-spec.md`) |
| `examples/blastcontain-verify.yaml` | Sample config |
| `Containerfile` | The two-stage hardened container |
| Apache 2.0 LICENSE, NOTICE, **THIRD_PARTY_NOTICES.txt** (Cisco/AGT MIT attribution), README, CONTRIBUTING, GOVERNANCE, SECURITY, CHANGELOG, CODE_OF_CONDUCT | |
| `.github/workflows/ci.yml`, `integration.yml`, `release.yml`, **`import-policy.yml`** (forbids `blastcontain.platform` imports) | |

## What stays in the existing monorepo (`C:\Users\deudn\blastcontain\`)

Everything you haven't migrated yet:
- `server/` — the Ledger, Charter management, web UI (closed source — keep here)
- `tests/scenarios/` and `tests/containers/` — multi-agent test scenarios (probably move to platform-only)
- The `tools/blastcontain-verify/` and `tests/integration/` directories are now duplicated in `blastcontain-oss/verify/` — once you're confident in the OSS extraction, **delete these from the monorepo** and update the platform to depend on the published `blastcontain-verify` package.

The future state of the existing monorepo is **the closed-source platform repo**. Rename it to `platform/` and make the GitHub repo private.

---

## Manual steps for you

### Prerequisites — verify these first

None of the following have been confirmed from this machine. Check each before running the steps below, or they will fail partway through:

- **`gh` CLI installed and authenticated** — `gh auth status` should show a logged-in account with `repo` and `admin:org` scopes. If not: `winget install GitHub.cli`, then `gh auth login`.
- **The `blastcontain` GitHub org exists, or you can create it** — `gh api orgs/blastcontain` returns the org if it exists (404 means it needs creating). Creating an org via `gh api orgs` needs elevated scopes and is restricted on some accounts; the web UI (https://github.com/account/organizations/new) always works and orgs are free.
- **A PyPI account that can register both project names** — confirm `blastcontain-core` and `blastcontain-verify` are still available (https://pypi.org/project/blastcontain-core/ → "not found" is good) and that your account can create Trusted Publishers.
- **Podman or Docker authenticated to `ghcr.io`** for the container push (Step 4) — needs a GitHub token with `write:packages`.

### Step 1 — Create the GitHub repos

```bash
gh repo create blastcontain/core   --public  --description "Shared types, Charter schema, signing, and SARIF for BlastContain tools"
gh repo create blastcontain/verify --public  --description "Pre-deployment compliance scanner for AI agents"
```

If the GitHub org doesn't exist yet:

```bash
gh api orgs --method POST -f login=blastcontain
```

(Or create via the web UI — GitHub orgs are free.)

### Step 2 — Initialize git in each repo and push

```bash
cd C:/Users/deudn/blastcontain-oss/core
git init
git add .
git commit -s -m "Initial release of blastcontain-core 0.1.0"
git branch -M main
git remote add origin git@github.com:blastcontain/core.git
git push -u origin main

cd C:/Users/deudn/blastcontain-oss/verify
git init
git add .
git commit -s -m "Initial release of blastcontain-verify 0.3.0"
git branch -M main
git remote add origin git@github.com:blastcontain/verify.git
git push -u origin main
```

Note the `-s` flag on commit — this enforces DCO sign-off per `CONTRIBUTING.md`.

### Step 3 — Configure PyPI Trusted Publishing

PyPI's "Trusted Publishers" (no API token, OIDC-based) is the modern way to publish from GitHub Actions.

For `blastcontain-core`:
1. Reserve the name on PyPI: https://pypi.org/manage/account/publishing/
2. Add a pending publisher: project name `blastcontain-core`, owner `blastcontain`, repo `core`, workflow `release.yml`, environment (leave blank)
3. Tag and push: `cd core && git tag v0.1.0 && git push --tags`
4. The release workflow will publish to PyPI on tag push

For `blastcontain-verify`:
1. Same flow, project name `blastcontain-verify`, repo `verify`, workflow `release.yml`
2. **Publish core first, wait for it to be available on PyPI, then tag verify** — verify depends on `blastcontain-core>=0.1,<1.0`

### Step 4 — Build and publish the container

The verify Containerfile is already set up. To publish to GitHub Container Registry:

```bash
cd C:/Users/deudn/blastcontain-oss/verify
podman build -t ghcr.io/blastcontain/verify:0.3.0 -t ghcr.io/blastcontain/verify:latest .
echo $GITHUB_TOKEN | podman login ghcr.io -u <your-username> --password-stdin
podman push ghcr.io/blastcontain/verify:0.3.0
podman push ghcr.io/blastcontain/verify:latest
```

The `release.yml` workflow handles this automatically on tag push.

### Step 5 — Clean up the original monorepo

After confirming the OSS extraction is working in production:

```bash
cd C:/Users/deudn/blastcontain
# Remove what's been extracted
git rm -r tools/blastcontain-verify/
git rm -r tests/integration/
git rm -r tests/tools/verify/
git rm  docs/BlastContain-verify-spec.md

# Update platform code to consume verify as a package, not as source
# (anywhere that did `from blastcontain_verify import ...` now imports
#  the published package, same import path)

git commit -s -m "Extract verify tool to blastcontain-oss/verify"
```

Then transfer or rename the repo to `blastcontain/platform` and make it private.

### Step 6 — Make `server/blastcontain/charter/schema.py` import from core

In the platform repo, replace the local Charter schema with:

```python
from blastcontain_core.charter import (
    CharterSchema,
    DelegationRules,
    HitlConfig,
    RemediationProof,
    EnvironmentConstraints,
)
```

The classes are wire-compatible — the platform was already using the same field names.

Keep platform-specific extensions (storage, versioning, approval workflows) in `server/blastcontain/charter/` as separate modules that consume the OSS schema.

### Step 7 — Watch for community

Once `blastcontain-verify` is on PyPI and the README is live, expect:
- A small number of GitHub stars in the first week
- Maybe 1–2 issues in the first month
- Be responsive — early signal-to-noise is high

Plan a Hacker News / Reddit / Hashnode launch announcement once you have a working `pip install blastcontain-verify`, a 30-second demo GIF, and the spec doc live.

---

## Drill and Discovery

Skipped in this migration — they don't have implementations yet. When each is ready:

1. Create `blastcontain/drill` or `blastcontain/discovery` (public, Apache 2.0)
2. Depend on `blastcontain-core`
3. Same boilerplate set (copy from `verify/`)
4. Same import-policy enforcement to keep platform code out

---

## Sanity reminders

- **Don't touch the OSS code from the platform repo.** If platform needs something verify has, it should import from the published PyPI package, never from sibling source.
- **The MIT_RISK_MAP is canonical.** Any new finding_type needs a corresponding entry in `core/blastcontain_core/constants.py` — and the verify `CHANGELOG.md` should call out the new MIT mapping.
- **`signing.py` is a public commitment.** Once it's published, the canonical encoding (`json-sort-keys-tight`) and the Ed25519 packet format become contracts. Breaking changes need a major version bump.
- **CONTRIBUTING.md says no CLA.** Stick with DCO — switching to a CLA later would invite a fork. The community read on this is strong.

If you want me to also extract drill or discovery once they exist, or to write a launch blog post / HN announcement, ping me.

---

## Platform import (2026-07-17)

The commercial platform repo was merged into this repo as a **clean snapshot**
(no history carried over) and re-licensed Apache-2.0:

- `platform/server/` — Charter compiler, Ledger + MPL, Fleet API (`blastcontain-server`, was `Proprietary`, now Apache-2.0; uv sources now point at in-repo `core`/`guard`)
- `platform/gui/` — Next.js console + hardened Containerfile
- `platform/tests/` — server unit tests, scenarios, container compose
- `docs/` — the product spec set, at repo root; the verify/drill spec mirrors now point at the in-repo canonical `verify/docs/spec.md` / `drill/docs/spec.md`

**Deliberately not imported** (stale or runtime artifacts): `tools/` pre-split
copies of verify/drill/discovery, `tests/tools/`, `tests/integration/` (older
duplicate of `verify/tests/integration/`), `tests/containers/Containerfile.verify`,
`blastcontain.db`, `gui/web/node_modules/`, `audit.json` / `report.md` scan
outputs, product `CLAUDE.md`, and the legacy `integration.yml` workflow.

The "OSS never imports platform" rule is unchanged and still CI-enforced —
the boundary is now a directory boundary instead of a repo boundary.
