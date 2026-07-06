# Changelog

All notable changes to `blastcontain-verify` are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [semver](https://semver.org).

## [Unreleased]

### Fixed
- **CLI no longer crashes (and loses the audit packet) on a non-UTF-8 stdout.** The results table and summary print status emoji (`✅ ❌ ⏭ ⚠️`); on Windows a redirected/piped stdout or a legacy cp1252 console couldn't encode them, so `click.echo` raised `UnicodeEncodeError` mid-run — and because the table prints *before* the report/audit/SARIF write block, the run aborted with a traceback (exit 1) and the audit packet was never written even though the scan completed. `main()` now reconfigures `stdout`/`stderr` to UTF-8 (`errors="replace"`) before any output. Linux/container output is unaffected. Regression-tested in `tests/unit/test_cli.py`.

## [0.4.0] — 2026-06-28

### Added
- **Check plugin system.** Organizations can add their own checks without forking: expose a `CheckGroup` (a `name`, the `provides` check-ID set, and `run(ctx)`) through the `blastcontain_verify.checks` entry point. Plugins run after the built-ins under the same crash quarantine — a broken plugin degrades to a `SCAN-PLUGIN` finding (status ERROR), and check-ID collisions are rejected. See `docs/plugins.md` and `examples/plugin-check/`.
- `--require-signing` flag — exit 3 *before scanning* when no real signing key is configured, so CI attestation pipelines never emit an advisory (default-HMAC-key) packet.

### Changed
- **Typed check contract (internal).** Check groups now implement `run(ctx: CheckContext) -> CheckGroupResult` (`contract.py`) and are inventoried in an ordered registry (`registry.py`) instead of being hand-called with `**kwargs` from the scanner. Typed config access replaces silently-defaulted kwargs; `ScanState.fired` replaces the ad-hoc `env02_fired` threading for composites. External behavior — CLI, report, audit packet, SARIF — is unchanged.
- Audit packets signed with the built-in default HMAC key now carry `signature.advisory: true` (additive field from `blastcontain-core`) — integrity-only signatures are machine-distinguishable from attestation. README/SECURITY.md state the distinction plainly.
- Doc-drift tests (`tests/unit/test_doc_consistency.py`) pin the spec's per-check sections and the README's check/category counts to the canonical inventory `constants.ALL_CHECK_IDS`, and pin pyproject/`__version__`/CHANGELOG coherence (regression guard for the hardcoded `generator_version` bug).
- `CONTRIBUTING.md` gains the augmentation acceptance checklist (pip-audit-clean tree, no exact-pins of shared libraries, offline/read-only import safety, tree-size budget, graceful degradation) — codifying the litellm/tldextract lessons. The Security workflow now also audits the opt-in `[cisco]` tree weekly, non-gating.

### Security
- **Every augmentation is now CVE-clean — Cisco MCP scanner dropped, Cisco skill scanner cleared.** `cisco-ai-skill-scanner>=2.0.12` raised its `litellm` floor to `>=1.84` (current `litellm` relaxed its `aiohttp`/`python-dotenv` pins to ranges), clearing CVE-2026-34993/-47265/-40217/-28684 — so the opt-in `[skill]`/`[cisco]` extra is now clean. `cisco-ai-mcp-scanner` is **removed from packaging**: every release still exact-pins the vulnerable `litellm==1.83.7`, it now conflicts with `skill>=2.0.12`, and its only consumer (MCP-01) is dormant without a Charter. (`[cisco]` is now an alias for `[skill]`; the `[mcp]` extra is gone. Re-add when upstream relaxes the pin and Charter activates MCP-01.) Bumped `agent-governance-toolkit>=4.1` and regenerated the default lock (`pip-audit`-clean).

## [0.3.1] — 2026-06-03

### Fixed
- **Hardened-container integration crash.** The scan crashed with an uncaught
  `OSError` when it could not write the audit packet — e.g. when the `/reports`
  output volume is not writable by the non-root scan UID (10001), as happens in
  CI's rootless podman (`OSError: ... '//reports/audit.json'`, propagating out of
  `main()`). `cli.py` now reports a clear, actionable error and exits 3 (ERROR)
  instead of a traceback, and the integration conftest makes the mounted output
  dir writable by the scan UID so the audit packet is written and the suite passes.
- Hardened-container scan no longer crashes when optional ML dependencies (presidio→`tldextract`, `litellm` via the Cisco scanners, Hugging Face/`onnxruntime`) meet the read-only `$HOME` and `--network none` profile. Their first-use `~/.cache` writes and remote fetches previously raised (`OSError: Read-only file system` / `socket.gaierror`) and, with some unpinned version combinations, aborted the scan. Caches are now redirected to the writable `/tmp` tmpfs and offline mode is forced *before any optional dependency is imported* (`__init__._harden_runtime_env()`, mirrored by `Containerfile` `ENV`). `$HOME` is deliberately left read-only so PERM-01 stays correct.
- MEM-01 now falls back to its built-in regex PII patterns when Presidio is installed but returns no matches (its network/cache-dependent recognisers degrading offline). Previously a present-but-degraded Presidio could PASS PII-laden context — a false negative.
- `load_config()` degrades to defaults with a stderr warning on a malformed or unreadable `--config` file (invalid YAML, or a path that is a directory) instead of raising out of `main()`.

### Changed
- **`[full]` no longer bundles the Cisco scanners — secure by default.** `[full]` is now the CVE-clean augmentation set (Presidio + AGT), and the official image ships it. The Cisco AI Defense scanners (`cisco-ai-skill-scanner` → SKILL-02, `cisco-ai-mcp-scanner` → MCP-01 backend) are **opt-in** via a new `[cisco]` extra (or `[mcp]`/`[skill]`), because they transitively pull `litellm` and its CVE-bearing `aiohttp`/`python-dotenv` pins with no upstream fix. When absent, SKILL-02 / MCP-01 SKIP with a hint on how to enable them. See SECURITY.md.
- Optional-dependency import guards in `augmentation.py` also catch `SystemExit`, so an ML library that aborts its own import downgrades the augmentation instead of crashing Verify.

### Security
- The default install and container image are now free of known-vulnerable dependencies (verified by `pip-audit` against `constraints-full.txt`). Added a `Security` CI workflow: `pip-audit` on the pinned image dependencies + `bandit` SAST on the package, gated on PRs and run weekly. SECURITY.md documents the opt-in Cisco scanners' known CVEs and the hardened-runtime mitigation.

## [0.3.0] — 2026-05-26

### Added
- `--skip-checks` flag to suppress specific check IDs (e.g. `CRED-02,LOCAL-01`)
- `--api-live-probe` flag (off by default) — API-01 only does live HTTP OPTIONS when explicitly enabled
- `--sarif PATH` flag — emit SARIF 2.1.0 for GitHub Code Scanning / GitLab Security / IDEs
- Ed25519 audit packet signing via `BLASTCONTAIN_SIGNING_KEY_PATH` / `BLASTCONTAIN_SIGNING_KEY_PEM`
- Synthetic `SCAN-<GROUP>` findings when a check group raises — scanner no longer crashes silently
- Re-exports from `blastcontain-core` so external tools can use the same models, schemas, signing, and SARIF format

### Changed
- Extracted shared types into `blastcontain-core` package (`models`, `constants.MIT_RISK_MAP`, `charter`, `signing`, `sarif`, `ignore`). This package now depends on `blastcontain-core>=0.1,<1.0`.
- Audit packet `schema_version` bumped to `1.1` — signature block now includes `algorithm`, `key_id`, `value_encoding`, `canonical`, and Ed25519-specific `public_key` and `public_key_encoding`
- Canonical signing encoding tightened to `json.dumps(sort_keys=True, separators=(",", ":"))` so signatures are reproducible cross-language
- Presidio engine now lazy-initialised on first `MEM-01` call instead of at import time
- Default HMAC key `local-verify-default` now emits a stderr warning on every use
- API-01 destructive POST keyword match now also checks the path (`/admin/destroy` fires regardless of operationId)

### Fixed
- NET-02 always-true conditional (`if "0.0.0.0:" in line or ":::":` — the literal `":::"` was truthy, fast-path was a no-op). Detection worked via the regex but the gate didn't filter as intended.

### Security
- API-01 live HTTP probe is now opt-in. Previously the scanner would send `OPTIONS` to any server URL listed in a spec — a malicious OpenAPI spec could direct scanner traffic at attacker-controlled URLs.

## [0.2.0]

Pre-extraction monorepo version. See git history.

## [0.1.0]

Initial proof-of-concept.
