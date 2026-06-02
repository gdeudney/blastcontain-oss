# Changelog

All notable changes to `blastcontain-verify` are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [semver](https://semver.org).

## [Unreleased]

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
