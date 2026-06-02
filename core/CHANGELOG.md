# Changelog

All notable changes to `blastcontain-core` are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [semver](https://semver.org).

## [Unreleased]

## [0.2.0] — 2026-06-01

Adds the shared Drill (adversarial red-team) types and the AI-native taxonomy,
so `blastcontain-drill` and the platform Ledger consume the same dataclasses —
mirroring how Verify shares `InfraFinding`/`ScanResult`.

### Added
- `blastcontain_core.models` — `DrillOutcome`, `DrillStatus`, `DrillFinding`, `DrillReport`
- `blastcontain_core.constants` — `ATLAS_TECHNIQUES` (MITRE ATLAS registry, verified vs atlas.mitre.org), `OWASP_AGENTIC_MAP` (T1–T15), `DRILL_CATEGORY_TAXONOMY`, and `atlas_for()` / `owasp_for()` / `taxonomy_for()` lookups

### Notes
- ATLAS is the primary taxonomy for Drill findings; the two agent techniques `AML.T0086` (Exfiltration via AI Agent Tool Invocation) and `AML.T0110` (AI Agent Tool Poisoning) cover the action plane.
- Drill's MIT mapping carries only the real top-level domain name; numeric subdomain IDs are intentionally omitted rather than invented (validate against airisk.mit.edu before adding).
- Additive only — no change to the signing format or existing types, so this is backwards-compatible for `blastcontain-verify>=0.1,<1.0`.

## [0.1.0] — 2026-05-26

Initial extraction from the `blastcontain-verify` monorepo.

### Added
- `blastcontain_core.models` — `Severity`, `ScanStatus`, `InfraFinding`, `ScanResult`
- `blastcontain_core.constants` — `MIT_RISK_MAP`, `TIER_BLAST_WEIGHTS`, `mit_for()` lookup helper
- `blastcontain_core.charter` — `CharterSchema`, `DelegationRules`, `HitlConfig`, `RemediationProof`, `EnvironmentConstraints`, `load_charter()`
- `blastcontain_core.signing` — `sign_packet()`, `verify_packet()`, `canonical_bytes()` (Ed25519 + HMAC fallback)
- `blastcontain_core.sarif` — `build_sarif()`, `write_sarif()` (SARIF 2.1.0)
- `blastcontain_core.ignore` — `load_ignore_patterns()`, `is_ignored()` (`.blastcontainignore`)

### Notes
- Canonical signing encoding is `json.dumps(payload, sort_keys=True, separators=(",", ":"))` and is recorded as `signature.canonical = "json-sort-keys-tight"`.
- The HMAC default key `local-verify-default` emits a stderr warning on every use to surface that signatures are advisory-only without a real key.
