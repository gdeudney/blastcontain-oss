# Changelog

All notable changes to `blastcontain-drill` are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [semver](https://semver.org).

## [Unreleased]

### Added
- **Operators layer** — model-free technique transforms (`base64`, `leetspeak`, `many_shot`, `persona`, `payload_split`, `prefix_injection`, `multilingual`) that expand the seed corpus into fresh variants while preserving each seed's category/goal. Enable with `--operators`.
- **Generative layer** (`--generative`) — a no-refusal/abliterated attacker model crafts and refines jailbreaks against the caged target in a PAIR/TAP loop, discovering novel attacks. Discovered jailbreaks go to a separate, sensitive corpus (`--generative-corpus`), never the signed report (which carries only an excerpt). Adds `--attacker-model`, `--generative-only`, `--generative-iters`; records `attacker_model` in the DrillReport bench provenance.
- **IBM Granite Guardian** as a second guard family — `--guard-model` now auto-selects the guard scorer (Granite Guardian or Qwen3Guard) via a pluggable factory, so guard models are swappable and comparable. Granite scores the assistant turn against a `harm` criteria (`<score>yes/no</score>`), avoiding request-contamination.
- Hardened `Containerfile` (`ghcr.io/blastcontain/drill`) and a container build job in the release workflow.

## [0.1.0] — 2026-06-01

Initial release: the Replay-layer red-team with cage action-ground-truth and a
signed, ATLAS-tagged DrillReport (drill-spec §11 build-order steps 1–5).

### Added
- **Attack corpus** — `AttackSource` plugin interface, a version-pinned built-in
  Replay seed corpus (`v2026.06`, ATLAS-tagged), and an AI-Infra-Guard adapter
  behind an availability flag.
- **Cage harness** — `Cage` interface with two backends: `InProcessCage` (drives a
  real OpenAI-compatible model through an agent loop with tool/egress allowlists,
  a planted canary, and a tool-call log) and `PodmanCage` (deny-all-egress
  container running a non-LLM stub agent).
- **Action probes** — canary-exfil, egress-attempt, and forbidden-tool detectors
  over cage observations. Drill's value-add over content-only scoring.
- **Scoring** — `Scorer` plugin interface, an LLM-as-judge (content plane), a
  Qwen3Guard classifier behind an availability flag, and a content+action combine
  that yields HELD / BYPASS + detection latency + blocked-by.
- **Runner / reporter / CLI** — orchestrator, Markdown report, and signed
  DrillReport packet (delegates signing to `blastcontain-core`).

### Notes
- Depends on `blastcontain-core>=0.2` for the shared `DrillFinding`/`DrillReport`
  types and the ATLAS/OWASP taxonomy.
- Role A (red-team) only. Role B (prove a Charter-denied action cannot execute)
  arrives with `blastcontain-guard`.
