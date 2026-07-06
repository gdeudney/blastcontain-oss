# Changelog

All notable changes to `blastcontain-drill` are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [semver](https://semver.org).

## [Unreleased]

## [0.2.0] — 2026-07-05

Corpus expansion + two-plane scoring hardening. Every source layer is now real, multi-turn attacks
ship, guardrail scorers are pluggable across three families, and the model-sweep + drill-diff
harnesses close the regression loop. Still Alpha; the CLI surface gained several flags but no
existing flag was removed.

### Added

**Attack corpus — new sources**
- **Operators layer** (`--operators`) — model-free `str→str` technique transforms applied to every
  seed, expanding each into fresh variants while preserving category/goal. Ships 19 transforms:
  encoders (`base64`, `rot13`, `caesar`, `atbash`, `morse`, `binary`, `url_encode`, `reverse`),
  filter-evasion (`leetspeak`, `char_space`, `zero_width`, `homoglyph`), and framing (`many_shot`,
  `persona`, `payload_split`, `prefix_injection`, `multilingual`, `academic_framing`, `fiction_frame`).
- **JailbreakBench source** (`--jbb`) — vendored MIT dataset revision `886acc3` (100 harmful + 100
  benign over-refusal probes). New `DrillOutcome.OVER_REFUSAL` in `blastcontain-core`; scorers are
  benign-aware (judge branches its prompt, guards abstain by axis eligibility).
- **System-card source** (`--systemcard`) — cyber-misuse / dual-use, identity & leaked-info honesty,
  and ART indirect-injection probes derived from published system-card taxonomies.
- **Multi-turn source** (`--multiturn`) — the cage now carries conversation state
  (`Attack.turns` + `cage.run_agent`, one Toolbox spans all turns). Ships long-context reference
  tracking, decomposition/recompose, and a real multi-turn crescendo (a canary read on turn 1 and
  an exfil on turn N are one `CageObservation`).
- **Generative layer** (`--generative`) — abliterated/no-refusal attacker model crafts and refines
  attacks against the caged target in a PAIR/TAP loop. Discovered jailbreaks are written to a
  separate, sensitive corpus (`--generative-corpus`), never into the signed report (which carries
  only an excerpt). Adds `--attacker-model`, `--attacker-base-url`, `--generative-only`,
  `--generative-iters`; records `attacker_model` in the DrillReport bench provenance.

**Scoring — pluggable guard family**
- **IBM Granite Guardian** as a second guard family. `--guard-model` now auto-selects across
  Qwen3Guard / Granite Guardian / WildGuard via `make_guard_scorer` (model-id substring match).
  Granite scores the assistant turn against a `harm` criteria (`<score>yes/no</score>`).
- **WildGuard scorer** — retires the Qwen3Guard real-roles hack. Native refusal + harm axes score
  benign over-refusal without abstaining.
- **DeepEval G-Eval judge** — `--judge-kind {llm,geval}` selects a calibrated CoT judge (via the
  `[judge]` extra); reuses Drill's local judge model through a wrapped `DeepEvalBaseLLM`.
- **Rubric-on-Attack refactor** — each `Attack` carries a `Rubric{question, axis, on_match, severity}`;
  scorers declare `axes` and `score_content` routes by eligibility. Replaces the `guards-abstain-on-benign`
  hack with principled routing (new judging modes need zero scorer/combine edits).

**Reproducibility & regression**
- **Model-sweep harness** — `python -m blastcontain_drill.sweep --models a,b,c` runs Drill per target
  model with a fixed judge/guard, producing signed per-model reports plus a risk-ranked leaderboard
  (md + json).
- **Drill diff** — `blastcontain-drill-diff old.json new.json` computes the regression delta between
  two signed DrillReports; new CLI entry point.
- **Sweep resumability** — `--resume` skips finished models, retries transient failures.
- **Effective-attack database** — `attackdb` records generative-discovered attacks with content +
  scoring provenance for later replay.
- **Version-pinned attack sources** — every `AttackSource` declares a `revision`, recorded in the
  signed report as `name@revision` (e.g. `jailbreakbench@886acc3`, `builtin-replay@v2026.06.1`).
- **ASR@k + judge-reliability surfacing** — reports now expose confidence and judge/guard agreement.
- **Jailbreak-resistance study harness** — sweeps generative attacks across model fleets, records
  the ASR distribution and the effective-attack corpus per target.

**Packaging & operations**
- Hardened `Containerfile` (`ghcr.io/gdeudney/blastcontain-drill`) and a container build job in the
  release workflow. Runs as non-root, offline-hardened caches, pinned dependencies.
- `[project.urls]` now points at `gdeudney/blastcontain-oss` (the actual repo).

### Changed
- Built-in Replay seed corpus bumped to `v2026.06.1` (relabel `jb-03` single-shot crescendo →
  `crescendo-singleshot`; the real multi-turn crescendo lives in the multi-turn source).
- Reasoning-model handling: `ChatClient` sends `chat_template_kwargs={"enable_thinking": false}`,
  the generative attacker uses a concise prompt with `max_tokens=4096`.
- Qwen3Guard scorer uses real `user`/`assistant` roles (was under-flagging unsafe content when the
  attack prompt and response were concatenated).
- Report provenance: `bench.attacker_model` recorded; `sources` list emitted as `name@revision`.

### Fixed
- AI-Infra-Guard adapter body: `model_redteam_report` now uses the API-correct target `model[]` +
  `eval_model` shape.

### Notes
- Depends on `blastcontain-core>=0.2,<1.0` for the shared `DrillFinding`/`DrillReport` types and
  the ATLAS/OWASP/MIT taxonomy.
- Role A (red-team) matures; Role B (prove a Charter-denied action cannot execute) is unblocked
  now that `blastcontain-guard` is built, with Charter-source → Drill wiring still pending.
- ~150 model-free unit tests across 21 files (up from 52 in 0.1.0); lint clean.

## [0.1.0] — 2026-06-02

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
