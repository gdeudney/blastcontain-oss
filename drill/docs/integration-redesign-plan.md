# Drill integration redesign — implementation plan

Status: implementation started September 20, 2026. The first baseline and contract
milestone is documented in [redesign-baseline.md](redesign-baseline.md) and
[contracts-v1.md](contracts-v1.md). Phase 2 now has a first supported
[discovery and worker profile](plugin-workers.md). Phase 3A adds
[offline suite planning and locking](suite-planning.md). Phase 3B adds
[trusted evidence collection and offline reduction](evidence-reduction.md).
Phase 3C adds [fixture suite execution](suite-execution.md) with serial budgets and
fresh processes. Adaptive execution and run lifecycle work in 3D–3F and phases 4–7
remain planned functionality.

## Outcome

Make it possible to add an independently packaged attack tool without changing Drill's
runner or adding tool-specific CLI flags. Users should be able to review plugins and
attack content, select a reproducible suite, and run the same suite through the CLI,
CI or a local UI. Drill retains responsibility for execution limits, evidence and
final result interpretation.

Keep the current working sources, cage implementations, scorers, report signing and
legacy CLI usable throughout migration. Build this incrementally; do not replace the
runner in one change.

This plan supersedes the in-process discovery, silent availability filtering and
UI/sandbox exclusions in the earlier [registry design sketch](plugin-registry-design.md).
It also updates the older [roadmap](roadmap.md) restriction to converters only:
a bounded external attack strategy is now in scope, while Drill remains the suite runner.

## Starting point and boundaries

The original inspected baseline was `bd8d93c3a20098baac43e8a139e9bb10f2bde298`.
PRs #62–65 are now merged: MCP poisoning, Scout tracking/provenance, contracts,
and bounded workers, including the reviewed completion, publication-retry and cleanup
fixes. Phase 3A starts from main `0dac0701a3c56c51882f678e6086b83da5838851`.

Existing sources include 14 built-in cases, 200 JBB behaviors, 19 deterministic
operators, five multi-turn cases and 12 system-card cases. The generative loop is
PAIR-style sequential refinement, not TAP tree search. The AIG adapter requires
separate live-service validation. These distinctions must survive the redesign.

Scope: Agents and MCP first; reusable integration interfaces; suite execution;
research provenance; a local acceptance UI. Future Skills, APIs and CLI tools can
use the same contracts after concrete adapters exist. No public plugin marketplace,
automatic package installation, organization-wide governance engine, or full Charter
console is required. Verify remains the tool for environment/control validation;
Drill runs adversarial evaluations. Charter integration initially means optional
versioned references, not a prerequisite or a source of implicit authorization.

## Architecture and proposed deliverables

Proposed locations (names may be refined in the contract review):

| Location | Responsibility |
|---|---|
| `drill/blastcontain_drill/contracts/` | Versioned scenario, capability, event and result schemas |
| `drill/blastcontain_drill/plugins/` | Manifest discovery, compatibility, worker protocol and SDK helpers |
| `drill/blastcontain_drill/suites/` | Suite validation, planning, locking and execution coordination |
| `drill/blastcontain_drill/evidence/` | Event collection, artifact references, integrity and result reduction |
| `drill/plugins/pyrit/` | Separately packaged optional PyRIT adapter |
| `drill/plugins/agentdojo/` | Later environment integration proving the contract generalizes |
| `drill/examples/suites/` | Small reproducible agent/MCP suites and expected outcomes |
| `drill/ui/` | Local acceptance and run-inspection UI, using the same application service as the CLI |
| `drill/blastcontain_drill/corpus/arxiv/` | Paper-to-implementation mappings; existing modules linked in place |
| `tools/scout/` | Research ingestion, processing/review history and implementation evidence |

Start with Drill-specific contracts. Move only proven cross-tool primitives into
`blastcontain-core`; do not require simultaneous redesigns of Verify and Guard.

Five extension roles: scenario source, attack strategy, target adapter, environment
adapter and evaluator. An operator is a scenario-transform capability. A plugin may
provide several roles. Existing `AttackSource`, `Attacker`, `Cage` and `Scorer`
implementations get compatibility wrappers rather than wholesale rewrites.

## Delivery phases and acceptance gates

### Progress through planning and locking

Phase 0 has a local Linux baseline, source hashes, signed-report compatibility
fixture and packaging checks, with the merged changes passing applicable CI.
Phase 1 has additive record schemas, role/lifecycle
interfaces and legacy bridges; the production runner still uses its existing
observations and reports. The data contracts do not provide evidence authority/reduction,
suite execution or UI.

Phase 2 adds data-only discovery, metadata-bound acceptance, a strict worker protocol,
rootless Podman isolation, brokered calls, host/engine deadlines, independent stopping,
diagnostics and a reference plugin. The first profile accepts empty configuration and
explicit broker channels only; unsupported access/configuration fails closed. Phase 3A
adds strict suite schemas, deterministic resolution, complete case rosters and acceptance-bound
locks. Phase 3B adds trusted producer registration, scoped proof artifacts, deterministic
reduction and a conservative legacy observation bridge. Phase 3C adds replay and
materialized operator execution with serial scheduling, budgets and independently
stopped fixture processes. The next unit is 3D: brokered adaptive execution and shared
budgets across target, attacker and evaluator models. Signed evidence follows in 3E;
external tools await phase 4.

### Phase 0 — Establish the baseline and migration contract

**Deliverables**

- Reconcile main, PR #62 and local Scout changes in independently reviewable changes.
  Confirm merge dependencies without merging unrelated work automatically.
- Capture baseline source inventory, package contents, representative signed reports,
  CLI/config examples and deterministic expected results.
- Define compatibility commitments and document inaccurate PAIR/TAP wording.
- List supported platforms and optional runtime requirements. Keep current Python
  3.11/3.12 and Linux/Windows core CI coverage; container-dependent coverage is explicit.

**Tests and validation**

Run existing core, Drill and Scout unit suites; existing Podman containment tests;
MCP exposure tests on the branch containing them. Separate unavailable live-model
checks from passing checks. Inspect built wheels for datasets, license files and
excluded Scout proposals.

**Exit gate:** reproducible baseline artifacts and a documented supported-platform
matrix. Every existing failure is resolved or explicitly recorded before comparison.
Prior successful test counts are evidence of past runs, not completion of this gate.

### Phase 1 — Scenario, evidence and plugin contracts

**Deliverables**

- A `ScenarioSpec` separating legitimate task, attack objective, injectable surfaces,
  fixtures, security expectations, task-success checks and required observations.
- Manifest schema: plugin ID/version, adapter API version, upstream artifact identity,
  role(s), capability declarations, configuration schema, licenses/notices and access needs.
- Minimal acceptance-record schema binding an actor/decision to artifact digest and granted
  scope, usable by the planner before the richer Scout/UI workflow in phase 5.
- Lifecycle contracts: prepare, reset, execute/step, cancel, collect evidence and close.
  Adaptive strategies consume observations and propose actions under a bounded session.
- Versioned events for payload delivery, model output, tool requests, authorization
  decisions, attempted/performed effects, state changes and errors.
- Separate result dimensions: execution completeness, security outcome, task utility
  and evidence quality. Preserve upstream verdicts as attributed observations.
- Legacy wrappers and schema migration rules for reports consumed by `core`, diff and sweep.

**Tests and validation**

Schema validation for missing/unknown fields, unsupported versions and malformed event
sequences; serialization round trips; existing-attack conversion tests; report-reader
compatibility tests. Use the same deterministic cases through old and wrapped paths,
comparing semantic outcomes, IDs, goals and provenance (excluding timestamps/run IDs).

**Exit gate:** existing sources and generative fixtures work through wrappers without
changing their intended behavior. The contract represents both direct prompts and MCP
metadata/response injection without tool-specific branches in the runner.

### Phase 2 — Plugin packaging, discovery and bounded workers

**Deliverables**

- Data-only discovery of manifests; discovery must not import third-party executable code.
- Versioned worker protocol for selected external plugins; in-process execution reserved
  for explicitly trusted built-ins. Separate environments prevent dependency collisions.
- Isolated execution profile using the supported container runtime. A virtual environment
  is dependency isolation, not a security boundary.
- Brokered target access, explicit environment/network grants, bounded messages, deadlines,
  cancellation and worker cleanup. Do not expose the host home or container socket by default.
- SDK/reference plugin plus reusable conformance tests. Installing a package does not
  enable it, execute it during discovery, or accept its attack content.
- A diagnostic command reporting installed, accepted, compatible and available separately.

**Tests and validation**

A fixture plugin that would write a marker on import proves discovery never imports it.
Test duplicate IDs, incompatible API versions, malformed/oversized messages, worker exit,
hang, timeout and cancellation. In container integration tests, verify denied file/network
access with controlled sentinels and allowed target traffic through the broker. Verify
cleanup on success, exception and interruption.

**Exit gate:** a reference external plugin runs without core edits, cannot bypass the
configured target-call limit, and leaves no worker/container after termination. Unsupported
isolation profiles fail explicitly; they never silently fall back to host execution.

### Phase 3 — Suite planner, lock file and unified execution

The [detailed delivery plan](suite-execution-plan.md) splits this phase into 3A–3F.
3A–3C are implemented; the [planning guide](suite-planning.md),
[evidence guide](evidence-reduction.md) and [execution guide](suite-execution.md)
document their commands/APIs and the distinction between planning readiness,
observations and execution/security results.

**Deliverables**

- Strict suite schema selecting target, plugins, scenarios, required/optional coverage,
  evaluators, environment profiles, accepted versions, seeds and execution budgets.
- Pure planning step producing compatibility diagnostics and a reviewed lock file:
  exact plugin/data revisions or digests, scenario IDs, target/model configuration,
  acceptance references and suite hash. No credentials in the lock file.
- One execution path for replay, transformed and adaptive cases. Explicit per-case
  reset, bounded concurrency and append-only event/artifact recording.
- Calls, turns and wall-clock budgets enforced before dispatch, including attacker,
  target and evaluator calls. Token reservations are conservative; monetary estimates
  are not advertised as hard caps without reliable accounting.
- Signed result envelope covering the plan identity and evidence hashes; sanitized
  summaries plus separately controlled raw traces. Stop/rerun commands; automatic
  resume only for cases proven resettable, never blind replay of uncertain side effects.
- CLI equivalents of plan, run, inspect and cancel. `blastcontain-drill-suite plan`
  and `check-lock` exist; execution/result commands remain proposed.

**Tests and validation**

Required plugin unavailable, capability mismatch, invalid config, missing acceptance,
changed artifact digest, incomplete payload exposure and evaluator failure all produce
explicit outcomes. Test scope/call-budget enforcement under retries and concurrency;
reset isolation; cancellation; report tampering; redaction and secret omission.
Replay saved deterministic evidence through the reducer and require identical conclusions.

**Exit gate:** a locked suite of existing agent and MCP fixtures runs end to end and
records every selected case as completed, unsupported, skipped, failed or cancelled.
No selected required case can disappear. A run cannot pass its acceptance gate when
required coverage is missing or errored. Keep attempted blocked harm distinct from
completed harm; legacy BYPASS summaries must explain that mapping.

### Phase 4 — First production adapter: bounded PyRIT integration

**Deliverables**

- Pin one upstream release and dependencies; retain applicable license/NOTICE material.
  Review selected payload/data artifacts separately from the framework license.
- A small supported set: one adaptive multi-turn strategy and one static case, operating
  through Drill's target broker and event stream. Crescendo is the first adaptive candidate.
- Capability declarations and clear exclusions. Add TAP only after its branching/pruning
  lifecycle is represented and tested; do not imply all PyRIT strategies are supported.
- A documented local suite with benign-task controls, a deterministic resistant target
  and a deterministic vulnerable target. Add a bounded live-model validation protocol.

**Tests and validation**

Run SDK contracts against the real pinned PyRIT package, not only a mocked adapter.
Compare direct upstream execution with adapted execution using identical deterministic
targets: prompts, conversation order, reset behavior, feedback and budgets must agree
within documented adapter transformations. Test injected tool effects and exact exposure.
Run the live protocol on an available local model with model/version, settings, seeds,
repetitions and results recorded; repeat at least three times to expose variability.

**Exit gate:** plugin install/configuration requires no runner/config-class/CLI source
edits. Target traffic is observed and limited by Drill. Real-package smoke tests pass;
missing live-model availability leaves a visible release-validation item, not a claimed
live pass. No universal attack-success threshold is required for model-dependent results.

**First usable delivery:** phases 0–4 provide a CLI/CI suite with existing sources and
one real external adapter. UI development is not on this critical path.

### Phase 5 — Research mapping and acceptance records

**Deliverables**

- Connect plugin/source/scenario IDs to Scout paper IDs, upstream revisions and coverage
  scope (dataset only, partial method, original examples, full reproduction if substantiated).
- Separate plugin acceptance, attack-content acceptance and suite inclusion. Acceptance
  is a technical release decision with an actor, rationale and exact digest/scope; organization
  role policies remain configurable rather than invented by the tool.
- Make reviewed Git manifests/locks the execution source of truth. SQLite tracks workflow
  state and history; references bind it to committed artifacts. Mismatches are surfaced,
  never silently reconciled using whichever timestamp is newer.
- Track implementation and validation evidence separately from discovery/classification.
  Changed paper metadata, plugin capabilities or payload content mark the relevant reviews stale.
- Database schema migration, backup/restore and audit export; explicit status refresh after
  PR merge rather than assuming a citation is an implementation.

**Tests and validation**

Idempotent imports, transactional migrations and rollback; many-paper/many-source mappings;
stale reviews; acceptance revoked; malicious text treated as data; unmerged PRs; artifact
license conflicts; Git/database divergence; concurrent edits. Restore a backup and prove
review history and implementation evidence survive. Unchanged accepted suites run without
asking for repeated acceptance; changed digests cannot reuse the old acceptance.

**Exit gate:** trace a suite result to scenario, plugin, code revision, paper, review and
test evidence in both directions. Pending/partial work is never presented as a full paper
implementation. A different operator can rebuild the accepted suite from versioned artifacts.

### Phase 6 — Local acceptance and run UI

**Deliverables**

- Screens for plugin capabilities/licenses, Scout candidates and coverage, acceptance diffs,
  suite composition, preflight diagnostics, run/cancel and evidence inspection.
- Shared application service used by CLI and UI; no separate UI runner or policy logic.
- UI writes reviewable configuration/acceptance changes, then executes an identified lock.
  Backend revalidates the lock and acceptance at start, including when the UI is stale.
- Local-only default with authenticated/session-bound mutations, origin/CSRF protection,
  safe handling of hostile paper/trace text, and no arbitrary shell/package execution route.
  Multi-user remote deployment requires a separate access-control design.

**Tests and validation**

Browser end-to-end flows for candidate → review → suite → preflight → run → report; update
requiring renewed acceptance; cancel; unavailable plugin; incomplete exposure; and restored
history. Test UI/CLI plan-hash parity, stale concurrent edits, XSS in metadata, request forgery,
secret redaction, keyboard navigation and clear error recovery.

**Exit gate:** Gordon can select an accepted plugin, understand its requested access, run
an agent/MCP suite and trace a finding to its source without editing Python. The identical
lock produces the same deterministic outcomes through CLI and UI. Unchanged state requires
no repeated confirmations.

### Phase 7 — Prove integration breadth, then release

**Deliverables**

- AgentDojo environment adapter for one pinned task family, including state setup/reset,
  legitimate-task success and attacker-goal evaluation. Expand only after parity is shown.
- Then a bounded garak probe adapter. Evaluate DeepTeam for incremental coverage before
  adding another attack-generation dependency; keep adapter work independently releasable.
- Compatibility matrix covering capabilities, platforms, versions, artifacts and known limits.
- Migration guide, author tutorial, sample plugin, suite examples, signed-report examples,
  release notes, rollback procedure and reproducible packaging.

**Tests and validation**

AgentDojo direct-versus-adapted task/attack outcome parity with deterministic trajectories;
state isolation across cases; explicit unsupported environments. garak probe extraction and
result attribution, without converting text labels into claims of tool execution. Run the
shared adapter conformance suite on every integration. Measure planner/reducer overhead on
the phase-0 fixture set and investigate unexplained regressions before release.

**Exit gate:** both a strategy adapter and an environment adapter work without framework
special cases; user can run a pinned mixed suite with honest coverage reporting. All required
CI and release checks below pass. Keep any unvalidated integration experimental and excluded
from required release suites.

## Test and validation matrix

| Level | Execution | Required evidence |
|---|---|---|
| Unit/schema | Every relevant PR | Deterministic schema, reducer, planner, provenance and migration checks |
| Regression | Core/Drill/Scout changes | Existing CLI/source/scoring/report behavior; intentional changes documented |
| Adapter contracts | SDK or adapter changes | Lifecycle, capabilities, protocol, cancellation, errors and reset correctness |
| Container integration | Supported Linux CI runner | Sentinel file/network isolation, real fixtures, cleanup and bounded calls |
| Packaging | Release and dependency changes | Install wheels into clean environments; manifests/data/notices present; inactive proposals absent |
| Real upstream smoke | Adapter PRs/releases | Actual pinned package with deterministic target, no paid-service requirement |
| Live model | Explicit bounded release validation | Model/config/seed/repetition details, security and utility outcomes, observation limitations |
| UI end-to-end | UI/service changes | Same plan as CLI; acceptance, execution, cancellation and hostile-content handling |
| Security/dependencies | Relevant PRs/releases | Existing lint, Bandit, pip-audit/import-policy checks plus each isolated plugin dependency environment |

CI path filters must include manifests, the arXiv registry and plugin directories:
changes under Drill's registry must trigger Scout coverage tests too. Preserve a fast
model-free lane. Optional jobs must disclose skips; a missing optional environment is
not a passing validation of that adapter.

For deterministic fixtures, exact expected security/utility outcomes and complete
selected-case accounting are release requirements. For stochastic live runs, report
counts and variation rather than promising repeatable model output or universal ASR.
An effective attack and a blocked attack can both validate the harness when the observed
result agrees with the fixture's known behavior.

## Implementation order and review units

Use small PRs with their own evidence and rollback point:

1. Baseline/compatibility fixtures and design contracts (phase 0).
2. Scenario/events and legacy wrappers (phase 1).
3. Manifest discovery, worker protocol and SDK (phase 2).
4. Planner/locks, followed by executor/evidence/signing (phase 3).
5. First pinned PyRIT adapter and bounded suite (phase 4).
6. Scout/acceptance lifecycle and migrations (phase 5).
7. Local service and UI in separate changes (phase 6).
8. AgentDojo, then garak, independently; release/migration validation (phase 7).

No calendar dates are committed until the first adapter spike establishes the actual
upstream fit. Re-estimate after phase 4. If PyRIT cannot operate within the broker contract,
record the constraint and narrow the supported strategy before expanding the core.

## Definition of done

- New compliant plugins need packaging/configuration, not runner or CLI edits.
- Accepted plugin/content versions and suite locks are reproducible and traceable to Scout.
- Execution limits are enforced outside third-party plugins; unsupported capabilities are explicit.
- Reports distinguish content, attempted action, prevented effect, actual effect and legitimate utility.
- A required missing test cannot produce a passing suite; raw upstream verdicts never substitute for
  absent Drill evidence.
- Existing Drill entry points and signed-report consumers retain documented compatibility.
- CLI, CI and UI invoke the same planned execution path.
- At least PyRIT and one AgentDojo environment pass conformance and integration gates; broader
  tool support is claimed only for adapters that have independently passed their gates.
- Documentation and migration artifacts are sufficient to reproduce the demonstrated suite
  in a clean supported environment, including the acceptance and implementation history.
