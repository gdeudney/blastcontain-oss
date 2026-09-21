# Drill suites — phase 3 delivery plan

Status: PRs #62–67 and the prerequisite review fixes are merged. Phases 3A
(schema, resolution and locking) and 3B (evidence authority/reduction) are merged.
Phase 3C's [fixture execution API](suite-execution.md) is implemented;
adaptive execution and run lifecycle work in 3D–3F remain planned.
See [suite-planning.md](suite-planning.md) for the supported offline commands,
examples, acceptance flow and current limitations. This document expands
phase 3 of the [integration redesign](integration-redesign-plan.md).

Planning readiness is not an execution or security result. The current commands
are `blastcontain-drill-suite plan` and `check-lock`; other commands below remain
proposals. The first catalog supports the existing controlled fixture environment
and external strategy metadata, not arbitrary target/environment worker adapters.

## Delivery outcome

An operator can select reviewed agent and MCP scenarios, inspect exactly what will
run, accept that plan, and execute it with explicit limits. Every selected case has
a recorded disposition. The result separates agent behavior, cage containment,
task success and missing evidence. A signed report identifies the plan and the
evidence used to reach each conclusion.

Keep the existing Drill CLI, sources, local abliterated LLM attacker, scorers and
report readers usable. First deliver CLI and CI support. A later local UI calls the
same application service for review, inclusion, execution and inspection. Verify
continues to validate controls; Drill tests adversarial behavior; Charter references
remain optional context. Organizational authorization policy is outside this phase.

## Decisions for the first supported suite

- Agents and controlled MCP description/response poisoning are the initial targets.
  Direct testing of arbitrary remote MCP servers, Skills, APIs, CLI tools and code
  needs separate adapters and validation; the current poisoning fixture does not
  imply that coverage.
- Planning is data-only and deterministic. It consumes reviewed scenario snapshots,
  trusted built-in inventories, manifests, acceptance records and explicit runtime
  probe results. It never imports external plugin code, starts workers, contacts a
  model, installs packages or pulls images. Probing is a separate explicit operation.
- External plugins keep the current Linux/rootless-Podman profile, empty config,
  pinned local image IDs and broker access. There is no added host fallback.
  CLI planning/inspection remain usable on supported Linux and Windows platforms.
- Replay, deterministic transforms and adaptive attacks share case scheduling,
  budgets, evidence and results. They have different producers of proposed inputs.
  Adaptive attacks retain the existing PAIR-style loop and local abliterated-model
  configuration; TAP and a real PyRIT adapter are later work.
- Unknown source revisions cannot produce an executable lock. Resolve an exact
  content digest plus code/build identity. A remote model alias is recorded honestly
  as an alias if no immutable model identity is available; do not promise reproducible
  live outputs from a seed or alias alone.
- Required coverage fails closed. Optional exclusions need explicit reasons and
  remain visible. An empty selector cannot silently produce a successful run.
- A plugin verdict is a claim. Only registered host/environment emitters can supply
  trusted observations; an `authority` string received over JSON grants no authority.

## Data and application boundaries

| Record/service | Required behavior |
|---|---|
| `SuiteSpec` | Version, target kind and binding references, source selectors, plugin roles, fixture/environment profile, evaluator policy, required/optional groups, seeds, concurrency, global and per-case limits |
| `ResolvedPlan` | Ordered cases; exact source, scenario, transform and plugin identities; capabilities and observations; target/model settings without secrets; unresolved/unsupported diagnostics; content digest |
| `SuiteLock` | Immutable resolved plan plus acceptance snapshots/references and artifact hashes; recorded probe observations; lock digest; no executable object or credential values |
| `CaseRecord` | Stable ID derived from source/scenario/config/repetition; required flag; scheduling state and terminal disposition; result/evidence references or explicit exclusion reason |
| `RunRecord` | Unique run ID, lock digest, complete planned case roster, runtime identity, global ledger, cancellation/cleanup state, artifact index and gate result |
| Collector/reducer | Append-only bounded event/artifact recording; trusted emitter assignment; reference validation; deterministic reduction into `ScenarioResult` |
| Application service | Plan, accept, run, inspect, cancel and explicit rerun operations shared by CLI and future UI; no product policy inside command handlers |

Use strict decoding: reject duplicate/unknown fields, nonfinite numbers, unsupported
versions, duplicate case IDs and invalid budget combinations. Hash a documented
canonical encoding. Store artifacts under generated safe filenames, never raw IDs
or plugin-provided paths. Readers reject traversal, symlinks and oversized artifacts.

Avoid circular acceptance hashes: suite acceptance binds the resolved plan's content
digest, excluding decisions/timestamps. The final lock digest also covers the
acceptance snapshots. Plugin acceptance retains `review_digest(manifest)` semantics;
content acceptance binds exact scenario/data bytes. Check the latest decisions at
run start and before launching each case. Do not treat a stale snapshot as current
authorization. Rich actor/role management remains phase 5.

Credential references resolve only in trusted bindings at execution. Lockable
configuration uses an allowlist of supported fields; reject embedded authorization
headers, URL userinfo, arbitrary secret-bearing config and signed query credentials.
Plugin payloads cannot select broker destinations or retrieve credentials. Record
safe endpoint/model identity separately from secret material.

## Reviewable implementation units

Each row is a separate PR-sized milestone. Tests belong with the behavior they
validate. A milestone is complete only after its checks pass on its actual PR head.

| Unit | Deliverables | Required tests and exit gate |
|---|---|---|
| **0. Repair current stack** | Fix worker pipe cleanup, MCP step exhaustion and Scout proposal retry; update affected evidence/compatibility notes | Reproduce and then fix all three review cases. Test both output streams above pipe capacity, independent cancel/timeout, partial MCP runs with and without observed harm, recorded preview then publish, and retry after publish failure. All affected PR checks pass. |
| **3A. Schema, resolution and lock** | `suites/schema.py`, `planner.py`, `lock.py`; explicit built-in catalog; materialized reviewed external scenario data; pure compatibility diagnostics; content/plugin/suite acceptance checks; proposed `plan` command | Stable lock under equivalent input ordering; duplicate/empty selection; missing required vs optional plugin; role/surface/observation mismatch; stale/revoked acceptance; changed image/data/target config; secrets absent. No worker/model calls during planning. Lock fully enumerates every case. |
| **3B. Evidence authority and reduction** | `evidence/collector.py`, `artifacts.py`, `reducer.py`; trusted producer registration; legacy observation bridge; versioned payload conventions and terminal reasons | Fake plugin authority/effect claims cannot establish success; broken/hash-mismatched/cross-case references rejected; gaps/truncation/contradictory completion never yield held; offline replay yields identical results. Controlled legacy/MCP outcomes preserved except explicitly corrected false-held cases. |
| **3C. Replay and transformed execution** | `suites/service.py`, `runner.py`; fixed case roster; serial global/per-case budget ledger; fresh environment/reset contract; agent/MCP bindings; deterministic transform identities; reset and cleanup evidence | Resistant/vulnerable agents and both MCP surfaces run from one lock. Step exhaustion, backend failure, missing exposure, reset failure, unsupported target and optional exclusions are distinct. Every planned case receives one terminal disposition; no state/canary bleed between cases. |
| **3D. Adaptive execution and shared budgets** | Broker wrappers for target, attacker and evaluator; global/per-case ledger; pre-dispatch reservations; bounded concurrency; deadline propagation; legacy PAIR-style strategy bridge and reference external plugin | Recording-backend parity for the existing attacker prompt/history; two-call reference strategy; limits under concurrent cases, retries, exceptions, reset, cancellation and unavailable usage accounting. Local abliterated-model configuration remains supported. No network provider call bypasses the ledger. |
| **3E. Durable results, stop and signing** | Run/artifact store; sanitized summaries and opt-in protected raw evidence; signed suite envelope; inspect/verify/cancel/rerun services; explicit legacy export | Lock/evidence tamper or missing files fail verification; secret sentinels absent from normal artifacts; cancellation stops active workers and records pending cases; crash recovery never claims completion; stale/forged stop request cannot affect another run; required signing cannot silently fall back. |
| **3F. CLI, examples and release validation** | Proposed suite CLI; agent/MCP fixture suites; acceptance walkthrough; result explanations; CI matrix; package install checks and bounded live validation recipe | Clean-wheel plan/accept/run/inspect/cancel round trip; all 501 current definitions still load; existing CLIs/report readers remain compatible; Linux container checks and Linux/Windows model-free tests pass; live checks recorded separately from deterministic fixture results. |

Sequence: 0 → 3A → 3B → 3C → 3D → 3E → 3F. Define collector and ledger interfaces
before 3C so early execution cannot become an unbudgeted alternate path. Until 3E,
execution is a development API, not the advertised production suite command.
After this phase, integrate a pinned PyRIT release as the first real external tool.

## Execution and outcome rules

At run creation persist the complete roster before dispatch. Case scheduling states
are pending/running/terminal; terminal dispositions distinguish completed, incomplete,
unsupported, skipped, error and cancelled. `skipped` is a case-record disposition,
not a new value silently inserted into the existing v1 `ScenarioResult` enum.
If a schema change becomes necessary, version it and add migration tests.

For each executable case: revalidate identities and current acceptance; reserve
resources; prepare a fresh/resettable environment; establish observation channels;
deliver the attack; collect evidence; evaluate; finalize; independently clean up.
Scenarios sharing a mutable environment cannot run concurrently without a proven
isolation/reset contract. Initial concurrency defaults to one.

The existing synchronous cage API is insufficient for hard cancellation on its own.
Use an independently stoppable execution process or cancellable I/O binding. Timing
out an awaiting thread does not stop its work. In-process fixtures remain explicitly
trusted simulations; actual container claims require the Podman profile and checks.
Cancellation of a remote request does not prove remote side effects stopped: record
that uncertainty and require fresh validation before rerun.

| Observed situation | Required interpretation |
|---|---|
| Complete execution, required exposure and observations present, no violation | Security held for the tested scenario; utility reported separately |
| Forbidden action attempted and cage blocked it | `action_attempted`, containment `blocked`; legacy BYPASS explains attempted harm |
| Independent environment evidence confirms an effect | `effect_observed`; identify the effect and observer |
| Model/plugin says an action succeeded | Claim only, never proof of an effect |
| Step/turn/deadline budget exhausted | Execution incomplete; no held result; retain affirmative observed harm if any |
| MCP response never reaches a target call | Incomplete/unexercised, never held |
| Evaluator unavailable/failed or required evidence missing | Error/incomplete/unknown as applicable; required gate fails |
| Agent refuses a benign task | Utility failed when measured; security and task utility stay separate |

Reducer inputs include the pinned scenario, trusted trace and validated evaluator
observations. Preserve per-channel provenance and coverage scope. A legacy boolean
or aggregate tool list cannot be promoted into stronger evidence than it contains.
For example, the cage's simulated “delivered” response is not proof of a real
external send, and an aggregate observation cannot invent event timing.

The run gate is separate from execution completion. It passes only when every
required case completed, required observations/evaluators are satisfied, and its
explicit security/utility policy passed. Optional omissions appear in the summary;
they never disappear from counts. Failures to persist evidence or clean up resources
make the run non-passing even if individual model responses looked safe.

## Budgets, retries and stopping

- Reserve from both the global and case ledgers atomically before every target,
  attacker and evaluator call. Retries and ambiguous network failures consume calls.
  Reset, worker replacement and scenario delegation never replenish global limits.
- Count target/model calls, strategy iterations, tool steps, wall time and artifact
  bytes separately. Nested tool calls need a binding that can observe/enforce them;
  reject a hard-limit requirement an opaque remote adapter cannot enforce.
- Disable hidden transport retries or route each attempt through the ledger. Inject
  brokered clients into existing scorers/attacker code; wrapping only the outer
  legacy loop is not sufficient to budget internal requests.
- Reserve conservative input/output tokens only when the tokenizer/endpoint supports
  enforceable limits. Otherwise report estimates and rely on hard call/time caps;
  reject a requested hard token cap the adapter cannot honor. Money remains an estimate.
- Keep primary monotonic deadlines plus independent worker stopping. Bound pipe
  draining, cleanup and evidence volume, including during idle periods and callbacks.
- Cancellation prevents new dispatch, terminates owned workers, finalizes in-flight
  cases conservatively and marks unstarted cases cancelled. Local stop requests use
  an owner-restricted run directory/control channel; never trust an arbitrary PID file.
- Initial rerun creates a new run linked to the original and revalidates acceptance.
  No automatic crash resume. Add resume only for adapters with tested reset and
  idempotency guarantees; never replay uncertain effects automatically.

## Evidence storage and compatibility

The signed envelope binds schema version, lock digest, runtime/reducer identities,
case roster, results, policy and artifact hashes. Verify against an operator-trusted
key when attestation is required; an embedded key alone is not trusted identity.
Retain clearly labeled advisory local signing for demos. If required signing cannot
load its key, fail explicitly instead of accepting the current fallback as attestation.

Default artifacts contain bounded structured observations and redacted summaries.
Credentials never enter worker messages, locks or reports. Opt-in raw traces need
owner-only storage, explicit retention and separate access; redact exception paths
and headers too. Hash and sign exactly the retained representation. If redaction
removes evidence needed for a conclusion, mark it unverifiable/partial; do not claim
an independently replayable conclusion from missing raw inputs.

Existing `DrillReport` and diff/sweep readers retain their schema. Provide an explicit
legacy projection and a suite-native envelope. Do not label absent utility checks as
success or map partial action evidence to a completed effect. Freeze representative
old reports; review any intended result change rather than blindly refreshing hashes.

## Proposed operator flow and acceptance checklist

Proposed command group: `blastcontain-drill-suite` with `plan`, `accept`, `run`,
`inspect`, `verify`, `cancel` and `rerun`. `accept` records a local explicit decision
on the reviewed digest and scope; it is not an organizational approval policy.
Planning emits human-readable diagnostics plus machine-readable data; failures have
nonzero exit codes suitable for CI. Existing `blastcontain-drill` flags stay valid.

The initial example suite includes benign task controls, resistant and vulnerable
synthetic agent targets, MCP description and response cases, deterministic transforms,
the reference worker and a recording attacker. Include expected outcomes and explain
which observations are synthetic, container-observed or live-model outputs.

Release gate:

1. Resolve the current review findings and pass fresh checks in dependency order.
2. A reviewed lock runs the complete fixture suite and accounts for every case.
3. Attempts, performed effects, containment, utility and missing coverage are distinct.
4. Budget/cancellation/cleanup adversarial tests pass, including sustained output floods.
5. Report tampering and secret-leak tests pass; offline reduction is reproducible.
6. Clean packaging and supported-platform CI pass without treating skips as coverage.
7. Run a small local-model suite with a configured abliterated attacker when available;
   record actual model identities, settings, caps and repetitions. If unavailable,
   leave live-model validation visibly pending rather than claiming it passed.

The UI, Scout's richer review workflow, remote monitoring/Charter graph and further
external frameworks remain later milestones. They consume this service and evidence
model instead of creating separate execution paths.
