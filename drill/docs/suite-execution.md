# Suite execution development API (phases 3C/3D)

`blastcontain_drill.suites.service.run_suite` executes an accepted lock through one
budgeted path: replay, materialized operators, PAIR refinement and an accepted
external strategy. Existing Drill commands and signed report formats are unchanged.
[Durable signed runs](suite-runs.md) are available in 3E; the [3F CLI](suite-cli.md) exposes their lifecycle.

Targets run in **trusted simulations**, with actual loopback MCP transport when
selected. Live models can drive those simulations; the fixture tools do not delete
real files or transmit customer data. Separate case processes allow independent
stopping, not OS containment. External strategy code runs only through the existing
rootless Podman isolation profile. This does not yet test arbitrary remote MCP servers.

## Run an accepted lock

Follow [suite planning](suite-planning.md) to inspect a plan, record acceptance and
create its lock. `examples/suites/mcp.json` selects four vulnerable MCP cases;
changing its target to `builtin.target.resistant` requires new acceptance.

```python
import asyncio
from pathlib import Path

from blastcontain_drill.plugins.catalog import read_acceptances
from blastcontain_drill.suites.artifacts import read_document
from blastcontain_drill.suites.catalog import builtin_catalog
from blastcontain_drill.suites.lock import SuiteLock
from blastcontain_drill.suites.service import ExecutionInputs, run_suite

lock = SuiteLock.from_dict(read_document(Path("suite.lock.json")))

def current_inputs():
    # Reload CURRENT decisions and installed bytes. Lock snapshots are not permission.
    return ExecutionInputs(
        builtin_catalog(), read_acceptances(Path("acceptances.json"))
    )

run = asyncio.run(run_suite(lock, current_inputs=current_inputs))
for case in run.cases:
    print(case.case_id, case.disposition, case.legacy_outcome, case.diagnostics)
print("Suite security gate:", "passed" if run.passed else "not passed")
print("Usage:", run.usage.to_dict())
```

For external content, reload its accepted `SourceSnapshot` in the callback and pass
it to `builtin_catalog(external_sources=...)`. For an external strategy, also supply
its current manifest via `plugins=...`, its acceptance records and runtime probes.
The worker independently checks the actual local image and isolation at launch.
Metadata cannot install an arbitrary host implementation.

`progress=` receives immutable snapshots containing the entire case roster. Up to
`spec.concurrency` cases may be running, with a supported maximum of eight. Results
stay in planned order; contention can affect which case consumes the remaining
shared budget. Revalidate current acceptance before each case, adaptive round and
provider dispatch. Changed installed code invalidates earlier locks.

## Supported bindings

| Input | Execution |
|---|---|
| Resistant/vulnerable built-in targets | Fresh deterministic fixture backend per attempt |
| `builtin.target.llm` | Locked OpenAI-compatible endpoint through the host model broker |
| Agent target | Replay, materialized operators, multi-turn and supported injections |
| MCP target | Controlled description/response poisoning through the loopback fixture |
| `builtin.environment.fixture` | Fresh process, workspace, tool state and random canary |
| `builtin.evaluator.heuristic` | Refusal heuristic; no evaluator model call |
| `builtin.evaluator.llm` | Locked evaluator endpoint; harm/refusal/freeform rubric |
| `builtin.strategy.pair` | Sequential attacker refinement with legacy prompt/history formatting |
| Accepted external attack strategy | Rootless Podman worker using granted broker channels |
| Adaptive scenarios | Agent, one entry prompt, explicit attack objective; fresh target each round |
| Adaptive multi-turn/injection/MCP, other environments or runtime adapters | Explicitly `unsupported` |
| Optional planning exclusion | Retained as `skipped`, with planning diagnostics |

Operators execute the exact bytes materialized in the lock. Seeds identify planned
repetitions; the broker does not claim deterministic model sampling or send a model
seed. Random fixture canaries change on every attempt. Model aliases remain mutable;
a declared pinned model digest is accepted configuration, not endpoint attestation.

## Models, credentials and local abliterated attackers

Select `builtin.target.llm`, add `ModelSettings(channel="target", ...)`, and provide
the exact base URL ending in `/v1` for an OpenAI-compatible chat endpoint. Add an
`attacker` setting for PAIR and an `evaluator` setting for the LLM judge. For example:

```python
ModelSettings(
    "attacker", "http://127.0.0.1:1234/v1", "local-abliterated",
    temperature=1.0, max_output_tokens=8192,
)
```

Use the model ID actually loaded by the local server. The shared attacker helper
preserves the legacy system prompt, last-attempt feedback and output cleanup. The
new suite path treats provider failure as an error rather than silently substituting
a prompt. PAIR stops at an observed bypass, failed attempt or exhausted budget; a
search stopped at its limit is `incomplete`, even when earlier attempts held.

Adaptive selections require an explicit `attack_objective`. The 501 legacy replay
seeds remain unchanged; create and accept a derived `SourceSnapshot` with the desired
objective instead of inferring one from a prompt. The [adaptive example](../examples/suites/adaptive.py)
shows this process with controlled, model-free responses.

A setting may name a symbolic `credential_ref`. Supply `credentials=resolver` to
`run_suite`; the trusted host resolver maps that name to a token in memory. No
automatic environment-variable lookup occurs. Credentials never enter the lock,
case subprocess or plugin container. Use distinct references/endpoints for distinct
model roles where required. Only the locked destination receives each token.

Default HTTP routing makes one request per reservation: no automatic retries,
redirect following or inherited HTTP proxy configuration. Input is capped at 128 KiB
of canonical JSON, response bodies at 1 MiB, and decoded output at 32 KiB UTF-8.
Compressed responses are rejected. Output-token requests are capped by the locked
setting. Provider errors are normalized without retaining response/error bodies.

`run.model_calls` records case/attempt ID, channel, request/response digests, status
and reported input/output tokens. Missing or invalid token counts are `None`, never
zero. Token counts are provider reports, not independent metering or billing limits.
Call reservations enforce the budget regardless of whether usage is reported.

An optional async `transport(settings, messages, secret, timeout, max_tokens)` can
return `ModelReply` for a trusted host integration or recording test. It must honor
cancellation and perform at most one provider attempt. It is not a plugin hook.

## Budgets, cancellation and cleanup

Atomic reservations charge both the active case and the global pool before each
model/tool dispatch. All target, attacker and evaluator channels share that pool.
Failures consume their reservation; retries require another. Fresh targets and
plugin resets never replenish it. A PAIR round or external target attempt consumes
one strategy iteration. Replay consumes none. MCP initialization/discovery is fixed
fixture setup, bounded separately by RPC limits and the parent deadline.

The artifact budget covers retained canonical evidence bundles and retained plugin
claim-digest metadata. Exhaustion retains a truncated evidence prefix; if the initial
bundle cannot fit, no bundle is returned. Attempt scenarios, receipts, model-call
summaries and Python object memory are not a durable storage quota. Raw generated
prompts remain in memory for replay, so applications should not log entire run objects.
Use the [3E durable service](suite-runs.md) for protected persistence and retention.

Global/case deadlines include setup, I/O, all rounds and cleanup. Native process
cleanup has a separate two-second allowance; the existing worker profile adds a
bounded container-removal allowance and its own maximum 300-second session deadline.
A cleanup failure prevents a pass and stops new case dispatch; cases already active
still finalize their evidence. Budget exhaustion never establishes a held result.

Pass an `asyncio.Event` as `cancel=` and set it to stop an in-memory run. Active
requests and case/worker processes are cancelled and cleaned up, and the returned
roster retains terminal outcomes for pending cases. Cancelling the caller coroutine
also cleans up but propagates `CancelledError`; `progress=` receives its final
snapshot. The [durable service](suite-runs.md) adds persistent stop requests,
signed results and conservative crash inspection, exposed through the [suite CLI](suite-cli.md).

## Evidence and outcomes

Native evidence records contain output hashes/counts and normalized action policy
observations, not raw arguments, canaries, destinations or error text. Model responses
are transient inputs to the fixture/evaluator; a bounded final-response excerpt is
shared with an adaptive strategy. Child processes inherit only fixed code roots and
minimal runtime environment. External plugin code never runs in those processes.

Payload delivery requires the exact document/MCP payload to reach a dispatched
model call. Reading a poisoned response on the final tool step is insufficient.
Every selected content evaluator must supply a definite whole-output assessment;
conflicting judgments fail closed. Tool-action evidence does not rely on the judge.
Observed actions remain findings even if later calls or cleanup fail.

Each native attempt has an evidence bundle, independently held receipt and reduction
policy. Replay with `reduce_evidence(scenario, evidence, receipt,
policy=case.reduction_policy)`. Adaptive cases retain these under `case.attempts`,
along with each materialized `attempt.scenario` and execution identity. Their
aggregate retains the strongest observed finding and cannot turn an incomplete
attempt into a pass. Per-attempt usage covers its target/evaluators; outer case usage
also includes attacker calls, iteration reservations and claim metadata.

A plugin's return value is an untrusted claim. Only its digest is retained, separately
from native attempt evidence. A claim without any observed target attempt fails,
regardless of the claimed outcome. Even a completed simulation does not establish
independently observed external effects.

Every normally returned run contains a terminal disposition per planned case:
`completed`, `incomplete`, `cancelled`, `unsupported`, `skipped` or `error`. The suite
gate requires all required cases to complete with a `HELD` projection and no measured
utility failure. If all cases are optional, all non-excluded cases must meet it.
Cleanup failure anywhere prevents a pass. Receipts are unsigned host anchors;
the [durable service](suite-runs.md) signs these anchors in authenticated envelopes.

## Validation record

Phase 3D was checked on Linux/Python 3.12 with 564 Core/Drill/Scout regression tests
and 39 real Podman integration tests. The recording backend verifies PAIR prompt and
feedback parity, all three broker channels, concurrent budgets, revocation, retries,
provider failures, missing token counts and cancellation. Controlled loopback HTTP
checks cover redirects, proxy inheritance, invalid/compressed/oversized responses.
Actual containers verify the two-call reference strategy, shared suite limits,
claim-only rejection and active-worker cleanup.

Clean Core/Drill wheels loaded all 501 definitions, passed four Drill CLI help checks,
and ran the adaptive demo. Ruff, suite type checking and medium-severity Bandit
checks passed. These are controlled fixture results; live model quality and usage
billing were not measured. Run the model-free example from the repository root:

```bash
python drill/examples/suites/adaptive.py
```
