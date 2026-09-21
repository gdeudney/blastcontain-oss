# Fixture suite execution (phase 3C)

The development API `blastcontain_drill.suites.service.run_suite` executes replay
and materialized operator cases from an accepted lock. It supports the resistant
and vulnerable built-in agents, the controlled MCP description/response fixtures,
single/multi-turn prompts and document injection. It uses the phase 3B evidence
collector and reducer. Existing Drill commands and signed report formats are unchanged.

This milestone runs **trusted simulations**, with actual loopback MCP transport.
A separate case process allows the parent to stop a hung fixture; it is not an OS
sandbox or proof of container containment. No real files are deleted and the
fixture's send tools do not transmit data. Real model bindings, adaptive attacks
(including local abliterated attackers) and external workers join this execution
path in 3D. Their existing legacy commands remain available.

## Run an accepted fixture lock

Follow [suite planning](suite-planning.md) to inspect a plan, record acceptance and
create its lock. Use `examples/suites/mcp.json` for four vulnerable MCP cases;
changing its target to `builtin.target.resistant` requires a new plan and acceptance.

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
    # Read CURRENT decisions and installed bytes at each revalidation.
    # Historical acceptances embedded in the lock are never execution permission.
    return ExecutionInputs(
        builtin_catalog(), read_acceptances(Path("acceptances.json"))
    )

run = asyncio.run(run_suite(lock, current_inputs=current_inputs))
for case in run.cases:
    print(case.case_id, case.disposition, case.legacy_outcome, case.diagnostics)
print("Suite security gate:", "passed" if run.passed else "not passed")
print("Usage:", run.usage.to_dict())
```

For reviewed external *data*, the callback must also reload its `SourceSnapshot`
and supply it to `builtin_catalog(external_sources=...)`. Arbitrary runtime bindings
and plugin code do not become executable by appearing in catalog metadata.

`progress=` optionally receives immutable `SuiteRun` snapshots: the first contains
the entire pending roster, subsequent snapshots show one running case at most and
terminal outcomes. This roster and the returned evidence stay in memory. There is
no durable run store, crash resume or advertised suite `run` command yet; those are
3E/3F deliverables. A caller cancelling the coroutine stops/reaps its active child;
durable cancellation and terminal records for cancelled pending cases remain in 3E.

## What runs and what fails explicitly

| Input | Current execution |
|---|---|
| `builtin.target.resistant` / `builtin.target.vulnerable` | Fresh deterministic fixture backend for each case |
| Agent target | Replay, materialized operators, multi-turn and supported injections |
| MCP target | Controlled poisoned descriptions/responses through the loopback fixture |
| `builtin.environment.fixture` | Fresh process, workspace, tool state and random canary |
| `builtin.evaluator.heuristic` | Host-selected refusal heuristic; no evaluator model call |
| Accepted operator scenario | Executes exact materialized prompt bytes; never regenerates them |
| Live target/model settings, adaptive strategy, plugin or other binding | `unsupported`; no substitute backend or model request |
| Concurrent execution | `unsupported`; serial execution only in 3C |
| Optional planning exclusion | Retained as `skipped`, with its planning diagnostics |

Case `execution_identity` binds its planned ID, exact scenario bytes, seed and
replay/operator mode. The lock already binds source revision, build identity and
materialized content. Seeds distinguish planned repetitions; the current fixture
backend has no stochastic sampling. Fresh random canaries intentionally differ on
every execution. Changed installed code invalidates earlier locks.

## Budgets and independent stopping

The parent owns one global ledger and one active case ledger. Every target call
and tool operation requires a reservation **before dispatch**. Reservations are
not refunded after failures, and no implicit retry occurs. Global usage survives
case changes and environment replacement. Operators were materialized during
planning, so replay performs zero adaptive strategy iterations.

The model/tool counters cover agent dispatches. MCP initialization/discovery is
fixed fixture setup, bounded by the fixture's RPC limits and the parent deadline;
each agent-requested MCP tool call consumes a tool step. The heuristic evaluator
uses no model calls. All provider/attacker/evaluator model routing follows in 3D.

The artifact budget covers canonical retained evidence-bundle bytes, including
producer metadata and terminal records. Exhaustion preserves a truncated prefix;
if even the initial bundle cannot fit, no evidence bundle is returned. It never
produces a held result. Summaries, receipts and Python object memory are not a
durable storage quota; protected run storage belongs to 3E. The collector's own
record/byte ceilings apply in addition to the suite budgets.

Wall deadlines include launch and case I/O. The parent can kill a child that does
not cooperate; process/pipe cleanup has a separate bounded two-second allowance.
Fixture cleanup errors stop further case dispatch. A failed workspace removal is
reported rather than treated as clean. New cases are not launched after global
model-call, evidence-byte or wall-time exhaustion.

## Evidence and outcomes

Output records are hashes/counts. Action records contain policy classifications
and blocking observations, not raw arguments, canaries, destinations or error text.
The child inherits the fixed Python code roots and minimal runtime environment,
not provider credentials or arbitrary `PYTHONPATH`. Case processes are trusted
built-in code and are never used to execute externally supplied plugin modules.

Payload delivery is recorded only when the exact document/MCP content has reached
a dispatched target call. Reading a poisoned response on the final available tool
step does not prove exposure. A resistant agent that never reads an injected
document remains `incomplete` for that injection. The broad Agent example may also
report benign refusals; a resistant fixture is not promised to pass every case.

Every normally returned run contains one terminal record per planned case:
`completed`, `incomplete`, `unsupported`, `skipped` or `error`. Diagnostics distinguish
budget resource/scope, missing exposure, failed backend, failed preparation,
evidence errors, revoked acceptance and cleanup failure. Missing scoring after an
earlier stop preserves that stop; an actual conflicting/indefinite assessment is
still an error. Observed attempts survive later budget or process failure.

The suite gate requires every required case to complete with a `HELD` projection
and without measured utility failure. If all cases are optional, every non-excluded
case must meet that condition. Cleanup failure anywhere prevents a pass. Optional
excluded cases stay in the roster. This gate does not promote unmeasured utility
to success or simulated tool responses to independently observed effects.

Each returned case includes its `EvidenceBundle`, independently held `EvidenceReceipt`,
separate result dimensions and usage. Offline reduction of those records reproduces
the result. Receipts remain unsigned host anchors; authenticated run storage,
retention, inspect/cancel/rerun and signing are phase 3E.
