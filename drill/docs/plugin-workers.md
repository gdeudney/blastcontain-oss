# Plugin discovery and bounded workers — phase 2

Drill can now discover reviewed metadata without importing plugin code and run an
explicitly selected external plugin in a bounded local Podman container. This is
an additive API and diagnostic command. The existing agent/MCP CLI, generative
attacker and signed reports still use their current execution path.
[Suite planning](suite-planning.md) and [evidence reduction](evidence-reduction.md)
are now additive APIs; suite execution, real upstream adapters and the acceptance UI
remain later phases.

## Discovery and acceptance

`blastcontain-drill-plugins --directory DIR [--acceptances FILE] [--probe-runtime]`
reads only `*.drill-plugin.json` files in explicit directories. It never imports
Python entry points, starts a plugin, installs a package or pulls an image.
`--probe-runtime` only checks local runtime requirements and image presence.

Each file contains a [schema-1 PluginManifest](contracts-v1.md). In this profile,
`artifact_digest` is a complete local Podman **image ID** (`sha256:` plus 64 lowercase
hex digits), not a tag or a registry URL. The entry point and its dependencies are
inside that image. There is no host command or additional container-argument field.

Diagnostics report these independently:

| Field | Meaning |
|---|---|
| installed | A metadata file is registered in the selected directory |
| compatible | Its schema/API/profile is supported and the plugin ID is unique |
| accepted | A current explicit decision matches all reviewed metadata and requested access |
| available | The local Linux rootless Podman profile and exact image are available; false if not probed |

Invalid files remain visible with diagnostics. Duplicate IDs are incompatible;
Drill does not pick whichever version happens to be found first. Unknown schema/API
versions, duplicate JSON keys, nonfinite numbers, symlinks, non-regular files and
metadata larger than 64 KiB are rejected.

Acceptance files have `{"schema_version": 1, "records": [...]}`. Each record uses
`AcceptanceRecord`, with `kind="plugin"`. Its digest is `review_digest(manifest)`:
SHA-256 over canonical JSON of the **entire manifest**, including the image ID,
capabilities, license/notices and requested access. It is deliberately different
from the image ID. Changing any reviewed field invalidates the old acceptance.

File order is authoritative: the last decision for a plugin wins, including rejection
or revocation. All requested grants must match the record's grants. A filename or
installed package alone grants nothing. Callers should load the current records and
use `catalog.select(...)` immediately before starting a worker; the worker also
validates its detached metadata/decision snapshot at startup. In-flight revocation
is not polled in this phase; the operator can independently cancel the worker.
Actor authentication, organizational roles and persistent review workflows belong
to the later acceptance integration. These records alone do not establish identity.
Plugin acceptance is also separate from attack-content approval and suite inclusion;
those gates will be enforced by the suite planner and later acceptance workflow.

## First execution profile

The initial profile intentionally supports only empty plugin configuration (`{}`)
and these explicit access requests: `broker.target`, `broker.attacker` and
`broker.evaluator`. Other access or nontrivial configuration schemas are rejected,
not silently ignored. Full schema validation and additional isolation profiles can
be added with their own conformance evidence.

Requirements are local Linux, rootless Podman, cgroup v2 with delegated memory/PID
controllers and seccomp support. Missing or unsupported isolation fails explicitly;
there is no host-process, virtual-environment or remote-engine fallback.

Before starting plugin code, Drill creates a stopped container and inspects its
image, user, mounts, privileges, namespaces, resource limits and timeouts. The profile
uses a read-only root, UID/GID 65532, no added capabilities, no new privileges,
private namespaces, no network, no host mounts/devices/engine socket, disabled
image volumes, disabled proxy forwarding and an explicit minimal environment.
Image health checks/systemd mode/restarts are disabled. Memory including swap is
limited to 256 MiB, processes to 64, and the private non-executable `/tmp` to 16 MiB.
This profile does not claim a CPU-rate quota; execution time is bounded separately.

The controller enforces a monotonic wall-clock deadline including setup, plus a
watchdog that stops idle workers. Podman's independent container timeout and
automatic removal provide a second stop mechanism when the Python watchdog is
unavailable. That engine timer uses whole seconds, rounded up from the remaining
budget before creation; it is a backup, not a millisecond-precise controller deadline.

Cancellation and failure immediately terminate/remove the container without asking
the plugin to cooperate. Cleanup drains both output pipes without retaining data,
including while the container is being removed. Control operations have a ten-second
execution limit followed by at most two seconds to reap their client; the attached
worker client has a separate two-second reap limit. Full pipes cannot extend these
waits indefinitely;
a cleanup failure is surfaced with the exact container name, never reported as a
successful cleanup. Successful close, timeout, malformed protocol and cancellation
paths are checked for leftover containers. Abrupt machine/power loss is outside
these process-lifecycle guarantees.

Runtime flags follow [Podman's documented container isolation and timeout options](https://docs.podman.io/en/latest/markdown/podman-run.1.html).
The local engine, kernel, image build and trusted host bindings remain part of the
trusted computing base. These fixtures validate the configured profile; they are
not a claim that containers eliminate every kernel or runtime vulnerability.

## Protocol and broker

The protocol uses version-1 JSON lines on stdin/stdout. Lifecycle requests carry a
strictly ordered request ID and method: `prepare`, `reset`, `execute`, `close`.
Plugins return a result/error or, during execute only, request a broker call.
Calls have a monotonically increasing session-wide ID, a declared channel and a
validated `Injection`. Unknown fields/types/versions, stale IDs and malformed or
oversized frames terminate execution.

Default limits are 30 seconds, four total broker calls, 128 total sent/received
messages, 64 KiB per frame and 16 KiB of standard error. Budgets belong to the host,
cover all channels, and survive scenario reset. Calls reserve budget before dispatch;
failed/cancelled attempts still count. Worker requests are serial; concurrent execute
requests are rejected. Direct network access cannot bypass the broker's counters.

A host binding is an explicitly supplied, trusted async callable accepting
`(Injection, BrokerContext)` and returning JSON data. It owns the endpoint, credentials
and target implementation; plugin payloads never select a host URL or executable.
The same mechanism can mediate target, abliterated-attacker and evaluator calls.
A binding must honor async cancellation and use the provided deadline for its I/O.
Blocking host code or code that suppresses cancellation is not an acceptable binding.
The container boundary applies to external plugin code, not to a malicious host binding.

`WorkerResult.claims` is untrusted plugin output. `WorkerResult.calls` contains the
host-observed channel, call ID, scenario, injection, response/error for that execute
request. `worker.calls` retains all session attempts, including failures. Responses
are observations, not proof of tool effects or security success. No upstream success
label is converted to HELD/BYPASS, utility or trusted `ScenarioResult` evidence here.
The [phase-3B collector/reducer](evidence-reduction.md) provides that interpretation
for host-owned observations. Feed worker result data through its untrusted claim path;
the worker protocol does not grant evidence authority. Raw observations
remain in memory unless a caller explicitly exports them; production redaction and
signed suite evidence are not implemented by this worker protocol.

## Authoring and validation

The [reference plugin](../plugins/reference/README.md) packages the stdlib-only SDK
inside its image. It demonstrates prepare/reset/execute/close and two feedback-driven
broker calls without adding a runner branch or a tool-specific CLI flag. The SDK is
convenience code for well-behaved plugins; host checks also cover plugins that ignore it.

The conformance tests cover inert discovery, stale/revoked acceptance, unsupported
configuration/runtime, duplicate IDs, byte limits and lifecycle order. Real containers
prove denied host file/network/credential/socket access, allowed broker traffic,
resource settings, session-wide budgets, replay rejection, incorrect IDs, malformed
output, stdout/stderr floods, early exit, hangs, cancellation, idle expiry and the
independent engine timeout. Existing cage/MCP checks run alongside them. The integration
job sets `DRILL_REQUIRE_WORKER_TESTS=1` so a missing runtime cannot masquerade as success.

```sh
PYTHONPATH=core:drill:tools/scout python -m pytest core/tests drill/tests/unit tools/scout/tests -q
PYTHONPATH=core:drill DRILL_REQUIRE_WORKER_TESTS=1 python -m pytest drill/tests/integration -m podman -q --timeout=45
ruff check core drill tools/scout
python -m mypy --follow-imports=silent --ignore-missing-imports drill/blastcontain_drill/contracts drill/blastcontain_drill/plugins
bandit -q -r drill/blastcontain_drill/plugins
```

CI now includes PRs targeting `codex/**` so this stacked milestone can be checked
before its prerequisites are merged. Local validation and GitHub CI results should
be reported separately. No real PyRIT/AgentDojo/garak integration or new live-model
validation is claimed by this phase.

Local validation on September 20, 2026 (Linux, Python 3.12.13, Podman 5.7.0):
**315** Core/Drill/Scout tests and **22** container checks passed, with the one live-model
test explicitly deselected. Ruff, contract/worker Mypy and worker Bandit passed.
Clean wheels retained all 501 attack definitions and passed all five CLI help checks
plus four installed MCP fixtures. The reference demo made two brokered calls, reported
registered/compatible/accepted/available independently, and left no worker container.

Review follow-up on September 20: **335** Core/Drill/Scout tests and **35** container
checks passed after the completion, publication-retry and worker-cleanup fixes; the
live-model test was deselected. Existing signed-report compatibility fixtures still
pass without refreshing their hashes. The new checks include sustained 16 MiB
stdout/stderr floods, floods during broker calls, explicit cancellation and automatic
deadlines, and real child-process backpressure on the controller's pipes. Cleanup
suppresses duplicate cancellation while a request is already terminating. Ruff,
contract/worker Mypy and worker Bandit passed; no test worker containers remained.
