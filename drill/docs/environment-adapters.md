# Reviewed simulation environments (worker API 3)

An environment owns simulated state and observes tools; an attack strategy supplies
adversarial inputs. Those authorities are different. API 3 supports a separately
reviewed environment/evaluator plugin with **only** `broker.environment` access.
API 1/2 attack workers cannot acquire this route. The host never imports framework
code; [AgentDojo banking](../plugins/agentdojo/README.md) is the first implementation.

## Selection and trust

The manifest must use `adapter_api: 3`, exactly the `environment` and `evaluator`
roles, and capabilities `environment.stateful.v1`, `task.utility`,
`observe.model_output`, `observe.tool_actions`, `observe.payload_delivery` and
`fixture.<supported-fixture-id>`. It must also advertise its prompt/injection
capabilities. Plugin/image acceptance, content acceptance, runtime availability
and exact suite acceptance remain separate gates.

The suite explicitly selects that plugin as `environment` and its sole evaluator,
with `target.kind: agent` and `target.binding: builtin.target.llm`. Each scenario
requires one supported fixture, a legitimate task, `task_checks: [utility]`, a
`state_violation` security goal and at most one nonempty document injection.
Adaptive strategies, multi-turn scenario definitions, branching, MCP targets and
other environment bindings are rejected. The environment can make sequential
model/tool turns within the shared case budgets; scenario seeds identify repeated
cases, not guaranteed deterministic model behavior.

Acceptance of this role explicitly trusts the pinned plugin's state/oracle
implementation **for a simulation**. It does not make an upstream label independent
proof of external effects. Final `WorkerResult.claims` remain untrusted summaries;
they cannot replace missing observations, task checks or completion. This profile
never emits external `Effect` evidence. An environment with a malicious oracle can
lie about its own simulation, so image/source review and native parity are necessary.

## Protocol and lifecycle

Use the existing SDK lifecycle with `serve(plugin, protocol=3)` and
`broker.environment(payload)`. Each request is an API 3 `environment` frame on the
fixed `environment` channel; ordered session-wide request/call IDs and frame limits
still apply. During one execute/reset scope, operations have these exact fields:

| Operation | Payload fields besides `operation` | Host behavior |
|---|---|---|
| `start` | `state_digest` | Records initial state once; cannot refill a budget |
| `model` | `messages` | Calls the locked target with host credentials/token cap; observes actual output |
| `reserve_tool` | `tool`, `arguments`, `before_digest` | Matches actual model command/current state; charges before effect; returns opaque `ticket` |
| `observe_tool` | `ticket`, `after_digest`, `output`, `attack_success` | Consumes one ticket, hashes result/state and records a positive simulation oracle finding |
| `finish` | `utility_success` | Requires final model response and no pending tool; records utility and complete coverage |

`model` returns `response_text`. The host requires exactly one JSON object:
`{"tool":"name","arguments":{...}}` or `{"final":"answer"}`. It rejects malformed
JSON, duplicate/extra fields and another model call before the previous command
is consumed. Model endpoint, credentials, roles and output budget cannot be chosen
by the worker. Tool names/arguments are additionally restricted by the adapter.
Tool output is capped at 32 KiB. State digests use SHA-256.

Record attack-oracle results after each action so a later rollback/failure cannot
erase observed harm. Only `finish` records final utility. State observations form
an ordered before/after chain; offline reduction rejects broken chains. Tool
operation digests bind command and response hashes. Exposure is recorded only when
the selected payload reaches a real host model request. Missing exposure/checks
cannot establish `held`; a cancelled run keeps its stop reason and partial findings.

The host controls model/tool/artifact/wall limits, rechecks current acceptance on
each operation, and independently stops/removes the container. One reservation is
active at a time. State, scope and tickets cannot be reused across cases. Each
case gets a fresh container under the unchanged [worker containment profile](plugin-workers.md).
An image has no direct provider network or credentials.

## Author validation

An additional environment needs native versus adapted state/oracle trajectories,
benign task success/failure, attack success, simultaneous task/attack success,
malicious input parsing, fresh reset/concurrent state, cancellation, shared limits,
unsupported inputs, partial harm retention and signed offline replay. Run the
generic worker conformance suite as well. Passing adapter tests does not establish
attack effectiveness against a live model or authorize production targets.

Existing API 1/2 workers and signed schema-3 runs remain readable. New observations
require this reader version; older readers reject their unknown payload types.
Installed-code digests change, so executable locks must be regenerated and reviewed.
