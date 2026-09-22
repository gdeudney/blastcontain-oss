# Host-owned model conversations (phases 4B1–4B2)

`suites.conversations.ModelConversation` is a Python service for bounded attacker
and evaluator model history. The host chooses the run, case, model channel,
initial system message and limits. Callers can then submit a user prompt against
an opaque checkpoint. Only the host-observed model response becomes assistant
history. A prompt containing serialized roles remains user text.

API 2 workers can now use these sessions through separately accepted conversation
and branching routes. Suite execution closes every session and retains its sanitized
graph in signed run schema 2. API 1, PAIR and static PyRIT keep their existing behavior.
[Controlled Agent checkpoints](agent-checkpoints.md) now provide a separate target
route. The [bounded Crescendo adapter](../plugins/pyrit/CRESCENDO.md) uses both
routes. MCP state restoration remains unsupported.

## Service example

After constructing a `ModelBroker` with accepted model settings and an active
case `Ledger`, trusted host code can use:

```python
from blastcontain_drill.suites.conversations import ConversationLimits, ModelConversation

conversation = ModelConversation(
    broker,
    ledger,
    run_id=run_id,       # the current generated run ID
    case_id=case_id,     # the current planned case's sha256 identity
    channel="attacker",
    system_message=reviewed_attacker_system_message,
    limits=ConversationLimits(max_attempts=6, allow_branching=True),
)
try:
    first = await conversation.send(conversation.root, "Propose a controlled test prompt.")
    second = await conversation.send(first.checkpoint, "Refine using the observed feedback.")
    alternate = await conversation.send(first.checkpoint, "Try a different refinement.")
finally:
    conversation.close()
```

Branching changes the next model request's history. It retains both previous
responses in host state and keeps every prior model-call charge and audit event.
It never repeats an earlier HTTP request to reconstruct history. The caller
must first cancel and await an active dispatch before closing the conversation.
There is no automatic retry, branch, reset, budget refill or provider fallback.

## Enforced boundaries

- A checkpoint is scoped to one in-memory session. Identical run/case/model
  settings in another session do not make its checkpoints valid.
- The run, case, model settings and limits are bound into an opaque scope digest.
  A changed model binding or replaced case ledger invalidates further sends.
- Only attacker/evaluator channels are accepted. A real target conversation must
  also preserve its tool, canary, environment and observation state; a model-only
  history cannot establish those properties.
- Branching is disabled by default. Without it, only the latest completed
  checkpoint can advance. With it, earlier checkpoints remain available but the
  shared case/global ledger remains authoritative across all branches and channels.
- One dispatch may be active in a session. A concurrent send or close fails.
  Cancellation/failure is retained as an event and cannot publish a checkpoint.
- Defaults allow 32 attempts and 64 KiB per full serialized history. Bounds are
  1–64 attempts, 1–128 KiB of history and 32 KiB per submitted prompt. Attempts
  that reach the broker count toward the session cap even if dispatch fails or
  the shared budget refuses the call. Pre-dispatch malformed/foreign requests
  cannot call the model. Existing broker output/token/transport limits apply.
- History overflow never silently truncates messages. If a returned response
  exceeds the history bound, its digest and charged call remain recorded, but
  no checkpoint is created. The host must treat the operation as failed.

Session history is sensitive and remains in memory unless raw model traces are opted in. `close()` drops its retained
references; this is not a guarantee of cryptographic memory erasure. Events contain
opaque scope/checkpoint identifiers, request/response digests, sequence and status,
without prompts, responses, system text or exception text. They are host audit
records. Suite execution binds them to the signed run and model-call ledger; they
are not security assessments. Target outcomes still come from host-observed target
evidence. The broker's optional raw trace callback obeys the run retention policy.

## API 2 worker use

Set `adapter_api: 2` in the manifest and use `serve(plugin, protocol=2)` in the
container. A changed manifest/image requires fresh plugin acceptance and a new
accepted suite plan/lock. Permissions are separate:

| Scope | Grants |
| --- | --- |
| `broker.attacker` / `broker.evaluator` | Existing one-prompt calls only |
| `broker.attacker.conversation` / `broker.evaluator.conversation` | Open, append user turns, close |
| `broker.attacker.branch` / `broker.evaluator.branch` | Send from an earlier checkpoint; requires the corresponding conversation grant |

The worker chooses an initial system message only for its explicitly granted
attacker/evaluator model. It cannot change the target system message, model endpoint,
credentials or settings, import assistant history, or invoke a target checkpoint.
For example, inside `execute`:

```python
opened = broker.conversation("attacker", {
    "operation": "open", "system_message": "Propose controlled test prompts.",
    "branching": True,
})
reply = broker.conversation("attacker", {
    "operation": "send", "conversation": opened["conversation"],
    "parent": opened["checkpoint"], "prompt": "Generate the first test.",
    "max_tokens": 512,
})
broker.conversation("attacker", {
    "operation": "close", "conversation": opened["conversation"],
})
```

The route accepts exactly these fields. Handles are bound to the current worker
reset, case, run and model channel. A worker reset invalidates previous handles;
close/reset cannot refund calls or session allocations. Routes allow four sessions
cumulatively, with 32 attempts and 64 KiB history each. Opening reserves 4096
artifact bytes and each send reserves 2048 for bounded audit metadata. Every wire
operation consumes the worker call/message budgets; model dispatches also consume
the shared case/global model ledger. Suite API 2 workers allow at most
`min(1000, 3 * case_model_calls + 8)` wire calls, within the same wall-clock cap.

Signed envelopes retain only scope hashes, graph edges, checkpoints, status and
request/response hashes. Each observed model call names its conversation scope and
sequence. Offline verification checks the graph, accepted branching, run/case/model
binding, closure and corresponding model records in both directions. Missing
conversation events or calls reject verification, including on re-signed records.
Raw text remains opt-in and expirable. Schema 1 runs remain readable; schema 2 is
required for these audits. This does not assert independent replay of an LLM's
behavior or rollback of real external effects.

## Crescendo validation and remaining live gate

The worker route and signed model graph are implemented. The separate
[Agent checkpoint route](agent-checkpoints.md) preserves synthetic tool state,
retains every target attempt and requires original checkpoint data for replay.

The [pinned Crescendo adapter](../plugins/pyrit/CRESCENDO.md) now compares native
and adapted histories, refusal/backtrack behavior and retry calls using controlled
models inside the restricted image. It uses original reviewed templates; bundled
upstream datasets remain removed. The separate bounded live gate remains pending.
