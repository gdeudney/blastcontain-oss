# Host-owned model conversations (phase 4B1)

`suites.conversations.ModelConversation` is a Python service for bounded attacker
and evaluator model history. The host chooses the run, case, model channel,
initial system message and limits. Callers can then submit a user prompt against
an opaque checkpoint. Only the host-observed model response becomes assistant
history. A prompt containing serialized roles remains user text.

This foundation is not wired into the plugin protocol, CLI, suite execution or
durable envelopes yet. It does not enable Crescendo, arbitrary editable target
history, or Agent/MCP state restoration. Existing PAIR and static PyRIT behavior
is unchanged.

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

History is sensitive and exists only in memory here. `close()` drops its retained
references; this is not a guarantee of cryptographic memory erasure. Events contain
opaque scope/checkpoint identifiers, request/response digests, sequence and status,
without prompts, responses, system text or exception text. They are host audit
records, **not** signed evidence or security assessments. The broker's optional
raw trace callback still obeys its configured retention policy.

## Remaining 4B work and acceptance gates

1. Add an explicitly versioned worker conversation route and separately reviewed
   access scopes. Old single-prompt grants cannot silently gain history editing.
   Reject forged/cross-case handles and unsupported messages before dispatch;
   enforce the same worker, case and suite budgets.
2. Add a persistent controlled Agent fixture with host-owned checkpoints. Fork
   only state that can be faithfully snapshotted in the controlled fixture.
   Preserve all observed actions, including abandoned branches. Never rerun a
   prefix to simulate rollback or claim support for external irreversible effects.
3. Bind conversation/checkpoint metadata to durable attempt evidence and replay.
   Missing or altered history must prevent verified success. Keep raw conversation
   inputs opt-in and expirable; stopping must close the fixture and worker.
4. Adapt pinned PyRIT Crescendo to those routes. Compare actual upstream and
   adapted histories, refusal/backtrack behavior and model calls using recording
   models before the separate bounded live gate. Review any required upstream
   templates independently; the static image deliberately excludes bundled data.

The foundation tests cover exact history, mutable transport input, foreign
checkpoints, changed bindings/ledgers, branching, shared budgets, failed dispatch,
concurrent sends, active cancellation, history overflow and unsupported target
sessions. Passing them is not a claim that the remaining integration is complete.
