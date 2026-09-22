# Controlled Agent checkpoints (phase 4B3)

API 2 strategies can maintain and branch the built-in synthetic Agent fixture.
The host keeps the actual message history, planted canary, observed tool-call log
and egress-attempt log. A branch restores an earlier snapshot directly; no earlier
model or tool call is replayed. Every executed turn remains a separate target
attempt, including attempts on abandoned branches. Suite reduction considers all
of them and never refunds budget or hides an observed forbidden action.

## Accepted scope and operations

Request `broker.target.conversation` in the manifest. Request
`broker.target.branch` as well if earlier checkpoints must remain selectable.
These are new grants requiring a reviewed manifest/image and a newly accepted
suite lock. `broker.target` alone keeps its existing one-prompt behavior.
The worker uses `serve(plugin, protocol=2)`:

```python
opened = broker.conversation("target", {"operation": "open", "branching": True})
first = broker.conversation("target", {
    "operation": "send", "conversation": opened["conversation"],
    "parent": opened["checkpoint"], "prompt": "A controlled first turn",
})
continued = broker.conversation("target", {
    "operation": "send", "conversation": opened["conversation"],
    "parent": first["checkpoint"], "prompt": "A follow-up turn",
})
alternate = broker.conversation("target", {
    "operation": "send", "conversation": opened["conversation"],
    "parent": first["checkpoint"], "prompt": "An alternative follow-up",
})
broker.conversation("target", {
    "operation": "close", "conversation": opened["conversation"],
})
```

Replies expose the resulting opaque checkpoint, final response text and advisory
legacy outcome. The worker cannot submit system/assistant messages, raw state,
canaries, file paths, credential settings or a different environment. Unsupported
fields and foreign handles fail before target dispatch. Handles belong to one
worker reset, case and run; closing cannot reopen or refill a session.

One Agent session and at most 32 sends are allowed per case. The accepted
`strategy_iterations`, model/tool counters and wall clock usually impose lower
limits. Open reserves 4096 artifact bytes, send reserves 2048, and retaining a
resulting fixture state charges its serialized size. Each snapshot is capped at
128 KiB. Overflow fails explicitly instead of dropping history. The worker's
existing protocol call/message limits also apply.

## Execution and limits

The Agent state persists in its host-owned session. Each turn runs fixed trusted
fixture code in a fresh child process, initialized from that state and reaped
before returning a checkpoint. This permits independent cancellation and avoids
rerunning a prefix to reconstruct history. A failed/cancelled turn creates no new
checkpoint; its observations and charges remain in the report.

The supported environment is `builtin.environment.fixture`, target kind `agent`,
with one plain prompt per send. Its `read`, `send`, `http_get` and destructive-tool
responses are synthetic. They do not write real customer records or send network
requests. The default policy, canary and previous tool observations survive
restoration. Tool actions are simulation observations, not independent proof of
external effects. These trusted child processes are not an OS sandbox; external
strategy code still runs in the rootless, network-disabled Podman worker.

MCP state, poisoned-document/catalog fixtures, custom environment/task fixtures,
arbitrary target-system editing and real irreversible effects are unsupported.
A real environment adapter must establish its own faithful snapshot/reset
contract before advertising checkpoints. Crescendo integration remains a separate
adapter/parity gate; this service alone does not claim that strategy is complete.

## Signed evidence and replay

Run schema 3 adds Agent graphs and input/output state digests to each observed
attempt. Graphs bind the run, case, accepted lock, worker reset, branch permission,
turn order, prompt and exact state. Offline verification requires every stateful
attempt to appear in the graph and every graph turn to have matching target
evidence. The strongest outcome from all attempts remains authoritative.
Schema 1 and 2 reports remain readable.

Raw state includes synthetic canaries, prompts and tool responses. It is omitted
by default. To replay a stateful run, either opt into the existing
`--raw-retention-seconds` policy, or separately retain its original scenario and
checkpoint maps. Expired state is unreadable and `purge-raw` deletes it under the
same signed retention policy as other raw artifacts. A signed report without
required history is intact but unreplayed, and cannot attest success.

The Python verifier accepts `states={state_digest: FixtureState(...)}` alongside
adaptive `scenarios`. The CLI equivalent is:

```bash
blastcontain-drill-suite verify RUN_DIRECTORY --trusted-key public.key \
  --lock original.lock.json --scenarios original-scenarios.json \
  --states original-checkpoints.json
```

The checkpoint JSON is an object mapping state digests to the original serialized
`FixtureState` records. Treat these input files as sensitive. Hashes, signatures,
state-prefix checks and graph checks apply to supplied data as they do to retained
artifacts. No model or tool is executed by verification.
