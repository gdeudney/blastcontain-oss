# Guard usage guide

Guard enforces a policy on calls routed through its wrappers. It does not sandbox
Python or prevent a compromised process from calling resources directly. Use OS
isolation and independent resource access controls alongside it.

## Install and run

From the repository root, in an activated Python 3.11+ virtual environment:

```bash
python -m pip install -e ./core -e ./guard
cd guard
blastcontain-guard lint examples/policy.yaml
python examples/quickstart.py
```

The [policy](../examples/policy.yaml) allows invoice reads, asks before deletion,
and denies unapproved sends. The [quickstart](../examples/quickstart.py) uses mock
tools that only return text: it does not delete or send real data.

Expected flow:

1. `query_invoice` is allowed without a prompt.
2. `delete_invoice` asks `Allow delete_invoice once? [y/N]`. Enter `y` to permit
   the mock call, or press Enter to deny it.
3. `send_invoice` is denied without a prompt.

The example writes `decisions.jsonl` and `decisions.json` in the current directory.
The JSON file is a signed decision-log packet. Without a managed signing key it
uses an advisory signature: anyone with the public default key can re-sign it.
For trusted provenance, configure `BLASTCONTAIN_SIGNING_KEY_PATH` to a managed
Ed25519 PEM key and validate packets against a separately trusted public key.
Do not commit private keys or decision logs containing sensitive operational data.

## Connect real tools

Decorate the actual callable with `@guard.tool(action_type="delete")`, or use
an appropriate adapter. Explicit action types avoid relying on name inference.
`guard.check(...)` returns a decision result: the caller must honor `allowed`
before doing any work. `guard.evaluate(...)` and `guard.explain(...)` do not
execute tools, prompt the user or record telemetry; they may call AGT.

The policy uses ordered rules: the first match wins, otherwise `default_action`
applies. Place specific restrictions before broad allowances. `allow always`
approves the current action and records a proposal; it does not edit the policy
or automatically approve future calls. A central approval requirement is denied
in standalone mode because no central exception authority is connected.

## Modes and external services

Use `Guard.from_config(...)` with the [mode examples](../examples/):

| Mode | Behavior |
|---|---|
| Guard only | Local policy decides |
| Dual | Local policy and HTTP service are combined; stricter wins |
| Sole | HTTP service supplies the decision, including overriding a local deny |

The mode demo `agent.py` automatically approves self-owned asks for comparison.
Use `quickstart.py` to see an actual human prompt. `demo_agt_server.py` is a mock
contract demonstration, not a production AGT service. Check authentication,
timeouts, request/response semantics and outage behavior against your deployment.

By default, unavailable AGT converts native ALLOW to DENY, while native ASK/DENY
remains. `degrade_to_native` enables fallback and records degradation; it weakens
that outage protection. External decision consultation does not stop a process
bypassing Guard. Running gateways, proxies and credential brokers are planned.

## Logs and troubleshooting

Every Guard instance buffers decisions in memory. The quickstart explicitly adds
a `JsonlSink`; Ledger and OTel delivery likewise require configured sinks. Call
`guard.close()` to drain asynchronous delivery on shutdown. Delivery failures do
not change an enforcement decision; inspect sink failure/drop counters and plan
log retention. The in-memory buffer is not a durable audit store and can grow in
long-running processes.

- Unexpected deny: run `blastcontain-guard simulate -p examples/policy.yaml
  --tool delete_invoice --action-type delete` and inspect the matched rule.
- No approval prompt: check `autonomy_mode`, the matched rule, approvers and that
  an `on_ask` callback is registered. Central requirements are not user overrides.
- No Ledger events: constructing Guard alone enables memory logging, not delivery.
- Missing policy file: run examples from `guard/` as shown; use explicit paths in
  your deployment configuration.

Organizations decide policies and approval authority. See the shared
[technical checklist](../../docs/technical-security-checklist.md) for how Guard,
Verify and Drill contribute evidence without replacing those decisions.
