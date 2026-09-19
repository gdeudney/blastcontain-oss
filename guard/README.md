# blastcontain-guard

**The in-process enforcer teams embed in their copilots.** Guard loads an
agent's policy — a local `governance.toolkit/v1` YAML (open, standalone) *or* a
compiled Charter — intercepts tool calls at the framework boundary, resolves
**allow / ask / deny**, prompts the user on *ask*, and records decisions as CloudEvents in memory.
Configure a file, Ledger or OpenTelemetry sink for external delivery; export a
signed decision-log packet when needed.

Part of the BlastContain *cage trilogy*: **Verify** checks the runtime and source against technical requirements · **Drill** attacks the agent inside it · **Guard** adds the runtime locks.
Apache-2.0, like Verify and Drill — a security control on your tool-call path
must be readable.

Guard works with a local policy without the Platform. Your organization owns
that policy, its approval authority and exceptions. These tools provide technical
controls and evidence; they do not establish organizational governance.

**Security boundary:** Guard protects calls routed through its adapters. An agent
that can execute arbitrary code with the same privileges can bypass an in-process
wrapper. Separate OS/container containment and externally enforced access controls
are still required. An HTTP policy decision alone does not create such a boundary.

Start with the [runnable usage guide](docs/usage.md) and the shared
[technical checklist](../docs/technical-security-checklist.md).

## Install

```bash
pip install -e ./core -e ./guard          # from the blastcontain-oss workspace
# optional: pip install -e "./guard[otel]"  # export decisions to OpenTelemetry
```

## Embed it

```python
from blastcontain_guard import AskChoice, Guard

# Run from guard/; see docs/usage.md for a complete runnable example.
guard = Guard.from_yaml("examples/policy.yaml")

def prompt(request):
    answer = input(f"Allow {request.tool_name} once? [y/N] ").strip().lower()
    return AskChoice.ALLOW_ONCE if answer == "y" else AskChoice.DENY

guard.on_ask(prompt)

@guard.tool                                # guard a hand-rolled tool
def delete_invoice(invoice_id): ...        # evaluated on every call
```

`on_ask` receives an `AskRequest` and returns `AskResult` / `AskChoice` /
`"allow once" | "allow always" | "deny"`. **Allow always** emits a
derive-then-ratify proposal to add the tool to `permitted_tools` — Guard never
widens policy itself.

Other entry points: `guard.check(tool, action_type=..., args=...)` (the full
enforcement round-trip → `EnforcementResult`), `guard.evaluate(...)` /
`guard.explain(...)` (decision only; may contact AGT, without approval or telemetry), `guard.write_decision_log(path)` (a signed
audit packet).

## Same code, config-only modes

Enforcement mode is *configuration, not code*. Write the agent once with
`Guard.from_config(...)`; switch modes by pointing at a different YAML — nothing
in the agent changes:

```python
guard = Guard.from_config("mode.yaml")   # identical agent code in every mode
```

| Mode | config `agt:` block | who decides |
|---|---|---|
| **guard-only** | *(omit)* | Guard, in-process |
| **guard + AGT** | `enabled: true · mode: dual · endpoint: …` | Guard; AGT backs it (tightens only) |
| **AGT-only** | `enabled: true · mode: sole · endpoint: …` | AGT alone (native is pass-through) |

Runnable: `examples/agent.py` + `examples/mode-*.yaml`, with `examples/demo_agt_server.py`
standing in for an AGT-compatible decision endpoint. These mode demos
automatically approve self-owned asks; use the usage guide for a real human prompt.
Validate the request/response contract against your service before production use.

## The policy

A `governance.toolkit/v1` ruleset — `default_action` plus ordered
`condition → allow | deny | require_approval` rules, first match wins,
deny-by-default. Conditions are evaluated by a **safe, eval-free** parser
(AST allowlist — no `eval`/`exec`), over `tool_name`, `action.type`, `args`,
`identity`, `agent_id`, `environment`, `delegation`.

The **honesty line** (charter-spec §3.7): a self/recommended concern is an
`ask [self]` the present user can lift; a mandatory Standard is a hard
`deny [central]` that never degrades to a click — in standalone mode a
`[central]` ask collapses to deny, since there is no central authority to grant
an Exception. See [`examples/policy.yaml`](examples/policy.yaml).

You can also compile a core `charter.yaml` offline:

```bash
blastcontain-guard compile examples/charter.yaml      # -> a ruleset
```

## CLI

```bash
blastcontain-guard lint     examples/policy.yaml
blastcontain-guard simulate -p examples/policy.yaml --tool delete_invoice --action-type delete
blastcontain-guard compile  examples/charter.yaml -o policy.yaml
blastcontain-guard hook     -p examples/policy.yaml   # Claude Code PreToolUse hook
```

### Claude Code

Guard's allow/ask/deny maps one-to-one onto Claude Code's permission decision —
Guard evaluates, Claude Code renders the *ask*. In `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [
        {"type": "command", "command": "blastcontain-guard hook --policy .blastcontain/policy.yaml"}
      ]}
    ]
  }
}
```

## Two fronts

Guard can consult an HTTP decision endpoint in `dual` or `sole` mode.
In `dual`, the stricter decision wins; in `sole`, AGT supplies the decision and
can override a native deny. With the default outage behavior, native ALLOW becomes
DENY when AGT is unavailable; native ASK/DENY remains in force. The optional
`degrade_to_native` setting permits fallback and records degradation. Choose that
tradeoff explicitly.

These calls still depend on the agent using Guard. Bypass-resistant enforcement
requires a separately deployed gateway, proxy or credential broker that controls
the actual resource path. This package contains policy helpers for those
components, **not running enforcement services**.

The exporter emits `governance.toolkit/v1` YAML, strips BlastContain extensions
and converts approval rules for unattended agents. A shared format is not proof
of identical semantics in an external implementation. The demo HTTP server
illustrates the contract; verify compatibility with your chosen deployment.
Export or push a policy with:

```bash
blastcontain-guard export-agt -p policy.yaml                 # -> AGT policy YAML
blastcontain-guard export-agt --charter charter.yaml --autonomy-mode autonomous
blastcontain-guard export-agt -p policy.yaml --endpoint https://agt/admin/policy
```

In code: `guard.to_agt_yaml()` / `guard.push_to_agt(client=…, endpoint=…, path=…)`.

## Status

Implemented: local-YAML policy source · safe evaluator · allow/ask/deny with the
approver split · single-hop delegation · `on_ask` + allow-once/always/deny ·
learning signal · CloudEvents telemetry (jsonl / Ledger / OTel-if-present) ·
signed decision log · Charter→ruleset compiler · native backend · generic / MCP /
Claude Code adapters · backend abstraction with fail-closed AGT seam · AGT policy
export + push seam (`to_agt` / `push_to_agt`) · **config-driven modes**
(`Guard.from_config`: guard-only / dual / sole, with an HTTP AGT backend) ·
**Platform Charter source** (`Guard.from_charter`: fetch → verify signature →
enforce; rejects unverifiable or dev-key-signed Charters; paused/quarantined
agents enforce deny-all).

Implemented HTTP consultation is distinct from a validated deployment of a
specific AGT service. Planned: running enforcement proxies/gateways/credential
brokers, broader delegation integration, and LangChain / OpenAI-SDK adapters.

See [`docs/architecture.md`](docs/architecture.md).
