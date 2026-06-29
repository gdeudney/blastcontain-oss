# blastcontain-guard

**The in-process enforcer teams embed in their copilots.** Guard loads an
agent's policy — a local `governance.toolkit/v1` YAML (open, standalone) *or* a
compiled Charter — intercepts tool calls at the framework boundary, resolves
**allow / ask / deny**, prompts the user on *ask*, and streams every decision as
a signed-able CloudEvent to the Ledger.

Part of the BlastContain *cage trilogy*: **Verify** proves the cage is built
right · **Drill** attacks the agent inside it · **Guard** adds the runtime locks.
Apache-2.0, like Verify and Drill — a security control on your tool-call path
must be readable.

> **The wedge:** Guard + a local YAML + Verify/Drill is a complete, fully-open
> governance toolkit on its own. The commercial Platform (which *issues* signed
> Charters and runs the change-governance machinery) is purely additive — you
> graduate by changing the policy *source*, not the enforcement.

## Install

```bash
pip install -e ./core -e ./guard          # from the blastcontain-oss workspace
# optional: pip install -e "./guard[otel]"  # export decisions to OpenTelemetry
```

## Embed it

```python
from blastcontain_guard import Guard, GuardDenied

guard = Guard.from_yaml("policy.yaml")     # open, standalone
guard.on_ask(host_ui.prompt)               # register your approval UI

@guard.tool                                # guard a hand-rolled tool
def delete_invoice(invoice_id): ...        # evaluated on every call
```

`on_ask` receives an `AskRequest` and returns `AskResult` / `AskChoice` /
`"allow once" | "allow always" | "deny"`. **Allow always** emits a
derive-then-ratify proposal to add the tool to `permitted_tools` — Guard never
widens policy itself.

Other entry points: `guard.check(tool, action_type=..., args=...)` (the full
enforcement round-trip → `EnforcementResult`), `guard.evaluate(...)` /
`guard.explain(...)` (pure decision), `guard.write_decision_log(path)` (a signed
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
standing in for a real AGT. The same `agent.py` yields three different behaviours.

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

Guard-native is the always-on, in-process **primary** (the only enforcer where
AGT can't be injected). AGT is an optional, out-of-process **second front**
behind it — same compiled policy, enforced even if the in-process library is
bypassed. When AGT is enabled but unreachable, Guard **fails closed** (never a
silent downgrade). The out-of-process choke points (egress proxy, MCP gateway,
credential broker) are the second front for the dangerous few.

Guard and AGT agree *by construction* because Guard's ruleset format already **is**
AGT's `governance.toolkit/v1` — the same compiled policy drives both. Emit the AGT
form (BlastContain extensions stripped, the autonomy switch applied so
`require_approval` → `deny [central]` for unattended agents) and push it to a
running AGT:

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

Planned (guard-spec §13): live AGT delegation/consult at runtime · running
choke-point sidecars · LangChain / OpenAI-SDK adapters.

See [`docs/architecture.md`](docs/architecture.md).
