# BlastContain Guard — Enforcement Library Specification

> **Historical draft preserved from PR #20.** Implementation/status claims need
> reconciliation; see [review scope](README.md).

**`blastcontain-guard` — the open enforcement library: evidence collector · independent verifier · sovereign fallback**
Version 0.3 — Draft | 2026-06-11 | Audience: Engineering

> Guard is the thin, open-source library a team imports into an **interactive / copilot / side-of-desk**
> agent. It loads the agent's compiled **Charter**, intercepts tool calls at the framework boundary,
> resolves **allow / ask / deny** (charter-spec §3.7), prompts the user on *ask*, and streams every
> decision to the **Ledger**. It speaks AGT's own policy format (`governance.toolkit/v1`) — and since
> **AGT v4** ships a capable free enforcer of its own, Guard's job is bigger than enforcement: it is
> the **evidence collector** the Ledger prices, the **independent verifier** of whatever engine
> enforces, and the **sovereign fallback** for teams that won't put a hyperscaler in their tool-call
> path (§1.2).
>
> Companion specs: [charter-spec](BlastContain-charter-spec.md) (the policy it enforces),
> [roadmap](BlastContain-roadmap.md) (Guard is the core of **P4**). **Status: 🟡 partial** — the OSS
> wedge is built (reference impl `blastcontain-oss/guard`, Apache-2.0; see §13).

> **Status legend:** ✅ done · 🟡 partial · ⬜ planned

---

## 1. What Guard is — and isn't

Guard makes a Charter *do something* for a copilot whose host you don't control at the kernel level.
It is the **policy decision + the point of interception**, in-process, at the tool-call boundary.

**Guard is:** a policy evaluator + framework adapters + an approval callback + a telemetry emitter.
**Guard is not:** kernel isolation (that's containers, validated by Verify — ENV-01/PRIV-01/CAP-01),
the agent mesh, or a model guard. It governs a **cooperating agent** — one that calls Guard before
its tools. For tamper-resistance against a *compromised* agent, pair it with an out-of-process choke
point (§9).

**Relationship to AGT (updated for AGT v4, 2026-06).** The original framing — Guard the lightweight
default, AGT the optional heavyweight backend — is obsolete. AGT v4 (MIT) ships in-process middleware,
a first-party Claude Code governance plugin, a Copilot CLI installer, `require_approval` approvals,
and signed Merkle audit — in the same `governance.toolkit/v1` format. Guard does not race that. The
two are **peer engines for one policy** (§8): Guard *targets* AGT (`to_agt` / `push_to_agt`),
*verifies* it (the conformance harness), and *stands in* for it where Microsoft can't credibly go
(§1.2). Enforcement stays fully functional — it is the means, not the product.

### 1.1 Licensing & policy sources

**Guard is open source (Apache 2.0)** — like Verify / Drill / Discovery, and for the same reason a
security control *must* be readable: nobody embeds a closed black box into their agent's tool-call
path. Open Guard is what makes it adoptable and trustworthy.

Guard takes policy from one of **two sources** — *orthogonal* to the §8 enforcement backend:

| Source | What | License | For |
|---|---|---|---|
| **Local YAML** | a hand-authored ruleset (`allow`/`ask`/`deny`) — *the same format the Charter compiles to* | **open** · standalone · local · free | the wedge · OSS users · CI · air-gapped |
| **Platform Charter** | the signed, versioned Charter pulled from the commercial Platform | **commercial** (needs a Platform account) | org-wide Standards, governance, MPL, audit, GUI |

The library — evaluator, adapters, `on_ask`, OTel emit, local-YAML mode, native backend — is **all
open**. The commercial gate is the **Platform that *issues* signed Charters** and runs the governance
machinery; Guard's Charter-source adapter is just an API client (open, but only useful pointed at a
Platform). You don't close any of Guard — you gate the server it optionally talks to.

**The two planes (charter-spec §2.5) map onto the open/closed line:**
- **Runtime plane** (concerns → `allow`/`ask`/`deny`) → works fully in **open** local-YAML mode. *You
  govern yourself.*
- **Change-governance plane** (Standards inheritance, named owners, decision log, central exceptions,
  MPL, derive-then-ratify, fleet audit) → the **commercial Platform**. *The org governs you.*

**Graduate without re-plumbing.** Local YAML *is* the compiled-Charter format, so moving from
hand-authored YAML to a Platform-issued Charter changes the *source*, not the enforcement — same
evaluator, adapters, and `allow/ask/deny`. (YAML can also be emitted as AGT `governance.toolkit/v1`
for interop.)

> The OSS-fallback embodied: Guard + local YAML + Verify/Drill/Discovery is a complete, useful,
> fully-open governance toolkit on its own. The Platform is purely additive.

### 1.2 Positioning — Guard's three jobs (post-AGT-v4)

AGT v4 commoditized the in-process enforcer. What it did **not** ship is what BlastContain monetizes —
priced risk (MPL), HITL-quality analytics (override rate, approval latency), behavioural drift, and
independent adversarial assurance (Drill). Guard is the open component that serves those, three ways:

| Job | What it means | Serves |
|---|---|---|
| **Evidence collector** | every decision → a versioned CloudEvent (`latency_ms`, `approver`, `ask_choice`, …) + a signed decision log — the EU AI Act Art. 12/14 evidence stream | the **Ledger** (the commercial analytics AGT's dashboard lacks) |
| **Independent verifier** | a second, non-Microsoft implementation of `governance.toolkit/v1`: diff Guard's decisions against AGT's (conformance harness, §8) and give **Drill Role B** its instrumented gate | **Drill** + the EU-independence story |
| **Sovereign fallback** | the open, standalone enforcer for air-gapped / non-Azure / sovereignty-bound deployments — what makes "you're not locked to a US hyperscaler" *true* | **EU / regulated** buyers |

Consequence for the backlog (§13): the AGT-facing glue (consult · export · conformance) and the
stability of the decision-event schema are the priority; enforcer feature-parity work (more framework
adapters, choke-point sidecar transports) is deprioritized.

## 2. Scope & non-goals

| In scope | Out of scope (v1) |
|---|---|
| Interactive / copilot / side-of-desk (v1 focus) · **autonomous via config (§7.1)** | Autonomous *fleets / mesh* at scale |
| Tool-call interception (framework boundary) | Kernel / syscall interception (use containers) |
| allow / ask / deny with user-as-approver | Multi-agent mesh, trust-decay scoring |
| Single-agent; optional delegation context | Full delegation graph (Part Two) |

## 3. Architecture — the two fronts

```
                    in-process (cooperating)                 out-of-process (tamper-resistant)
   ┌──────────────────────────────────────────┐        ┌───────────────────────────────────┐
   │  Copilot / agent                          │        │  Choke point (the dangerous few)  │
   │   tool call ─▶ [ Guard ] ─▶ allow ─▶ run  │        │   • egress proxy (block exfil)     │
   │                   │  ask  ─▶ host prompt   │        │   • MCP gateway (default-deny)     │
   │                   │  deny ─▶ block + why   │        │   • credential broker (needs the   │
   │                   └─ emit decision ─OTel─▶ │        │     Guard token to release secrets)│
   └──────────────────────────────────────────┘        └───────────────────────────────────┘
                         │                                              │
                         └────────────────  Ledger  ───────────────────┘
```

- **Front 1 — Guard (in-process):** covers the common case cheaply; the copilot calls Guard, Guard
  decides, the host renders *ask*.
- **Front 2 — out-of-process choke point:** gates the genuinely dangerous capabilities (egress,
  secrets, destructive APIs) so they're enforced even if the in-process library is bypassed. Map the
  concern's risk to which front enforces it: most → Front 1; exfiltration / secrets / destructive →
  also Front 2.

## 4. Decision flow

```
load compiled Charter (once)
on each intercepted tool call:
  1. build input  { tool_name, action.type, args, agent_id, identity, delegation_ctx? }
  2. evaluate against the Charter ruleset  →  allow | ask | deny   (+ which approver)
  3. allow  → run the tool; emit ALLOW
     ask    → invoke the host approval callback (allow once / allow always / deny)
              • allow      → run; emit ASK_APPROVED
              • allow-always → run; emit ASK_APPROVED + propose permitted_tools add (learning, §7)
              • deny       → block; emit ASK_DENIED
     deny   → block; surface reason + "request Exception" path; emit DENY
  4. every emit → OTel/CloudEvents → Ledger (+ HITL metrics)
```

## 5. The policy evaluator

A small, deterministic evaluator over the compiled Charter (mirrors AGT's `condition → action`):

- **Input:** `{ tool_name, action_type, args, agent_id, identity, delegation_ctx? }`
- **Ruleset:** `default_action` + ordered `rules` (condition expr → `allow|ask|deny`), each rule
  carrying `approvers` (`[self]` / `[central]`).
- **Resolution:** first matching rule wins; otherwise `default_action` (deny-by-default).
- **Approver split (the honesty line, §3.7):** self-selected/`recommended` concerns → `ask [self]`;
  `mandatory` Standards → `deny` (no user override; only a central Exception lifts it). In open,
  standalone (local-YAML) mode there is no central authority, so an `ask [central]` collapses to
  `deny` — a mandatory guardrail never degrades to a present user's click.
- **Delegation (optional, single-hop):** if `delegation_ctx` present, evaluate against the
  **intersection** of this agent's ruleset and the parent's (the weakest-link rule, charter-spec
  §2.4) — the stricter wins.

Conditions are evaluated by a **safe, eval-free parser** (an `ast` allowlist — comparisons, boolean
combinators, attribute access into the input, literals; never `eval`/`exec`, which is Verify's own
CODE-01 finding), so a malformed or hostile condition fails at *load* time, not at the tool-call
boundary. The ruleset *is* the local-YAML wedge (§1.1) — the same `governance.toolkit/v1` AGT consumes
(the rule action is AGT's `allow`/`deny`/`require_approval`; the evaluator surfaces `allow`/`ask`/`deny`):

```yaml
apiVersion: governance.toolkit/v1
name: invoice-bot-prod
default_action: deny                 # deny-by-default — the secure default
rules:
  - name: block-exfiltration
    condition: "action.type == 'send' and not tool_name in ['send_receipt']"
    action: deny                     # mandatory Standard — central Exception only
    approvers: [central]
  - name: confirm-destructive
    condition: "action.type in ['delete', 'drop', 'truncate']"
    action: require_approval         # ask [self] in interactive mode
    approvers: [self]
  - name: allow-reads
    condition: "tool_name in ['query_invoice', 'list_invoices']"
    action: allow
```

Sub-millisecond, pure function, no network on the hot path (decisions emit async).

## 6. Framework adapters

The bulk of the build is small adapters that surface the tool-call boundary. One interface:

```python
class Adapter(Protocol):
    def intercept(self, call: ToolCall) -> Decision: ...   # calls guard.evaluate
    def render_ask(self, req: AskRequest) -> AskResult: ... # host-specific prompt
```

Target adapters (each independent, ship incrementally):

| Adapter | Hook |
|---|---|
| **Claude Code** | `PreToolUse` hook / `settings.json` permission integration |
| **MCP middleware** | wrap the MCP client/server call path (covers many copilots at once) |
| **LangChain / LangGraph** | tool/callback handler |
| **OpenAI / Anthropic SDK** | function-call / tool-use wrapper |
| **Generic** | `@guard.tool` decorator for hand-rolled agents |

> MCP middleware is the highest-leverage first adapter — many side-of-desk copilots speak MCP, so one
> adapter governs many hosts.

**Prioritization (post-AGT-v4):** AGT ships first-party surface integrations (Claude Code plugin,
Copilot CLI, Agent Framework middleware), so adapter *parity* is not the race. The shipped adapters
(Claude Code · MCP · `@guard.tool`) stay — they are the evidence on-ramp — but the LangChain and
OpenAI/Anthropic-SDK adapters are **deprioritized** until a design partner needs one.

## 7. The approval (ask) interface

Guard does not own UI; the host renders the prompt via a registered callback:

```python
guard.on_ask(lambda req: host_ui.prompt(
    action = req.description,      # plain-language "what it wants to do"
    tool   = req.tool_name,
    risk   = req.risk_tag,         # MIT · OWASP, for context
    options = ["Allow once", "Allow always", "Deny"],
))
```

- **Allow once** — this call only.
- **Allow always** — run + **emit a learning signal**: propose adding the tool/action to
  `permitted_tools` (derive-then-ratify; the human ratifies the Charter change later, logged).
- **Deny** — block; recorded.

Every choice is EU AI Act Art. 14 evidence and a HITL-quality signal (latency, override rate).

### 7.1 Autonomy modes — how `ask` resolves

`ask` assumes a human is present; **`autonomy_mode` (charter-spec §3.2) decides how it actually
resolves** — which is why Guard runs on an autonomous agent too. It's a config, not a rebuild
(`allow` / `deny` are identical either way):

| Mode | `ask` resolves to |
|---|---|
| **interactive / copilot** | a **synchronous inline prompt** to the present user (`on_ask`) |
| **autonomous** | **async approval** — route to `hitl_config.escalation_contact`, park the action, **deny on `hitl_config.timeout_sec`**; or, with no approver configured, compile straight to **`deny`** |

For autonomous agents the *posture* shifts (not Guard's code): stricter defaults (bigger blast radius,
no human catching mistakes), heavier reliance on **Front 2 / AGT** (a compromised *unwatched* agent is
the worst case — exactly where the out-of-process line pays off), and the **behavioural baseline /
Semantic Circuit Breaker** (charter-spec §7.7) as the safety net a present human would otherwise be.

The schema already carries this: `autonomy_mode` + `hitl_config.{required_for, timeout_sec,
escalation_contact}` were designed for the async case. **v1 focuses interactive; Guard stays
autonomy-aware so autonomous is a supported option, not a corner to rebuild out of.**

## 8. Backends — two engines, one policy (native ⟷ AGT)

Native and AGT are **peer engines enforcing the same compiled policy** — the Charter compiles to one
format (`governance.toolkit/v1`) both consume, so they agree by construction. Which engine runs, and
in which combination, is **configuration** (`from_config`), not architecture:

| | **Guard-native** | **AGT** |
|---|---|---|
| What it is | the independent, Apache-2.0 implementation — evidence, verification, sovereignty (§1.2) | Microsoft's MIT engine — in-process middleware *and* MCP gateway / runtime privilege rings / mesh (v4) |
| Owns | the decision-event stream + the `ask` UX at the agent's own surface | kernel-grade isolation + the first-party Microsoft surfaces |
| When | standalone (sovereign / air-gapped), `dual` alongside AGT, or as AGT's verifier | teams standardized on AGT — Guard rides it in `sole` mode |

**Dual** keeps both engines live: native decides in-process, AGT backs it out-of-process, and the
**stricter verdict wins** (AGT can only tighten) — so the policy holds even if the in-process library
is bypassed (the §11 cooperating-agent limit). **Sole** makes AGT the only decider and Guard a thin
shim that still captures the evidence stream — Guard *rides* AGT rather than duplicating it. Either
way Guard keeps emitting decisions, which is the point: **whichever engine enforces, the evidence
lands in the Ledger.**

**Verification — the independence product (§1.2).** Because Guard independently implements the same
`governance.toolkit/v1` semantics, it can **conformance-test AGT**: load the same ruleset into both,
replay the same calls, diff the decisions. An independent party *re-evaluating the policy* — not just
trusting the engine's own logs — is what a regulator can't get from the engine vendor, and it is the
instrumented gate **Drill Role B** attacks to prove "a high-risk action cannot execute without the
gate firing."

**Availability (AGT enabled but unreachable):** **fail-closed** for `deny` / `ask` actions, with a
logged degradation finding — never a silent downgrade to the weaker in-process layer. An opt-in
`degrade-to-native` mode exists for low-risk agents, but it always alerts.

**Implemented (reference build) — the engines are a config, not a rebuild.** `mode: dual` = AGT backs
native (stricter-wins; AGT can only tighten); `mode: sole` = AGT is the sole decider, native is
pass-through. AGT is consulted out-of-process via an HTTP `endpoint` (the real `PolicyEvaluator`), and
the *same* compiled policy is emitted/pushed to it — `to_agt` / `push_to_agt` (roadmap `push_to_agt()`),
so the two fronts agree by construction (Guard's ruleset format already *is* `governance.toolkit/v1`).
Unreachable-AGT fail-closed is verified. Mode selection is entirely `Guard.from_config(...)`: the agent
code is **identical** across guard-only / dual / sole — only the config's `agt:` block differs.

## 9. Out-of-process choke point

For the dangerous few, in-process trust isn't enough. Provide thin, optional sidecars:

- **Egress proxy** — default-deny outbound; only Guard-approved destinations pass (enforces "block
  exfiltration" even if the agent is compromised).
- **MCP gateway** — default-deny tool allowlist at the protocol boundary (mirrors AGT's MCP gateway).
- **Credential broker** — secrets released only against a valid Guard decision token (so a compromised
  agent finds no cached secrets — aligns with the short-lived-credential / SPIFFE direction).

**Prioritization (post-AGT-v4):** AGT's MCP Security Gateway and Agent Runtime privilege rings cover
this ground wherever AGT is deployed — there, AGT *is* Front 2. Guard keeps the default-deny *policy*
helpers above (they also serve the sovereign path), but building the sidecar transports is
**deprioritized**.

## 10. Identity & telemetry

- **Identity** — sign Guard decisions with the agent's key (Ed25519; `did:mesh:` with AGT, or
  SPIFFE/SVID standalone). Optional but enables non-repudiation.
- **Telemetry** — emit each decision as a CloudEvent over **pluggable sinks** (in-memory buffer ·
  JSONL · Ledger HTTP · OpenTelemetry-*if-present*): `{agent_id, tool, action, decision, approver,
  latency_ms, ts}`. OTel is *one optional sink*, not the only transport — the Ledger has its own HTTP
  sink, so no OTel collector is needed to reach it. This *is* the audit trail and the HITL-quality
  feed; no separate logging path. Network sinks run off the hot path (async). The in-memory buffer
  also backs a **signed decision-log packet** — the same Audit-Packet envelope Verify/Drill use
  (`blastcontain_core.signing`) — for the at-rest, tamper-evident record.
- **The schema is a contract.** The decision-event shape is the **Ledger's ingestion format** and the
  EU AI Act Art. 12/14 evidence format — Guard's most important interface post-AGT-v4 (§1.2). Version
  it, evolve it additively. A planned **AGT-event bridge** maps AGT's audit stream (Merkle audit /
  Decision BOM) into the same schema, so the Ledger prices AGT-governed fleets with or without Guard
  in the call path.

## 11. Threat model & limits (honest)

- **Assumes a cooperating agent.** A fully compromised agent can skip Guard. Mitigation: Front 2 (§9)
  for the dangerous capabilities; treat Guard as governing intent + the common case, not a sandbox.
- **Not a content guard.** Prompt-injection / jailbreak detection is the enforcement plane's job
  (NeMo/Cisco/AGT) and Drill's; Guard gates *actions*, not *content*.
- **Single-hop delegation only** in v1; full graph is Part Two.

## 12. API sketch

```python
from blastcontain_guard import Guard
from blastcontain_guard.adapters import MCPMiddleware

guard = Guard.from_yaml("policy.yaml")                    # open, standalone (the wedge)
# guard = Guard.from_charter_file("charter.yaml")          # compile a core Charter offline
# guard = Guard.from_config("mode.yaml")                   # mode (guard-only/dual/sole) is config
# guard = Guard.from_charter("invoice-bot", env="prod")    # signed Platform Charter
guard.on_ask(host_ui.prompt)                              # register approval UI
guard.attach(MCPMiddleware())                             # intercept MCP tool calls
# ... or wrap a tool directly:
@guard.tool
def delete_record(id): ...                                # evaluated on every call
```

## 13. Implementation status & work (roadmap P4)

**Reference implementation:** `blastcontain-oss/guard` (Apache-2.0), on `blastcontain-core` 0.2 —
sibling to verify/drill; 111 unit tests, ruff-clean. The functional wedge (local-YAML → evaluator →
`on_ask`/learning → telemetry → adapters → AGT export/push) is complete and standalone. **Post-AGT-v4
priorities (§1.2):** the AGT conformance harness, the versioned decision-event schema + AGT-event
bridge, and Drill Role B are the next builds; adapter parity and sidecar transports are deprioritized.

| Item | Status |
|---|---|
| Policy evaluator (Charter ruleset → allow/ask/deny) | ✅ |
| Safe, eval-free condition language (AST allowlist) | ✅ |
| **Local-YAML policy source** (open, standalone — the OSS wedge) | ✅ |
| Charter → ruleset compiler (offline `CharterSchema` bridge) | ✅ |
| `on_ask` callback + allow-once / allow-always / deny | ✅ |
| Learning signal (allow-always → `permitted_tools` proposal) | ✅ |
| Single-hop delegation intersection | ✅ |
| Adapter: MCP middleware (first) | ✅ |
| Adapter: Claude Code hook | ✅ |
| Adapter: generic `@guard.tool` decorator | ✅ |
| Adapter: LangChain · OpenAI/Anthropic SDK | ⬜ deprioritized — AGT ships first-party integrations (§6) |
| OTel/CloudEvents emit → Ledger (pluggable sinks) | ✅ |
| Signed decision-log packet | ✅ |
| Backend abstraction (Guard-native ⟷ AGT) + fail-closed | ✅ |
| Config-driven modes (`from_config`: guard-only / dual / sole) | ✅ |
| AGT policy export + push seam (`to_agt` / `push_to_agt`) | ✅ |
| AGT runtime consult (HTTP `endpoint` evaluator) | 🟡 (seam done; needs a live AGT) |
| Out-of-process choke points (egress / MCP / broker) | 🟡 policy logic done; transports deprioritized — AGT's gateway/rings are Front 2 where AGT is present (§9) |
| **Conformance harness** — same ruleset, same calls, diff Guard vs AGT decisions | ⬜ **next** — the independent-verification seed (§8) |
| **Versioned decision-event schema** + AGT-event bridge → Ledger | ⬜ **next** — the Ledger's ingestion contract (§10) |
| **Drill Role B** gate harness — prove the gate cannot be bypassed | ⬜ **next** — with Drill |
| **Charter-source adapter** (Platform API client — fetch · verify signature · advisory gate · lifecycle gating) | ✅ (`platform_source.py`; exercised end-to-end against the platform server — `tests/server/test_platform_loop.py`: sign → fetch → verify → enforce, pause → deny-all, decisions → Ledger) |
| Live AGT delegation / mesh · multi-hop delegation | ⬜ |

---

## See also
- [BlastContain-charter-spec.md](BlastContain-charter-spec.md) §3.7 — the allow/ask/deny model Guard enforces
- [BlastContain-roadmap.md](BlastContain-roadmap.md) — Guard = P4
- [BlastContain-platform-spec.md](BlastContain-platform-spec.md) — where Guard sits in the stack
- [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit) — AGT v4
  (2026-06): the peer engine Guard targets, verifies, and falls back from
