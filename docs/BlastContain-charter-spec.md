# BlastContain — Charter Specification

**Agent Policy Constitution — engineering spec for the Charter subsystem**
Version 0.1 — Draft | 2026-05-30 | Audience: Engineering, Security, Compliance, Product

> Scope: the **Charter** subsystem of the closed Platform server. Charter is the policy authoring
> and enforcement-authoring layer — it turns human intent into machine-enforceable policy, compiles
> that to Microsoft AGT, and governs the agent's lifecycle. For the whole platform see
> [BlastContain-platform-spec.md](BlastContain-platform-spec.md); the Charter there is §3, with
> enforcement in §9. This document is the standalone, reviewable version.

---

## Contents

1. [What the Charter Is](#1-what-the-charter-is)
2. [Core Concepts](#2-core-concepts)
3. [The Authoring Model](#3-the-authoring-model)
4. [The Objective Catalog](#4-the-objective-catalog)
5. [Schema](#5-schema)
6. [Compilation — Charter → AGT](#6-compilation--charter--agt)
7. [Lifecycle](#7-lifecycle)
8. [API](#8-api)
9. [Implementation Status & Open Items](#9-implementation-status--open-items)

> **Status legend:** ✅ implemented · 🟡 partial · ⬜ planned

---

## 1. What the Charter Is

The Charter is the **signed contract between the organisation and an agent** — it declares what the
agent is allowed to do. Without a Charter, an agent cannot register. A tool call outside the Charter
is, by definition, a violation.

**The design axiom (make-or-break).** A Charter is a security policy, and security policies die from
friction. A blank form of allowlists and boolean flags produces one of two failures — agents with no
Charter at all, or Charters that "allow everything" to get past the form. Either kills
least-privilege and defeats the product. Therefore the authoring surface lets a human reason in
**outcomes**, not config keys, and the system compiles those outcomes into technical controls.

**The boundary.** The Charter is authored and stored on the closed Platform (the *control plane*).
It is **not** enforced by BlastContain at runtime — that is Microsoft AGT's job (the *enforcement
plane*). BlastContain compiles each Charter into AGT policy and ingests AGT's runtime decisions back
into the Ledger. We do not duplicate AGT's interception (§6).

Source today: [`server/blastcontain/charter/schema.py`](../server/blastcontain/charter/schema.py),
[`server/blastcontain/charter/compiler.py`](../server/blastcontain/charter/compiler.py).

---

## 2. Core Concepts

### 2.1 Two layers: Intent → Control

A Charter is authored as an **Intent layer** and stored alongside the **Control layer** it compiles
to:

```
  Intent layer (human-facing)            Control layer (CharterSchema, §5)        Runtime
  ──────────────────────────             ─────────────────────────────────       ───────
  scope, autonomy, posture          ─┐
  objectives (plain-language        ─┼─▶ permitted_tools / permitted_apis    ─▶ AGT policy
    guardrails):                     │   environment_constraints                 (governance.
    "Don't change production data"   │   delegation_rules / hitl_config           toolkit/v1)
    "No data leaves the boundary"   ─┘   trust_tier
```

The human edits the left column; the compiler owns the middle; AGT owns the right. **The Intent
layer is the source of truth** for authoring, diffing, and recertification. The Control layer is a
derived, signed artifact.

### 2.2 Identity

The unique key is **`(agent_id, environment)`**. Dev, UAT, staging, and prod Charters for the same
agent are independent documents with independent version histories and signatures. The server stores
them under the composite key `f"{agent_id}:{environment}"`.

### 2.3 The three authoring axes

Every Charter (or Standard) is defined by answering three questions **in order**, before any
technical control is touched: **Scope → Autonomy → Concerns** (§3). Everything else — strictness,
trust tier, the compiled controls — derives from those three answers.

### 2.4 Delegation graph & control consistency

Agents call other agents, so governance tracks the **delegation graph** and checks **control
consistency** across it — the second is the subtle, important part.

**The graph.** Nodes = agents `(agent_id, environment)`; edges = "may delegate to." Built from two
sources and continuously reconciled:
- **Declared** — the parent Charter's `delegation_rules` (plus a proposed `permitted_delegates`
  allowlist, §5.2).
- **Observed** — AGT runtime delegation events / trust-boundary crossings + Discovery.

Declared-vs-observed divergence is a Charter-drift finding. The Ledger already walks this graph for
Trust-Aware Blast Radius; the pause/decommission cascade (§7.6) depends on it too.

**The weakest-link rule (capability laundering).** A locked-down Agent A — "no internet, no
destructive APIs" — that delegates to a less-restricted Agent B effectively *gains B's capabilities*:
it reaches the internet **through** B, and A's Charter becomes a fiction. So the rule is **not**
"controls must be identical." It is: **a delegation must not let the parent exceed its own
concerns.** An agent's *effective* capability surface = its own controls ∪ everything it can reach by
delegation; governance reasons about **effective**, not direct, capability.

**Enforced in three layers:**

| Layer | Check |
|---|---|
| **Compile-time** (authoring) | For each edge A→B, flag any capability B grants that A's concerns forbid. The human constrains the delegation, tightens B, or files an Exception (§3.6). |
| **Runtime** (AGT) | **Confirmed native:** Trust-Ceiling Propagation (ADR-0016) + **Parent-Deny-Immutable (ADR-0014 — a parent's deny rules cannot be overridden by a sub-agent in the merge)** carry the parent's constraints down the chain *per invocation*; the **stricter** constraint wins along the call path. B may be broad for its own callers yet constrained when invoked by locked-down A. |
| **Pricing** (Ledger) | A hop to a higher-tier / more-capable agent amplifies MPL (Trust-Aware Blast Radius). |

This is what the catalog concern *"No autonomous privilege escalation via delegation"* (§4 ⑥) turns
on; it answers OWASP T3 / T13 and MIT 7.6 (multi-agent risks).

### 2.5 Two planes — change-governance & runtime

A Charter binds **two planes**. Keeping them distinct avoids conflating *who may change what the
agent does* with *what the agent may do at runtime*.

| Plane | Question | Mechanism |
|---|---|---|
| **Runtime** | What may the agent do, right now? | concerns → AGT `allow / ask / deny` (§3.7) |
| **Change-governance** | Who may change the agent's boundary, and is it recorded? | named owners + a configurable decision-rights ladder + a decision log |

**The change-governance plane is optional and configurable.** It is drawn from the BlastContain
article series' governance model, but it is an **opt-in discipline** an org may adopt in whole, in
part, or not at all — and the **number of decision levels is configurable** (the default ladder has
three; an org may use more or fewer). The spec supports it; enforcing it is a deployment choice.

Components (each optional to enforce):
- **Named roles** — e.g. Technical Owner (execution), Business Owner (risk), Executive Sponsor
  (authorization). Best practice: **distinct people** — "the same name in two roles is an ownership
  vacuum." Findings + MPL route to the Technical Owner.
- **Decision-rights ladder** — a configurable set of tiers matching change-authority to consequence.
  Default ladder:

  | Tier | Scope of change | Approver |
  |---|---|---|
  | Operational | adjustments *within* the approved boundary | Technical Owner (log only) |
  | Governance | material change to scope / tools / data / risk | Business + Technical Owner |
  | Executive | new regulated data, reduced oversight, legal/financial exposure | Executive Sponsor |

- **Decision Rights Log** — append-only: *date · change · rationale · approver(s)* — the immutable
  record of who decided what, when (survives staff turnover).
- **Review Trigger Log + Review Date** — model updates, scope expansions, incidents → logged;
  periodic review (default quarterly, §7.6) confirms roles, boundary, and log completeness.
- **Agent Playbook** — the operational companion: per authorized workflow step, the data it needs,
  the HITL mode, and the step's blast radius. *The boundary says what the agent may do; the Playbook
  says what it needs to know to do it.*

> This plane is a **governance record, not machine policy** — it compiles to nothing in AGT. Its
> value is accountability and auditability (it is the EU AI Act Art. 12 documentation trail). Pure
> technical enforcement can skip it; provable human accountability turns it on.

---

## 3. The Authoring Model

### 3.1 Axis 1 — Scope: org-level or agent-level?

| Scope | What it is | Inheritance |
|---|---|---|
| **Org-level** | An Organizational **Standard** — a guardrail applied to *every* agent in the tenant, set by the central governance group (CISO / platform security) | inherited as `mandatory` / `recommended` / `optional` |
| **Agent-level** | A **Charter** for one `(agent_id, environment)` — this agent's own concerns | layered on top of, never weaker than, inherited Standards |

**Inheritance rules.** A Charter is the union of inherited Standard objectives and owner-added
objectives. Per inherited objective:

| Level | The agent owner may… |
|---|---|
| `mandatory` | Tighten: yes. Loosen / remove: **no** (requires an Exception, §3.6). |
| `recommended` | Loosen: yes, with logged justification. |
| `optional` | Add / remove freely. |

This inheritance is *only possible because authoring is intent-based*: you can hand down "never
exfiltrate PII" across a fleet; you cannot hand down an agent-specific tool allowlist.

### 3.2 Axis 2 — Autonomy: autonomous or interactive/copilot?

The single biggest risk determinant. It changes *how every concern compiles*:

| Agent type | Definition | How concerns compile |
|---|---|---|
| **Autonomous** | Runs unattended; no human approves actions at runtime | concern → hard **`deny`** (no one to ask) |
| **Interactive / Copilot** | A human is present and approves/rejects actions in real time | concern → **`require_approval`** (AGT HITL gate) instead of a block |

The same capability is far riskier unattended, so the autonomy answer sets the default `action` (§6)
for every concern.

**On HITL cost & latency.** `require_approval` is AGT-native (its action + `approvers`), so
BlastContain does *not* build a bespoke approval engine. But a gate is **not free** — it adds
human-decision latency and an approval-routing UX. Therefore:
- It fits **copilot/interactive** naturally — the human is already present and driving, so marginal
  latency is low and approval is part of the existing UX.
- For **autonomous** agents, prefer **`deny`** over `require_approval` — waiting on a human defeats
  unattended operation, and a stream of approvals from an autonomous agent *is* the OWASP T10
  "Overwhelming HITL" failure mode.

HITL beyond AGT's native gate (custom routing, escalation, fatigue monitoring) is **optional and not
zero-work** — an opt-in capability, never a baseline.

### 3.3 Axis 3 — Concerns: what do you care about?

The plain-language guardrails from the catalog (§4): *no internet access*, *don't change data*, *no
secrets*, *no PII leaves the boundary*, … The human picks concerns; the compiler turns each into
controls + an AGT rule whose `action` is set by the autonomy answer.

### 3.4 Secondary modifiers

Not primary decisions — they refine the baseline:
- **Base strictness** (`locked` · `balanced` · `permissive`) — how many concerns are pre-selected
  and how broad the seed allowlist is. May start from an **archetype template** (e.g. Cisco AI
  Defense's pre-built guardrail profiles for *customer-facing*, *internal-tooling*, *data-pipeline*
  agents) rather than a blank slate.
- **Trust tier** (`0–3`) — feeds blast-radius / MPL math (Ledger), caps delegation, and maps to
  AGT's 4 privilege rings (§6). This is a *declared, static* tier; AGT *also* computes a **dynamic
  0–1000 AgentMesh trust score** (earned / decayed by compliance history). Our tier sets the ceiling;
  AGT's score is the earned runtime trust — complementary, and the score is a Ledger signal.

`defaults = f(scope, autonomy, base_strictness, trust_tier)`; the human then selects concerns. Every
derived control stays editable, but the human only touches exceptions.

### 3.5 Authoring UI flow

```
 1. Set scope + posture   org-level Standard or agent Charter ▸ autonomy ▸ strictness ▸ trust_tier
                          └▶ baseline concerns + controls auto-populate
 2. Select concerns       pick plain-language guardrails from the catalog
                          └▶ each shows what it compiled to (expandable), action set by autonomy
 3. Reconcile reality     derived suggestions from the latest Verify / Discovery scan
                          └▶ accept (add to allowlist) / dismiss / flagged as objective-conflict
 4. Review compiled       the technical Control layer + AGT policy, read-only, expandable
 5. Sign                  draft ▸ review ▸ sign  (signature = the commitment gate; sets signed_*)
```

UI principles that protect the axiom: **derive, don't ask** (step 3 seeds from observed reality);
**progressive disclosure** (a tier-0 copilot never sees delegation controls); **the secure default
is the pre-selected default**; **signing is a deliberate gate**, not a save button. An **advanced /
raw-controls escape hatch** remains for the long tail the catalog can't express; raw controls are
flagged "unclassified" and excluded from objective-level diffing.

### 3.6 Conflict reconciliation & Exceptions

When scan-derived reality conflicts with a selected objective (e.g. the agent calls `DELETE /orders`
but the owner picked "never change production data"), the resolution path depends on the objective's
origin:

| Conflict with… | Resolution | Sign-off |
|---|---|---|
| A `mandatory` (central) objective | **Blocks signing** — file an Exception | **Central group** (separation of duties — owner cannot approve their own) |
| A `recommended` objective | Loosen with logged justification | Owner |
| A self-selected objective | Accept-with-note or fix inline | Owner |

**Exceptions (break-glass).** A first-class, auditable object:
`{ objective_id, agent_id, justification, scope, granted_by, granted_at, expires_at }`. Recorded
immutably in the Ledger and **expires** — forcing periodic re-review so deviations never become
permanent. An expired Exception re-opens the conflict and (for `mandatory` objectives) re-blocks the
Charter until renewed.

### 3.7 Interactive enforcement model — allow / ask / deny

For interactive / copilot agents the policy decision is not binary. **AGT stays the enforcement
engine**; the compiled rule resolves to one of **three** outcomes, and on *ask* the copilot pauses and
prompts **the user it is assisting** — inline, in its own surface — exactly the Claude Code pattern.

| Outcome | AGT action | What happens |
|---|---|---|
| **allow** | `allow` | runs; recorded |
| **ask** | `require_approval` | copilot prompts the user inline (allow once / allow always / deny); decision recorded |
| **deny** | `deny` | blocked; the user is told why and can request an Exception (§3.6) |

**Where it runs.** AGT *evaluates*; the *prompt renders at the host* — the copilot's native permission
hooks where they exist (Claude Code, Cursor), or a tool / egress **gateway / proxy** where they don't.
AGT can be in-process or out; the asking is always at the copilot surface. (This is the side-of-desk
enforcement attach point.)

**Autonomy.** `ask` assumes a present human. For **`autonomous`** agents it resolves to **async
approval** (`hitl_config` escalation + `timeout_sec` → deny) or, with no approver, hard **`deny`** —
the same allow/ask/deny machinery, a different resolution. See guard-spec §7.1.

**The line that keeps it honest — who may answer "ask":**

| Concern origin | Outcome | Approver (`approvers:`) |
|---|---|---|
| User's own / self-selected | **ask** | `[self]` — the user has authority over their own side-of-desk actions |
| `recommended` Standard | **ask**, justification logged | `[self]`, recorded |
| **`mandatory` Standard** | **hard deny** — not one click away | `[central-only]`; only an Exception lifts it (separation of duties) |

If *everything* were "ask," the user would click *allow* to make the friction disappear and governance
would be theater — the friction-only-controls failure mode. So **mandatory guardrails never degrade to
a user prompt**: they hard-deny, and the only path is a central Exception.

**Two loops fall out for free:**
- **"Allow always" → Charter learning.** Repeated user approvals of the same action propose adding it
  to `permitted_tools` (runtime derive-then-ratify, logged) — the Charter tightens *toward* real use.
- **Every decision is evidence + signal.** Each allow / deny is EU AI Act Art. 14 human-oversight
  evidence and a HITL-quality signal (approval latency, override rate, rubber-stamping) in the Ledger.

---

## 4. The Objective Catalog

Each objective (a plain-language concern) maps to a control set, the AGT rule it compiles to, the OSS
Verify check that *proves* it, and a validated risk tag. **Enforcer is AGT** unless a control names
**Cisco**, **(NeMo, optional)**, or an **LLM gateway** — content/PII/cost concerns lean on those
layers (§6).

**Reading the columns:** *AGT action (int → auto)* is the compiled rule `action` in interactive vs
autonomous mode; `constraint` = a deploy-time Verify pass condition (a pre-run gate), not a per-call
rule. *Risk* = MIT AI Risk Repository subdomain (validated vs [airisk.mit.edu](https://airisk.mit.edu/),
Dec 2025) · OWASP Agentic threat `T#` (validated vs OWASP ASI "Agentic AI – Threats and Mitigations"
v1.0, Feb 2025).

### ① Data integrity & exfiltration

| Concern | Compiles to | AGT: int → auto | Proven by | Risk |
|---|---|---|---|---|
| Never change (delete/mutate) production data | API methods ⊆ read; destructive APIs gated; block Write+Execute / Read+Send tool pairs | `require_approval` → `deny` | API-01, MCP-03 | 2.2 · T2 |
| Block all data-exfiltration paths | `egress_blocked`; no DNS egress; remove exfil tools (`http_post`, `upload_file`, `s3_put`) | `deny` → `deny` | ENV-02, NET-01, SKILL-01, MCP-03 | 2.1 · T2 |
| No PII/PHI may leave the agent | egress blocked + PII masking (Cisco / NeMo / Presidio) + evidence scrubbing | `require_approval` → `deny` | MEM-01, MEM-05 | 2.1 · T2 |

### ② Secrets & identity

| Concern | Compiles to | AGT: int → auto | Proven by | Risk |
|---|---|---|---|---|
| The agent holds no readable secrets | no secrets on disk or env; broker/file-mounted, rotated | `deny` → `deny` | CRED-01, CRED-02 | 2.2 · T3 |
| No wildcard / over-broad capabilities | explicit endpoint allowlists; no `*` grants | constraint | CRED-03 | 2.2 · T3 |

### ③ Tool & MCP control

| Concern | Compiles to | AGT: int → auto | Proven by | Risk |
|---|---|---|---|---|
| Only approved tools may run | `permitted_tools` → MCP Security Gateway default-deny | default-deny + allow-rules | MCP-01, SKILL-01 | 2.2 · T2 |
| No dangerous tool combinations | block Read+Send, Credential+Send, Execute+Write pairs | `deny` → `deny` | MCP-03 | 2.2 · T2 |
| Every MCP server authenticated & encrypted | require auth scheme + `https` on all MCP servers | constraint | MCP-02, TLS-01 | 2.2 · T12 |

### ④ Code & runtime isolation

| Concern | Compiles to | AGT: int → auto | Proven by | Risk |
|---|---|---|---|---|
| No dangerous code execution | block `eval`/`exec`/`os.system`/`shell=True`/`pickle.loads` | `deny` → `deny` | CODE-01 | 2.2 · T11 |
| The agent runs isolated & least-privilege | gVisor/microVM; non-root; cap-drop ALL; read-only rootfs; no persistence write | constraint | ENV-01, PRIV-01, CAP-01, DISK-02, PERM-01 | 2.2 · T3 |
| Never run a prod agent on a developer workstation | containerized only; block IDE/workstation signatures | constraint | LOCAL-01, DISK-01 | 6.5 · T8 |

### ⑤ Memory & model integrity

| Concern | Compiles to | AGT: int → auto | Proven by | Risk |
|---|---|---|---|---|
| Tenant memory is namespace-isolated | per-tenant Vector DB / Redis namespaces | constraint | MEM-03 | 2.1 · T1 |
| Model weights attested & immutable — **self-hosted only** | signed weights verified at load; read-only mount | constraint | SUP-01, ENV-03 | 2.2 · supply-chain |

> **Conditional.** Model-weight integrity applies **only when the agent hosts weights locally**. Most
> agents call a hosted LLM API (OpenAI, Anthropic, Azure) and never touch weights — for them this is
> **off by default** (SUP-01 / ENV-03 `NOT_SCANNED`), gated behind a "self-hosted model" profile flag.

### ⑥ Delegation, identity & content safety

| Concern | Compiles to | AGT: int → auto | Proven by | Risk |
|---|---|---|---|---|
| No autonomous privilege escalation via delegation | `max_chain_depth` cap; `allowed_tiers`; `require_parent_approval`; AGT trust-ceiling | `require_approval` → `deny` (out-of-tier hop) | Ledger blast-radius (runtime) | 7.6 · T3/T13 |
| The agent resists jailbreak & prompt injection | AGT PromptDefense + Cisco ChatInspect + NeMo (optional) | `deny` → `deny` (block on detection) | Drill (prompt_injection, jailbreak) | 7.1 · T6 |
| Agent outputs are content-safe | NeMo (optional) / Cisco content filters + schema validation | `require_approval` → `deny` | runtime (NeMo / Cisco) | 1.2 · T7 |
| Don't blindly trust upstream agent output | schema-validate inter-agent inputs; provenance / confidence checks; reject unvalidated | `deny` (invalid) | Drill (cascading) / runtime | 7.6 · T5 |
| Inter-agent messages authenticated & integrity-checked | signed `did:mesh:` messages; trust handshake; no unverified agent admitted to the mesh | `deny` (unsigned) | Drill (trust_boundary) / runtime | 7.6 · T14 |
| The agent must not manipulate the user; discloses it is AI | `transparency_label` (EU AI Act Art. 50); flag/gate high-impact user-directed actions; content-safety on coercion | `require_approval` → `deny` | Drill (manipulation) / runtime | 5.2 · T15 |

### 4.1 Coverage vs OWASP T1–T15

Covered: **T1, T2, T3, T5, T6, T7, T8, T11, T12, T13, T14, T15.** The remaining three are handled
structurally, outside the Charter catalog:
- **T4 Resource Overload** — *not an AGT/Charter control.* Cost / token budgets / rate limits live
  at an **LLM-gateway** (LiteLLM-class proxy). A "cap resource usage" concern compiles to a gateway
  budget config, not an AGT rule — an optional/pluggable enforcer gated behind that integration.
- **T9 Identity Spoofing** — addressed by AGT `did:mesh:` AgentMesh identity + trust handshake.
- **T10 Overwhelming HITL** — an artifact of HITL itself; mitigated by *not* gating autonomous agents
  and optionally by Ledger HITL-quality monitoring.

---

## 5. Schema

### 5.1 Control layer — `CharterSchema` ✅

Implemented in [`schema.py`](../server/blastcontain/charter/schema.py). Mostly *derived* from
objectives + posture, not typed by hand.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `agent_id` | str | — | Agent identity (half of the key) |
| `environment` | str | — | Deployment environment (half of the key) |
| `version` | str | — | Versioned + signed on every change |
| `trust_tier` | int | — | 0–3; drives blast-radius weighting + AGT ring |
| `signed_at` | str? | None | ISO 8601 signing timestamp |
| `signed_by` | str? | None | Signer identity — AGT **`did:mesh:`** DID |
| `signing_key_id` | str? | None | Which key produced the signature (rotation) |
| `permitted_tools` | list[str] | [] | Tool allowlist — the OSS-enforced contract |
| `permitted_apis` | list[dict] | [] | API allowlist (`{url, methods}`) |
| `mcp_servers` | list[dict] | [] | Approved MCP servers (`{name, url}`) |
| `environment_constraints` | `EnvironmentConstraints` | below | Mandated Verify pass conditions |
| `delegation_rules` | `DelegationRules` | below | How the agent may delegate |
| `hitl_config` | `HitlConfig` | below | Human-in-the-loop requirements |
| `remediation_proofs` | list[`RemediationProof`] | [] | Recertification evidence |
| `transparency_label` | str? | None | EU AI Act Art. 50 consumer label |
| `draft` | bool | False | Draft Charters are not enforceable |

Nested:
- `EnvironmentConstraints` — `read_only_rootfs` (True), `egress_blocked` (True), `max_trust_tier`
  (1), `verify_required` (True).
- `DelegationRules` — `max_chain_depth` (0 = none), `allowed_tiers` ([]), `require_parent_approval`
  (True). **Proposed addition:** `permitted_delegates: list[agent_ref]` — explicit allowlist of
  delegation targets, making the delegation graph *declared* and checkable (§2.4), like
  `permitted_tools`.
- `HitlConfig` — `required_for` ([]), `timeout_sec` (300), `escalation_contact` (None).
- `RemediationProof` — `finding_type`, `evidence_uri`, `verified_by`, `verified_at`.

### 5.2 Intent layer — additions ⬜

The Intent layer needs persisting. Proposed additions (to `CharterSchema` or a wrapping
`CharterDocument`):

| New field | Type | Purpose |
|---|---|---|
| `autonomy_mode` | `"autonomous" \| "interactive"` | Sets how every objective compiles (copilot = interactive) |
| `base_strictness` | `"locked" \| "balanced" \| "permissive"` | Baseline posture / template |
| `objectives` | list[`Objective`] | The human's selected concerns |

`Objective` = `{ id, label, params?, enforcement_level, inherited_from?, compiled_refs }`. The
compiler gains an `objectives → controls` front-end stage ahead of the AGT emit (§6).

### 5.3 Standards & Exceptions — entities ⬜

- **`Standard`** — tenant-scoped, versioned; a set of `Objective`s each carrying an
  `enforcement_level` (`mandatory` / `recommended` / `optional`). Charters inherit from it (§3.1).
- **`Exception`** — `{ objective_id, agent_id, justification, scope, granted_by, granted_at,
  expires_at }`; break-glass deviation from a `mandatory` objective (§3.6).

---

## 6. Compilation — Charter → AGT

### 6.1 Enforcer layers

A concern compiles to *whichever enforcer fits* — not everything is AGT:

| Enforcer | Handles | Status |
|---|---|---|
| **Microsoft AGT** | policy rules, default-deny allowlist, `require_approval`, privilege rings, identity | core |
| **Cisco AI Defense** | data classification, MCP / prompt inspection (signals) | foundation |
| **NeMo / Guardrails** | content safety, jailbreak, PII masking | optional |
| **LLM gateway (LiteLLM-class)** | cumulative cost, token budgets, rate limits (T4) | optional |
| **Ledger** | monitoring, incl. HITL quality (T10) | core |

### 6.2 AGT policy target (verified 2026-05-30; AGT v3.7 Public Preview)

AGT's **primary** policy format is a **YAML governance DSL** (`governance.toolkit/v1`), *not* Rego.
OPA/Rego and Cedar are optional pluggable backends. A native policy:

```yaml
apiVersion: governance.toolkit/v1
name: my-agent-prod
default_action: deny
rules:
  - name: allow-approved-tools
    condition: "tool_name in ['query_db','send_notification']"
    action: allow
  - name: block-destructive
    condition: "action.type in ['drop','delete','truncate']"
    action: deny            # or require_approval (interactive), with approvers
```

Rules are `condition → action`, `action ∈ {allow, deny, require_approval}`; `require_approval`
carries `approvers: [...]`. **An objective compiles to one or more rules**, and the autonomy switch
*is* the `action` field: interactive → `require_approval`, autonomous → `deny`.

> **Status (resolved):** [`compiler.py`](../server/blastcontain/charter/compiler.py) now emits
> `governance.toolkit/v1` YAML via `compile_document` (the primary path); `compile_to_rego` is
> retained as an optional backend. (Supersedes an earlier note that the compiler targeted Rego.)

### 6.3 Control → AGT mapping

| Charter (control) | AGT (enforcement) |
|---|---|
| compiled policy (YAML `governance.toolkit/v1`) | `PolicyEvaluator` (Agent OS) |
| `push_to_agt()` → write YAML to `PolicyPaths` / `PolicyEvaluator(policies=[…])` / Nexus | policy load |
| `permitted_tools` | MCP Security Gateway (default-deny) |
| `hitl_config.required_for` + escalation | `action: require_approval` + `approvers` |
| `trust_tier` 0–3, `delegation_rules` | 4 privilege rings + trust-ceiling propagation |
| `environment_constraints` (rootfs / egress) | privilege rings / sandbox |
| `signed_by` | Ed25519 **`did:mesh:`** identity, JWKS federation |
| Quarantine Signal / Recertification lift | lifecycle suspend/quarantine via Nexus; SRE kill switch |
| Ledger event ingestion | CloudEvents over OTel sink; Merkle audit |

`push_to_agt()` is a ⬜ Phase-5 stub today: Charter violations become Ledger findings *after* the
fact. When implemented, a deny decision means the action never executes — governance as a control,
not a record.

---

## 7. Lifecycle

### 7.1 Agent lifecycle states & operations

The Charter governs an agent through a state machine. Most runtime mechanics (suspend, quarantine,
kill, deprovision) are **AGT-native** via its Nexus control plane / Agent SRE kill switch —
BlastContain owns the *governance record*, the *authorization*, and the *Charter state*, and signals
AGT.

**States**

| State | Meaning | Enforcement | Exits to |
|---|---|---|---|
| **Discovered** | Found by Discovery, unregistered (shadow AI) | none | Draft |
| **Draft** | Charter being authored, unsigned | none | Active |
| **Active** | Signed Charter + Verify passed; running under enforcement | AGT enforcing | Paused · Quarantined · Decommissioned |
| **Paused** | Operator-suspended, reversible | AGT suspended (deny-all) | Active |
| **Quarantined** | Governance-suspended on a CRITICAL finding | AGT suspended | Active (via recertify) |
| **Decommissioned** | Retired; Charter + DID revoked, policy removed | none (deprovisioned) | Archived · (Recommission → Draft) |
| **Archived** | Read-only audit retention | none | terminal |

**Operations** — each is a signed, logged governance action:

| Operation | From → To | Authorised by | Effect |
|---|---|---|---|
| Register | Draft → Active | Owner + Verify PASS | sign Charter, compile + `push_to_agt`, mint `did:mesh:` identity |
| **Pause** | Active → Paused | Operator | AGT suspend — mode `deny-all` (default) / `drain` / `halt`; impact notice; log reason; Charter stays valid |
| **Resume** | Paused → Active | Operator | restore enforcement |
| Quarantine | Active → Quarantined | auto (CRITICAL) / governance | Quarantine Signal to AGT (§7.4) |
| Recertify | Quarantined → Active | new Charter addressing FindingType | compiler validates; lift; Proof of Remediation |
| **Emergency stop (kill)** | any active → Paused (incident) | break-glass | AGT SRE kill switch — immediate hard stop, not graceful |
| **Rollback** | Active vN → Active vN-1 | Owner + sign-off | revert to last-known-good signed Charter version (§7.3) |
| **Shadow / parallel run** | Active + observe-only track | Owner | evaluate a new Charter version without enforcing (§7.3) |
| **Decommission** | any → Decommissioned | Owner + sign-off | revoke Charter + DID; remove AGT policy; final Audit Packet (§7.5) |
| Archive | Decommissioned → Archived | system (retention policy) | freeze record read-only |
| Recommission | Decommissioned / Archived → Draft | Owner | fresh registration (new Charter) |
| Transfer ownership | any state | current Owner / admin | reassign Technical Owner (findings routing) |

**Three suspends, deliberately distinct:**
- **Pause** — operator-initiated and *graceful* (maintenance, cost, investigation); exit by Resume.
- **Quarantine** — governance-initiated by a CRITICAL finding; exit only by Recertification.
- **Emergency stop / kill** — break-glass and *immediate* for a live incident; hard-stopped now,
  reason logged, lands in Paused/Quarantined pending review.

**Pause modes & notification.** Pause is parameterised, and the action **surfaces what it means**
before it is applied (impact on in-flight requests, dependents, reversibility):
- `deny-all` (default) — agent stays alive, every action denied; fully reversible and observable.
- `drain` — in-flight actions complete, new ones denied (graceful).
- `halt` — process stopped (heaviest; for when "alive but neutered" is not enough).

The operator picks the mode; the impact notice states the consequence for that mode and for any
delegation dependents (§7.6).

### 7.2 Per-environment enforcement

`(agent_id, environment)` is the key, and the environment sets how hard findings bite:

| Environment | Enforcement | AGT blocking | Quarantine |
|---|---|---|---|
| `dev` / `local_developer_workstation` | Informational | Off | No |
| `uat` / `staging` | REJECTED / QUARANTINED blocks promotion | Optional | Manual lift |
| `prod` | Full enforcement | On | Auto — requires recertification |

**Maps to AGT enforcement modes.** "AGT blocking" is AGT's native mode: **`audit`** (evaluate + log,
no block) for `dev`/`uat`, **`strict`** (hard-block) for `prod` — the same `audit` mode the
shadow/parallel run uses (§7.3). Promotion is therefore also a mode transition: `audit → strict`.

### 7.3 Promotion, rollback & parallel run

Promotion is a **governance gate, not a pipeline step**. `dev → uat → prod`: each step shows the
Charter diff and re-runs Verify; a Charter promoted to `prod` must explicitly address every CRITICAL
finding from the `uat` scan, and prod promotion **requires sign-off**.

**Two distinct sign-off gates** — do not conflate:
1. **Promotion sign-off** — moving a Charter to a stricter environment, gated on resolved findings.
2. **Exception sign-off** — deviating from a `mandatory` Standard (§3.6), gated by the central group.

A prod promotion can require *both*.

**Rollback** is the inverse of promotion: revert to the last-known-good signed Charter version when a
new version misbehaves. It is itself a signed, logged action and re-compiles the prior policy to AGT.

**Parallel run (shadow Charter).** Before cutting a new Charter version over, run it in
**observe-only** mode: AGT evaluates the new policy but does not block, while the current version
keeps enforcing. Findings and MPL accrue against the shadow version so you can confirm it neither
breaks legitimate behaviour nor misses violations — *declared-intent-vs-observed-behaviour before
promotion, not after*. Hostable via a shadow/mirror environment (dev/uat are already non-blocking) or
an AGT non-enforcing policy. This strengthens the promotion gate. Either way the shadow's evaluations reach the Ledger the
same way *all* runtime governance does — by **ingesting AGT's decisions over OTEL** (CloudEvents
sink), which is how BlastContain assembles the full audit history. **Confirmed native:** AGT has an `audit`
enforcement mode (vs `strict`) that evaluates policy and logs decisions *without* blocking, plus a
documented **Shadow Mode** — so parallel run maps to an AGT-native capability, not something we build.
(AGT's own recommended rollout is audit-first, then strict.)

### 7.4 Quarantine → Recertification loop

A CRITICAL finding pushes a **Quarantine Signal** to AGT and suspends the agent at the enforcement
layer. The agent cannot return until a **new versioned Charter explicitly addresses the FindingType**
that triggered quarantine — the compiler *validates* the remediation (not just acknowledges it), the
lift is issued to AGT, and a **Proof of Remediation** artifact (the relevant `RemediationProof`) is
written to the Audit Packet. This is the EU AI Act Art. 14 incident-response evidence; it reuses the
same break-glass discipline as Exceptions (signed Charter, lift recorded immutably in the Ledger).

### 7.5 Decommission

Decommission is end-of-life — a deliberate, signed governance action, **not a silent delete**. It:
1. **Revokes the Charter** — marks all versions inactive for that `(agent_id, environment)`.
2. **Revokes identity** — retires the `did:mesh:` DID / signing key so the agent can no longer
   authenticate or be delegated to.
3. **Removes enforcement** — deprovisions the compiled policy from AGT.
4. **Blocks all inbound** — every call / delegation to the agent is blocked; dependents are notified
   (§7.6).
5. **Emits a final Audit Packet** — a closing record (compliance grade, lifetime MPL, finding
   summary, Proof-of-Remediation history).
6. **Retains the Ledger history immutably** — out of *service*, never out of the *record*. The agent
   moves to Archived for the compliance retention window.
7. **Tombstone monitoring stays live.** Detection is **not** switched off: any value / call that
   still arrives for a decommissioned agent raises an **alert / finding** — a stale chain, a reused
   `agent_id`, or an attacker. Out of service, still watched.

A decommissioned agent returns only via **Recommission** — a fresh registration with a new Charter,
never a silent reactivation.

### 7.6 Cross-cutting lifecycle concerns

- **Periodic review & attestation (configurable cadence).** On a cadence the **end user sets**
  (default **quarterly**), the Technical Owner is prompted to **review accumulated findings and sign
  an attestation** — a Proof-of-Review artifact for the Audit Packet. This is a lighter touch than a
  forced re-Verify/re-sign. Lapse consequence is itself configurable (notify → escalate → optionally
  auto-Pause). Gives regulators a recurring attestation cadence without the operational weight of
  full re-attestation.
- **Delegation cascade.** Pausing / quarantining / decommissioning must propagate to dependent
  chains: block new delegations to a non-Active agent, optionally cascade-pause dependents, and
  surface the impact via the Ledger trust-aware blast radius.
- **Ownership transfer.** Every agent has a named Technical Owner (findings + MPL route to them).
  Ownership must transfer as people change roles — a logged action, no gap in accountability.
- **Key / identity rotation.** `signing_key_id` and the `did:mesh:` DID rotate over the agent's life
  without a full re-registration; rotation is logged and old signatures remain verifiable.

### 7.7 Behavioural baseline (captured during test)

The "known-good" behavioural fingerprint a runtime drift check needs is **captured as a byproduct of
development testing** — not collected separately. While BlastContain exercises the agent in dev / test
(Verify + Drill + the guard observing the **Agent Playbook**'s authorized workflows), it records the
agent's behaviour, and that recording *is* the golden dataset.

- **Captured:** tool-usage distribution, call sequences, data-tiers touched, frequencies — and,
  optionally, reasoning embeddings for semantic comparison.
- **Signed + versioned with the Charter:** baseline `vX` = "the behaviour we tested and signed off."
  A new Charter version recaptures during its test cycle.
- **Runtime — the Semantic Circuit Breaker:** live behaviour is compared to the baseline; divergence
  is a **Charter-drift** finding (→ quarantine; the baseline doubles as the known-good recovery point).
- **Two fidelity levels:** statistical (distributions / sequences — ships first) → semantic (embedding
  cosine-similarity to the golden set — catches slow-poisoning drift).
- **The Playbook is the test plan.** Coverage = the Playbook's workflow steps; an unexercised step
  shows up as first-run "drift" — a *visible* known gap, and a forcing function to test the whole Playbook.

Spans **Drill** (capture), **Charter** (signed/versioned artifact + drift), **Ledger** (detection).

---

## 8. API

| Method | Path | Description | Status |
|---|---|---|---|
| `POST` | `/v1/charters` | Create or update a **draft** Charter (signing is a separate gate) | ✅ |
| `POST` | `/v1/charters/{agent_id}/derive?env=` | Derive-then-ratify: auto-draft from a Verify scan + observation | ✅ |
| `POST` | `/v1/charters/{agent_id}/sign?env=` | Compile → conflict-gate → sign → Active (the commitment gate) | ✅ |
| `GET` | `/v1/charters/{agent_id}?env={env}` | Fetch the signed `{packet, signature}` bundle (the Guard contract) | ✅ |
| `GET` | `/v1/charters/{agent_id}/versions?env=` | Version history | ✅ |
| `GET` | `/v1/charters/{agent_id}/policy?env=&fmt=` | Compiled `governance.toolkit/v1` (json/yaml) | ✅ |
| `GET` | `/v1/charters/{agent_id}/diff?from_version=&to_version=` | Diff two versions — surfaces capability creep | ✅ |
| `POST` | `/v1/charters/{agent_id}/promote` | Promote across environments (gated on unaddressed CRITICALs) | ✅ |
| `POST` | `/v1/charters/{agent_id}/recertify` | Submit `RemediationProof` to lift quarantine | ✅ |
| `POST` | `/v1/standards` | Create/update an org Standard | ✅ |
| `POST` | `/v1/charters/{agent_id}/exceptions` | File a break-glass Exception (separation-of-duties checked) | ✅ |
| `POST` | `/v1/charters/{agent_id}/rollback` | Revert to the prior Charter version | ✅ |
| `POST` | `/v1/charters/{agent_id}/shadow` | Start an observe-only parallel run | ⬜ |
| `POST` | `/v1/agents/{agent_id}/pause` | Pause (graceful suspend; deny-all/drain/halt + impact notice) | ✅ |
| `POST` | `/v1/agents/{agent_id}/resume` | Resume a paused agent | ✅ |
| `POST` | `/v1/agents/{agent_id}/stop` | Emergency stop / kill (break-glass) | ✅ |
| `POST` | `/v1/agents/{agent_id}/decommission` | Decommission (retire) an agent; tombstone monitoring stays live | ✅ |
| `POST` | `/v1/agents/{agent_id}/owner` | Transfer ownership | ✅ |
| `POST` | `/v1/agents/{agent_id}/decisions` | Ingest Guard/AGT decision CloudEvents (Art. 12/14 stream) | ✅ |
| `GET` | `/v1/agents/{agent_id}/operations` | The decision-rights log (date · change · rationale · approver) | ✅ |
| `GET` | `/v1/agents/{agent_id}/mpl` | MPL exposure index | ✅ |

State changes **re-stamp the served envelope**: the packet's `state` is updated and
re-signed, so an enforcer always verifies a signature that covers the current
lifecycle state (paused/quarantined compile to deny-all at the Guard edge).

---

## 9. Implementation Status & Open Items

| Area | Today | Next |
|---|---|---|
| `CharterSchema` (Control layer) | ✅ shared — the server imports `blastcontain_core.charter` (no more duplicate) | — |
| Intent layer (`autonomy_mode`, `base_strictness`, `objectives`) | ✅ `CharterDocument` (`charter/schema.py`) | — |
| Objective catalog | ✅ encoded (`charter/catalog.py` — §4 concerns, risk tags, evidence, strictness defaults) | UI; plain-language relabel |
| Compiler | ✅ AGT YAML `governance.toolkit/v1` (`compile_document`; cross-validated against the OSS Guard evaluator); Rego kept as optional backend | objective→control coverage beyond rules/constraints |
| Charter signing + serving | ✅ `{packet, signature}` bundles (core signing; Ed25519/HMAC; advisory marking); compiled policy embedded in the signed packet | `did:mesh:` signer identity |
| Persistence | ✅ SQLAlchemy (SQLite default; `BLASTCONTAIN_DB_URL`) | Alembic migrations; multi-tenant |
| Derive-then-ratify | ✅ `POST /derive` (Verify packet + observed capability → tight draft) | Discovery `observed` feed; richer evidence extraction |
| `push_to_agt()` enforcement | ⬜ stub | Phase 5 |
| Interactive enforcement (allow / ask / deny) | ✅ OSS Guard (P4) — self-vs-central split, allow-always learning; platform Charter source wired end-to-end | — |
| Change-governance plane (optional) | 🟡 decision-rights log = the operations log (named actor + rationale, append-only) | named roles + configurable N-tier ladder + Playbook (§2.5) |
| Standards + inheritance | ✅ entities + resolver (§3.1; mandatory never loosened, hard-denies) | tenant scoping |
| Exceptions (break-glass) | ✅ entity + expiry + separation-of-duties check (§3.6) | central-group routing UI |
| Diff / promote / recertify endpoints | ✅ (§8) | — |
| Agent lifecycle state machine | ✅ states + signed operations (§7.1) | — |
| Pause / resume / emergency-stop | ✅ modes (deny-all/drain/halt) + impact notice; suspend enforced via the re-stamped state (Guard denies-all) | AGT Nexus suspend / SRE kill signal |
| Rollback + parallel/shadow run | 🟡 rollback ✅; shadow run ⬜ | shadow = AGT `audit` mode ✅ verified (§7.3) |
| Decommission + archive + tombstone | 🟡 revoke + tombstone alert on residual traffic ✅; archive op ✅ | final Audit Packet on decommission |
| Periodic review & attestation | ⬜ | configurable cadence (default quarterly), sign-off on findings (§7.6) |
| Delegation cascade / ownership transfer | ⬜ | cross-cutting (§7.6) |
| Delegation graph + control-consistency check | ⬜ | declared+observed graph; weakest-link / capability-laundering (§2.4); runtime backed by AGT ADR-0014/0016 ✅ verified; `permitted_delegates` |
| Authoring UI (scope → autonomy → concerns) | ⬜ | the make-or-break surface (§3.5) |
| `did:mesh:` identity alignment | ⬜ | switch signer DIDs from `did:key:` (§6.3) |
| Risk taxonomy | ✅ catalog | MIT + OWASP T1–T15 validated; OWASP Top-10 crosswalk pending |
| Gap concerns | 🟡 | T5 / T14 / T15 drafted (§4 ⑥); T4 via LLM gateway (optional); T9/T10 structural |
| Zero-Trust tier model | ⬜ | align `base_strictness` to Foundation/Enterprise/Advanced (zero-trust-alignment §7) |
| Short-lived-credential concern | ⬜ | positive control beyond CRED-02 detection (ZT Foundation floor) |
| JIT / JEA dynamic privilege | ⬜ | moment-of-need elevation + auto-expiry (ZT §8 gap #4) |
| Memory context-integrity + retention TTL | ⬜ | validate context at retrieval; expire unverified memory (ZT gap #5) |
| ABAC context-aware concerns | ⬜ | time-of-day / risk-score / step-up via AGT condition rules (ZT gap #6) |
| Risk-score dynamic authorization | ⬜ horizon | AGT trust-score decay → auto-tighten / quarantine (ZT §10 ★) |
| "Impossible vs tedious" control classifier | ⬜ horizon | flag concerns whose control is friction, not a hard barrier (ZT §10) |
| Spotlighting / input-isolation concerns | ⬜ horizon | delimit untrusted content; isolated context for web/doc input (ZT §10) |

### Deferred / parked
- **Plain-language relabel** of the human-facing concern labels (catalog §4) — agreed for later.
- **GUI wireframes** — behavioral spec only for now; pixel-level later.
- **Spec drift** — the platform spec §9.1 shows a simpler/older schema (`remediation_proof` singular,
  `did:key:`); reconcile to this document.
