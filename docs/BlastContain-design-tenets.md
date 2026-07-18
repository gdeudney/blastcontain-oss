# BlastContain — Design Tenets

**The principles BlastContain is built on. When a design decision is unclear, these are the tiebreakers.**
Version 0.1 — Draft | 2026-05-31 | Audience: Product, Engineering

---

## Tenet 1 — Governance is a byproduct, not a prerequisite
### *(trust is derived, not demanded)*

**The rule.** BlastContain must deliver value when the customer has done **zero** upfront governance
work — no classified data, no defined baselines, no hand-authored policy. The platform **derives**
governance from what it observes and lets the human **ratify** it, rather than **requiring** the human
to produce governance artifacts before getting value. Governance maturity accrues as a *side effect of
running the product*, not as an entry toll.

**Why it's a tenet.** Most organisations carry data debt and process debt (see *Why agents fail in
organizations*). Any tool that demands classified data, authored policies, or a defined behavioural
baseline *before* it works hits the readiness wall and dies in pilot. This is the wall that kills agent
projects — and routing around it is BlastContain's core differentiator: **it closes that debt by
running, instead of demanding it closed first.** That's a selling point, not a compromise.

**The test.** For any feature, ask: *does this require the customer to do governance homework before
they get value?* If yes, redesign it to **derive-and-ratify**. And: *the secure default must be the
zero-effort default — effort should buy capability, not safety.*

**How it already shows up across the design:**

| Thing | The "demanded" way (rejected) | The "derived" way (BlastContain) |
|---|---|---|
| **Trust tiers** | classify all data into Tier 0–3 first | conservative default (untrusted); binary-first; tiers *derived* from Cisco/Presidio/source, human ratifies ([data-trust §1](BlastContain-data-trust-spec.md)) |
| **Charters** | author a policy per agent from blank | auto-drafted from Verify/Discovery scan → one-click ratify (charter-spec §3.5) |
| **Behavioural baseline** | run a separate baseline-collection / ML-training project | *captured* during dev/test as a byproduct (charter-spec §7.7) |
| **Catalog / least-privilege** | hand-maintain allowlists | observed reality reconciled to intent; "allow always" tightens the Charter toward real use |

**Corollaries.**
- **Conservative when unknown.** Absent information, assume the stricter posture (untrusted /
  sensitive). Safe-by-default; never blocked, only more restricted.
- **Effort buys capability, not safety.** You do the classification / tiering work to *gain*
  capability — never to *become* safe. This keeps the incentive aligned and prevents the "rubber-stamp
  to remove friction" failure.
- **Ratify, don't author.** The 90% path is a human approving a derived artifact, not producing one.
- **Progressive maturity, value at every rung.** Binary → tiers; statistical → semantic; informational
  → enforced. Each rung is useful on its own; the next rung is an upgrade, not a gate.

---

## Related tenets

Operative principles we already build by — listed here so they have a home; expand as needed.

| # | Tenet | In short | Applied in |
|---|---|---|---|
| 2 | **Intent, not controls** | Humans declare *outcomes* in plain language; the system compiles to technical controls. Security policies die from friction. | charter-spec §1, §3 |
| 3 | **The secure default is the easy default** | The pre-selected, zero-effort path is the safe one. (Corollary of Tenet 1.) | charter-spec §3.5 |
| 4 | **Impossible, not tedious** | Prefer a control that *removes* a capability over one that throttles it; friction-only controls fail against agentic attackers. | zero-trust-alignment §3 |
| 5 | **Derive then ratify** | Observe reality, propose, let a human confirm — never demand authored input. (Mechanism of Tenet 1.) | charter-spec §3.5, §3.7 |
| 6 | **Pluggable, not single-vendor** | Enforcement backends (AGT), guardrail models (Qwen3Guard/NeMo), gateways are swappable. Don't bet the product on one vendor. | **plugin-spec**, guard-spec §8, data-trust §2 |
| 7 | **Two planes, two fronts** | Separate *change-governance* from *runtime*; enforce *in-process* for the common case + *out-of-process* for the dangerous few. | charter-spec §2.5, guard-spec §3 |
| 8 | **Named accountability, no vacuum** | Every agent has named owners; "the same name in two roles is an ownership vacuum." | charter-spec §2.5 |

---

## See also
- [BlastContain-charter-spec.md](BlastContain-charter-spec.md) · [BlastContain-data-trust-spec.md](BlastContain-data-trust-spec.md) · [BlastContain-guard-spec.md](BlastContain-guard-spec.md)
- [BlastContain-roadmap.md](BlastContain-roadmap.md) — how the tenets sequence into work
- Article series: *Why agents fail in organizations*, *Data readiness as a product*
