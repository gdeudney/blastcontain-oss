# BlastContain — Data Trust & Content Control Plane (seed)

**The data-flow governance axis — what goes *into* the agent's context, and what comes *out*.**
Version 0.1 — Seed | 2026-05-31 | Audience: Product, Engineering

> Seed spec. Captures the governing principles and the **pluggable guardrail-model** plugin model;
> the full ingestion/egress gauntlet (from the BlastContain article series — *Preparing your
> organization for LLMs*, Parts 1 & 2) is to be detailed later. **Status: ⬜ seed / mostly future.**
>
> Complements the Charter: the **Charter governs what the agent may *do*; the Content Control Plane
> governs what *data* it may take in and let out.** *"Security stops malicious data; data readiness
> stops the wrong data."*

> **Status legend:** ✅ done · 🟡 partial · ⬜ planned · ◇ future add-in

---

## 1. Governing principle — trust tiers are progressive, not prerequisite

The single most important design rule for this axis, because **most orgs have not classified their
data** and requiring them to is the adoption wall (the "data debt" from *Why agents fail*).

- **Conservative default.** Unclassified data is treated as *untrusted / sensitive* — safe-by-default.
  You are never *blocked* for not tiering, only more *restricted*. Classification **loosens**; it does
  not unlock safety. (Right incentive: tier to gain capability, not to be safe.)
- **Binary first.** Entry point is **trusted / untrusted** (or internal / external) — any org can do
  this today. The Tier 0–3 model is the maturity *ceiling*, not the floor.
- **Derive, don't ask.** Never make a human classify. Infer the tier from signals already present —
  Cisco AI Defense labels (which already feed MPL base values), Presidio PII detection, source system,
  data location — and **propose** a tier the human ratifies.
- **Value at zero maturity.** Works when nothing is tiered; gets more precise as tiers fill in.
  BlastContain *closes* data debt as a byproduct of running, not as a precondition.

> Two distinct "tiers," very different cost: **agent trust tier** (one number per agent — cheap, keep
> it) vs **data trust tier** (per source — expensive, so progressive/derived/optional per above).

## 2. Pluggable guardrail models ◇ *(first concrete add-in)*

Content scanning — jailbreak, prompt-injection, policy violation — is done by **swappable
guardrail-model plugins**, not a hardcoded scanner. Same optional/availability-flag pattern as Verify's
augmentation and the NeMo "Skin" layer (platform-spec §2).

| | |
|---|---|
| **Examples** | **Qwen3Guard** (jailbreak detection), Wildguard, NeMo Guardrails, Cisco ChatInspect — others register via the plugin interface |
| **Interface (sketch)** | `scan(content, direction) -> { violations[], severity, classification }` |
| **Feeds two things** | **(1)** data-trust scoring — content that fails a scan drops in trust / is quarantined; **(2)** runtime content-safety concerns — the "resist jailbreak" / "content-safe" Charter concerns (catalog ⑥) are *enforced by* whichever guardrail plugin is installed |
| **Deployment** | optional; absent → those concerns degrade to weaker/runtime-only checks (declared honestly, like NeMo) |

First milestone: ship **Qwen3Guard as the reference jailbreak plugin**, with a clean registration
interface so other models/tools slot in.

## 3. The gauntlet (to be detailed — from the article series)

Listed as scope to flesh out; each maps to article content.

**Data IN — ingestion ("the No-Fly List for data"):**
safety scan → instruction-smuggling detection → sensitivity classification → payload inspection
(images/metadata/OCR) → normalize & harden (strip HTML / Unicode confusables / zero-width) →
provenance hash. Scoped vector indices by tier+purpose; quarantine with `reason_code`; contradiction
detection + truth-arbitration (higher tier / recency wins; HITL for money/legal).

**Data OUT — egress:**
identity-filtered retrieval (see only what the user is authorized for); token budgets (≈80% high-trust
/ 20% untrusted); streaming output guards; destination policies (sensitivity → channel); **canary
documents** ("dye packs"); DLP + provenance labels; deletion propagation (kill zombie data); memory
TTL + approval for behavioural memory writes.

## 4. How it connects

- **Charter concerns** — "no PII may leave," "content-safe," "resist jailbreak & prompt injection"
  (catalog ⑥) are enforced partly here, by guardrail plugins (§2).
- **Ledger** — data-classification labels feed MPL base values (already, via Cisco); scan results and
  quarantine events are logged findings.
- **Guard** — the out-of-process **egress proxy** ([guard-spec](BlastContain-guard-spec.md) §9) is
  where some egress controls physically sit.
- **Data trust tiers** are a Ledger/Charter signal, derived per §1.

## 5. Status & roadmap

| Item | Status |
|---|---|
| Trust-tiers-progressive principle | ◇ design principle (this doc) |
| Pluggable guardrail-model interface | ◇ future |
| Qwen3Guard reference jailbreak plugin | ◇ future (first piece) |
| Ingestion gauntlet | ⬜ to detail |
| Egress controls (canaries, DLP, deletion propagation) | ⬜ to detail |
| Derived tier proposals (Cisco/Presidio → ratify) | ⬜ |

---

## See also
- [BlastContain-charter-spec.md](BlastContain-charter-spec.md) — the concerns this enforces (catalog ⑥)
- [BlastContain-guard-spec.md](BlastContain-guard-spec.md) — egress choke point
- Article series: *Preparing your organization for LLMs* Parts 1 & 2; *Data readiness as a product*
