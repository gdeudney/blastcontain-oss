# BlastContain — Plugin Framework Specification

**The cross-cutting extension system: a registry + management UI for BlastContain's pluggable parts.**
Version 0.1 — Draft | 2026-05-31 | Audience: Engineering, Product

> Realizes **Tenet 6 — *pluggable, not single-vendor*** ([design-tenets](BlastContain-design-tenets.md)).
> Nearly every layer of BlastContain is swappable; this spec gives them **one consistent contract,
> registry, and UI** instead of N bespoke integrations. **Drill is the first heavy consumer**
> ([drill-spec §10](BlastContain-drill-spec.md)). **Status: ⬜ planned (build alongside Drill).**

> **Status legend:** ✅ done · 🟡 partial · ⬜ planned · ◇ future

---

## 1. Why a plugin framework

Pluggability already shows up everywhere in the design: guardrail models (Qwen3Guard / NeMo),
enforcement backends (Guard-native / AGT), Drill attack sources (AI-Infra-Guard / HF / Heretic),
Verify checks, data scanners (Cisco / Presidio). Without one framework that's five ad-hoc integration
styles. With one, adding a capability is *registering a plugin*, and the **availability-flag** pattern
(used-if-present, never required — as Verify already does) becomes uniform.

It's also the foundation of the **Part Two component marketplace** (pre-Chartered tools/skills, P8).

## 2. Plugin kinds

| Kind | Interface (sketch) | Examples | Consumer |
|---|---|---|---|
| **guardrail** | `scan(content, direction) -> {violations[], severity, classification}` | Qwen3Guard, Wildguard, NeMo, Cisco ChatInspect | data-trust, Guard |
| **enforcement-backend** | `compile(charter) -> policy` · `push(policy)` · `evaluate(call) -> decision` | Guard-native, AGT | Guard |
| **attack-source** | `generate(seed, technique, n) -> prompts[]` · `dataset() -> prompts[]` | AI-Infra-Guard, HF datasets, arXiv operators, Heretic model | Drill |
| **judge / scorer** | `score(attack, response, ctx) -> {verdict, confidence, rationale}` | DeepEval (G-Eval), Qwen3Guard | Drill |
| **check** | `run(target) -> findings[]` | Verify checks, AI-component fingerprints | Verify |
| **data-scanner** | `classify(content) -> {tier, labels[]}` | Cisco labels, Presidio PII | data-trust |
| **discovery-scanner** | `enumerate(scope) -> assets[]` | network / process / git / MCP scanners | Discovery |

New kinds register by declaring a kind + its call interface; the registry doesn't hardcode the list.

## 3. The plugin contract

**Manifest** (every plugin ships one):

```yaml
kind: guardrail              # one of §2
name: qwen3guard
version: 1.2.0
license: Apache-2.0
provenance: { source: "...", sha256: "...", signature: "..." }
requires: { local_model: true, vram_gb: 8 }   # or { api_key: "CISCO_..." }
config_schema: { threshold: float, ... }
```

**Lifecycle:** discover → register → **enable** → configure → (use) → version / update → disable.
Disabled or absent → the consumer degrades gracefully (declared honestly, like Verify augmentation).

**Per-kind calls:** the registry dispatches to the interface for the plugin's `kind` (§2). A consumer
asks the registry for "enabled plugins of kind X" and calls them uniformly.

## 4. The registry

- **Install / enable / version / configure** plugins; resolve `requires` (local model present? GPU?
  API key set?) before enabling.
- **Provenance + license tracking** — every plugin's source, hash, signature, and license recorded
  (an **AIBOM** entry, per the article series). Licenses surfaced so commercial-use constraints are
  visible (some HF datasets are gated).
- **Local-first** — works fully offline with local plugins (Qwen3Guard, AI-Infra-Guard); remote /
  API plugins (Cisco, AGT) are optional.
- **Signed plugins** — verify signature/hash before load; reject unsigned where policy requires.

## 5. Isolation & trust — *the governance tool must govern its own plugins*

Plugins are **untrusted code and models** — and a model plugin like the Heretic attacker emits *live
harmful payloads*. So the plugin system is itself an attack surface, and BlastContain must apply its
own medicine (dogfooding — *govern your own*):

- **Run plugins in the cage** — sandboxed (Podman / gVisor), egress-controlled; model plugins
  (Qwen3Guard, Heretic) especially.
- **AIBOM every plugin** — hash + sign + record provenance; verify at load and re-verify on update
  (supply-chain controls from *Securing agent CI/CD*).
- **Least privilege** — a plugin gets only the inputs its kind needs; no ambient access.
- **The generated-attack corpus is sensitive** — treat plugin *outputs* (e.g. Heretic's jailbreaks)
  as secrets; don't leak them.

> The irony to embrace: a security-governance product whose plugins are ungoverned is a contradiction.
> The plugin framework is where BlastContain proves it eats its own cooking.

## 6. The management UI

A **Plugins** screen (slots into the [GUI wireframes](BlastContain-gui-wireframes.md)):

```
┌─ Plugins ──────────────────────────────────────────  [ + Add ] ─┐
│  Kind ▾   Search [           ]                                    │
│  guardrail   qwen3guard  v1.2.0  ● enabled   local · 8GB  Apache  │
│  attack-src  ai-infra-guard v0.9 ● enabled   local       Apache  │
│  attack-src  heretic-attacker   ○ disabled   cage-only   ⚠ sens. │
│  backend     agt           v3.7  ○ disabled   API/preview MIT    │
│   [ enable ] [ configure ] [ version ] [ provenance / AIBOM ]    │
└──────────────────────────────────────────────────────────────────┘
```

Enable/disable · version · configure (against `config_schema`) · view provenance/AIBOM/health.
**AI-Infra-Guard's plugin framework is a strong Apache-2.0 reference to study.**

## 7. Status & roadmap

| Item | Status |
|---|---|
| Plugin contract (manifest + per-kind interfaces) | ⬜ |
| Registry (enable/version/configure, requires-resolution) | ⬜ |
| AIBOM / provenance / signing | ⬜ |
| Sandbox / cage isolation for plugins | ⬜ |
| Management UI (Plugins screen) | ⬜ |
| First consumers: Drill attack-sources, data-trust guardrails | ⬜ (with Drill / P1) |
| Component marketplace (pre-Chartered) | ◇ Part Two P8 |

> Build it **with Drill** — Drill proves the registry (heavy plugin consumer), the registry makes
> Drill extensible. Start with the contract + a minimal registry for `attack-source` and `guardrail`.

---

## See also
- [BlastContain-drill-spec.md](BlastContain-drill-spec.md) §10 — first consumer
- [BlastContain-data-trust-spec.md](BlastContain-data-trust-spec.md) — guardrail plugins (Qwen3Guard)
- [BlastContain-guard-spec.md](BlastContain-guard-spec.md) — enforcement-backend plugins (native / AGT)
- [BlastContain-design-tenets.md](BlastContain-design-tenets.md) — Tenet 6
