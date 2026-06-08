# Plugin Registry — Guard's input (the second consumer)

> Companion to Drill's [plugin-registry-design.md](../../drill/docs/plugin-registry-design.md).
> Same approach: derive requirements from *real code*, hand them to the cross-cutting session that
> builds the registry in `blastcontain-core`. This is **input**, not the design.
>
> Grounded in: `telemetry.py` (`Sink`, `MemorySink`/`JsonlSink`/`LedgerSink`/`OtelSink`, `Emitter`),
> `augmentation.py` (`AVAILABILITY_FLAGS`), `adapters/` (`MCPMiddleware`, `ClaudeCodeHook`),
> `backends/` (`NativeBackend`, `AgtBackend`, `combine_with_agt`), `guard.py` (`from_config`).

## TL;DR (the three things that change the design)

1. **Cardinality must be per-kind.** Drill is "always many." Guard needs **both**: telemetry *sinks*
   and *adapters* are **many** (`active(kind) -> list`); *backends* and *policy sources* are **one**.
   The registry needs `cardinality: one | many` per kind — Guard is the proof Drill-only would miss it.
2. **Guard's `backends` are NOT registry citizens.** Native is a mandatory primary, AGT an optional
   secondary, composed by a fixed rule (stricter-wins / fail-closed). Two, both first-party, no
   third-party "enforcement backend." They belong with Drill's **Cage/Attacker** (your Open Q#6):
   pick-one strategies, not registry-managed. Guard's real registry citizens are **sinks + adapters**.
3. **License: flag, don't hard-block** (your Open Q#3). Guard runs inside the *user's own* agent with
   *their* licensed deps (a Datadog sink, a proprietary adapter). Hard-blocking non-permissive at
   `register()` would break legitimate use. Register + `blocked_reason`; let the consumer decide.

## 1. What Guard actually does today (the evidence)

Guard's **telemetry sinks** are the clean analog of Drill's **scorers** — the registry's value lands
there almost unchanged. Adapters are the second fit. Backends are the exception.

| # | What Guard does today (real code) | → Registry requirement | vs Drill |
|---|---|---|---|
| G1 | `Emitter` fans **each decision out to many sinks at once** (`MemorySink` + `JsonlSink` + `LedgerSink` + `OtelSink`), built in `from_config` | **Multiple plugins per kind** (sinks); `active("sink") -> list` | = R1 |
| G2 | `OtelSink` is used-if-present (`available=OTEL_AVAILABLE`; else `emit()` no-ops + counts `dropped`); `AgtBackend.available()` is **runtime** (endpoint reachable *now*) | **Availability first-class** — *and may be dynamic*, not only import-time | R2 **+ new (A1)** |
| G3 | Sinks enabled by config: `--log` → jsonl, `--blastcontain-url` → ledger, otel opt-in; **`MemorySink` is always on** (it backs the signed decision log) | **Config-driven enable** + a **mandatory/always-on** flag a config can't disable | R3 **+ new (A2)** |
| G4 | The signed decision-log packet should record **which sinks/adapters were active** (provenance), like Drill's `corpus_sources` | **Guard is a 2nd consumer of `manifest()`** — wants `name@revision` + `license` in the Audit Packet | = R4 |
| G5 | A host attaches the adapter for *its* surface (MCP, Claude Code) and could pick a sink (Datadog) by name | **Resolve-by-name**: `resolve(kind, name, config)` | = R5 |
| G6 | Sink fan-out order **doesn't matter** (independent); adapters independent. Guard has **no global priority** need | **Ordering is consumer policy, not a registry concern** | ≠ R6 (Guard votes no) |
| G7 | Sinks need construction args (`JsonlSink(path)`, `LedgerSink(url, agent_id)`); **adapters need the live Guard** (`adapter.bind(guard)`) | **Config + factory** (= R7) — *and the factory may need a runtime host context*, not just a static dict | R7 **+ new (A3)** |
| G8 | Guard runs in the **user's own agent**; they install sinks/adapters they're licensed for | **License declared + FLAGGED**, not hard-blocked | ≠ R8 (Guard votes flag) |
| G9 | Adding a sink/adapter today means **editing** `Guard.__init__` / `from_config` to wire it | **Self-registration** (decorator) + **entry points** so a 3rd-party sink/adapter needs *no* Guard edit | = R9 |
| G10 | **Backends** (`native` + optional `agt`) are composed by `combine_with_agt` (stricter-wins / fail-closed); exactly two, first-party, **pick-one(+optional)** | **Cardinality one** — *not* a registry citizen; a pluggable strategy like Drill's Cage | ≠ the doc's `Plugin <|-- Backend` |

## 2. Where Guard fits the proposed abstractions

The `Plugin` / `Registry` / `PluginInfo` draft fits Guard's **sinks** and **adapters** directly — they
already have identity, availability, and (for sinks) a fan-out consumer. The correction is which Guard
types are citizens:

```
REGISTRY CITIZENS (active/resolve, many, 3rd-party)   PICK-ONE STRATEGIES (not registry)
  ┌─────────────────────────────────────────┐         ┌──────────────────────────────────┐
  │ Sink     active("sink")   -> [Memory,    │         │ Backend   native (always) +        │
  │                               Jsonl,     │         │           agt (optional), fixed    │
  │                               Ledger,    │         │           compose: stricter-wins   │
  │                               Otel, …]   │         │ Source    from_yaml | from_charter │
  │ Adapter  resolve("adapter","mcp") / many │         │           | from_config | platform │
  └─────────────────────────────────────────┘         └──────────────────────────────────┘
        ↑ same shape as Drill's scorers                      ↑ same bucket as Drill's Cage/Attacker
```

`Sink` ≈ Drill's `Scorer` (many, availability-flagged, fan-out, third-party-extensible — Datadog,
Splunk, S3). `Adapter` ≈ a host-surface plugin (MCP, Claude Code, future LangChain/SK) — cardinality
*many* but usually resolved as one. Both want `is_available()`, `name`, `revision`, `license`, and
`@register(...)`. Backends/sources want none of it.

## 3. How Guard would use it (before → after)

```python
# Guard.from_config (guard.py) — BEFORE: hand-assembled sinks + per-source if-ladder
sinks = []
if cfg.log: sinks.append(JsonlSink(cfg.log))
if cfg.blastcontain_url and not cfg.dry_run and cfg.agent_id:
    sinks.append(LedgerSink(cfg.blastcontain_url, cfg.agent_id))
# (MemorySink always added in __init__; OtelSink only if the embedder wires it)

# AFTER
sinks = registry.active("sink", cfg)                 # G1,G2,G3 — enabled+available, MemorySink mandatory
# provenance into the signed decision log (the Audit Packet), like Drill's corpus_sources:
packet["sinks"] = [i.tag() for i in registry.manifest(cfg) if i.kind == "sink" and i.available]  # G4

# adapters — BEFORE: from .adapters import MCPMiddleware; guard.attach(MCPMiddleware())
guard.attach(registry.resolve("adapter", cfg.adapter, cfg))   # G5,G9 — incl. pip-installed adapters
```

`MemorySink` registers with `default_enabled=True, mandatory=True` (can't be turned off — it's the
audit buffer). `OtelSink` registers `default_enabled=False`, `is_available()` gated on the
`opentelemetry` import. Sinks/adapters gain `kind` + `license` class attrs and a `@register(...)`
decorator; `Guard` stops importing concrete sinks.

## 4. Guard's answers to the open questions

1. **Cardinality (the big one).** Required, per-kind. Guard = `sink: many`, `adapter: many`,
   `backend: one`, `source: one`. Don't model "always many."
2. **Ordering home.** Consumer policy, not registry. Guard fan-out is order-independent; keep
   `priority` optional and consumer-applied (Drill's authority order is *Drill's* rule).
3. **License strictness.** **Register + flag** (`blocked_reason`), don't hard-block. Guard's deps are
   the user's to license. A consumer (Drill) can still choose to *refuse* flagged plugins; Guard won't.
4. **Config schema.** A `{name: {enabled, …}}` dict is enough — Guard already nests `agt: {enabled,
   mode, endpoint}` exactly like that. No pydantic needed; a declared per-plugin config-schema (R7)
   for validation is a nice-to-have.
5. **Where it lives.** `blastcontain_core.plugins`. Guard already depends on `blastcontain-core`; a
   Drill-only package would force Guard to re-implement. Strong agree.
6. **Not-registry-citizens.** Confirmed and extended: Guard's **backends** *and* **policy sources**
   join Drill's Cage/Attacker — pluggable ABCs the user picks one of, no third-party install need.

**Three new requirements Guard surfaces (not in Drill's list):**
- **A1 — dynamic availability.** `is_available()` may be evaluated at *runtime* (AgtBackend endpoint
  reachability), not only at import. The manifest snapshots a point-in-time; don't assume it's constant.
- **A2 — mandatory plugins.** A kind may have an always-on member a config cannot disable (Guard's
  `MemorySink` backs the tamper-evident log). Needs a `mandatory=True` beyond `default_enabled`.
- **A3 — runtime context in the factory.** Some plugins need the live host, not just a config dict —
  an `Adapter` binds to its `Guard` (`adapter.bind(guard)`). The factory signature should allow an
  optional host/context, not only `config`.

## 5. Scope — what Guard does **not** need

- **No content/guardrail-scorer kind here.** Guard gates *actions*, not *content* (spec §11) — the
  guardrail-model plugins are Drill's / the data-trust plane's. If Guard ever consults one pre-action,
  it'd reuse *that* shared kind, not define a new one.
- **No management UI** (agrees with Drill) — the manifest in the signed log is enough for Guard.
- **No hot-reload** — Guard loads policy + sinks at construction; that covers every case.
- **Backends/sources stay out** — see §2; modelling them as registry plugins would add ceremony for
  a fixed, two-member, first-party set.

---

**TL;DR for the build session:** the registry fits Guard *through telemetry sinks and adapters*, which
behave like Drill's scorers (many, availability-flagged, fan-out, `name@revision@license`, self-
register). Add **per-kind cardinality** (Guard needs `one` too), keep **backends/sources out**
(pick-one strategies), **flag licenses rather than block**, and allow **dynamic availability +
mandatory plugins + a host-context factory**. Build that into `blastcontain-core.plugins` and Guard's
`from_config` collapses to `registry.active("sink", cfg)` with provenance for free.
