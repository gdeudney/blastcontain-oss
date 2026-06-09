# BlastContain Verify — Design Roadmap

A sequenced plan for the seven design gaps identified in the 2026-06 review.
Companion to [`architecture.md`](architecture.md) (how it's built) and
[`spec.md`](spec.md) (what each check does). Each item below has a concrete
design, acceptance criteria, and a t-shirt effort size.

**Guiding principle (the review's core finding):** the engineering quality
currently outpaces the moat. The differentiators — agent-specific checks,
Charter allowlisting, blast-radius modelling, signed attestation — get the
investment; the generic checks get delegated or explicitly demoted to
"baseline hygiene."

---

## Sequencing at a glance

| Phase | Items | Theme | Target release |
|---|---|---|---|
| 0 — Quick wins | 6 (drift tests), 5 (signing honesty), 7 (augmentation policy) | Days of work, all verify-scoped, no design risk | 0.3.x |
| 1 — Moat, part 1 | 2a (Charter → MCP-01) | Small, high-value: the schema already exists | 0.4.0 |
| 2 — Foundation | 3 (registry + typed contract + plugins) | Enables 1, 2b, 4 without doing them twice | 0.4.0 |
| 3 — Policy | 4 (per-environment verdict policy) | Depends on 3 for clean wiring; recorded in the packet | 0.4.0 |
| 4 — Moat, part 2 | 2b (blast-radius model), 2c (tier wiring) | Needs a short design spec first | 0.5.0 |
| 5 — Delegation | 1 (best-of-breed engines for generic checks) | Built on the registry + augmentation pattern | 0.5.0 |

Phases 1 and 2 can run in parallel — Charter wiring is additive to
`mcp.run()`'s existing `permitted_tools` parameter and does not need the
registry refactor.

---

## Phase 0 — Quick wins (days, no design risk)

### Item 6 — Doc/count drift tests  *(size: S)*

The `generator_version` staleness bug and the hand-asserted "27 checks across
14 categories" are the same failure mode: facts duplicated in prose with no
test pinning them to code.

**Plan — one new unit test module, `tests/unit/test_doc_consistency.py`:**

1. **Canonical check inventory in code.** Add `ALL_CHECK_IDS: frozenset[str]`
   to `constants.py` (it is the natural home — `MIT_RISK_MAP` already lists
   most IDs). The scanner and reporters do not change.
2. **Spec ↔ code:** parse `docs/spec.md` for `#### <ID> —` headings; assert
   the extracted set equals `ALL_CHECK_IDS`.
3. **README ↔ code:** extract the "N security checks across M categories"
   claim with a regex; assert N == `len(ALL_CHECK_IDS)` and M == number of
   distinct check-ID prefixes.
4. **Version coherence:** assert `pyproject.toml` version ==
   `blastcontain_verify.__version__`, and that `CHANGELOG.md` contains a
   heading for it. (The audit packet already uses `__version__` after the
   0.3.1 fix — this pins the regression.)

**Acceptance:** a PR that adds a check or bumps a version with stale docs
fails CI with a message naming the drifted file.

### Item 5 — Signing honesty  *(size: S)*

The default HMAC key makes the signature integrity-only, not attestation.
Keep the fallback (it is right for local dev) but make the distinction
machine-readable and impossible to miss.

**Plan:**

1. **`signature.advisory: true`** — in `blastcontain_core.signing.sign_packet`,
   set this field whenever the default `local-verify-default` key signs the
   packet. Downstream tooling (and the Ledger) can then refuse advisory
   packets mechanically rather than by parsing a stderr warning.
   Schema bump 1.1 → 1.2 (additive).
2. **`--require-signing` CLI flag** — exit 3 before scanning if no real key
   source (`BLASTCONTAIN_SIGNING_KEY_PATH` / `_PEM` / non-default
   `BLASTCONTAIN_SIGNING_KEY`) is configured. For CI attestation pipelines
   that must never emit an advisory packet.
3. **Docs bluntness** — one paragraph in README + SECURITY.md: *"By default
   packets are integrity-checked, not attested. Attestation requires an
   Ed25519 key you manage."* No marketing language that implies otherwise.

**Acceptance:** `verify_packet` callers can distinguish advisory from attested
without env knowledge; `--require-signing` fails fast in a clean environment.

### Item 7 — Augmentation acceptance policy  *(size: S)*

The cisco→litellm exact-pin chain cost a CVE-clean default. The quarantine
architecture absorbed it; the *selection* process is what needs hardening.

**Plan — process + one CI tweak, no product code:**

1. **Checklist in `CONTRIBUTING.md`** ("Adding an augmentation"). A candidate
   package must pass before being added to any extra:
   - `pip-audit` clean on its full resolved tree, today;
   - no `==` pins of widely-shared libraries (the litellm lesson);
   - imports cleanly with no network/filesystem side effects under
     `--network none` + read-only HOME (the tldextract lesson);
   - tree size budget: < 25 transitive packages or an explicit justification;
   - a graceful-degradation path exists (flag in `augmentation.py`, dependent
     checks SKIP with an enable hint).
2. **Visibility CI for opt-in extras** — a non-gating job in `security.yml`
   that resolves `verify[cisco]` and runs `pip-audit` on the result,
   publishing the report as an artifact. The known-accepted CVEs stay
   documented in SECURITY.md; *new* ones become visible weekly instead of
   surprising an opt-in user.

**Acceptance:** the checklist exists and is linked from the spec's decision
log; the weekly job produces an auditable report for the cisco tree.

---

## Phase 1 — Charter wiring: make MCP-01 real  *(item 2a, size: M)*

The highest-leverage moat work: the schema (`blastcontain_core.charter.CharterSchema`
with `permitted_tools`, `trust_tier`, delegation rules) already exists, the
check logic in `checks/mcp.py` already accepts `permitted_tools`, and the
scanner has the explicit seam (`permitted_tools=None,  # Phase 3: pull from
Charter`). This is wiring, not invention.

**Plan:**

1. **`--charter PATH` flag + `charter:` config key.** Load YAML/JSON, validate
   against `CharterSchema` (pydantic-or-dataclass validation lives in core).
   Malformed charter → stderr warning + treated as absent (consistent with the
   config-file degradation decision), recorded as a SKIP reason on MCP-01.
2. **Feed `cfg.charter.permitted_tools` into `mcp.run()`.** MCP-01 then fires
   on observed tools outside the allowlist — the code path already exists.
3. **Tier linkage:** when the charter declares `trust_tier` and `--max-tier`
   is not explicitly set, derive `max_tier` from the charter. One source of
   truth for blast-radius input (sets up Phase 4).
4. **Record charter provenance in the packet** — charter file hash + version
   in a `charter` block, so the attestation states *which* allowlist judged
   the agent. Without this the audit trail has a hole.
5. **Tests:** dirty/clean charter fixtures; flip
   `test_mcp01_skips_without_charter` to assert MCP-01 fires (its docstring
   already says to do exactly this); add a no-charter regression test that
   MCP-01 still SKIPs.
6. **Docs:** restore the README Charter section — now describing a real flag.

**Acceptance:** `blastcontain-verify --charter charter.yaml --mcp-config mcp.json`
fails MCP-01 on an unapproved tool, the packet records the charter hash, and
the integration suite covers fire/skip/malformed paths.

---

## Phase 2 — Typed check contract + plugin registry  *(item 3, size: L)*

One refactor fixes the silent-`**kwargs` fragility and the fork-to-extend
problem. Do it before the policy engine and delegation work so those land on
the new contract instead of being migrated later.

**Design:**

```python
# blastcontain_verify/registry.py
@dataclass(frozen=True)
class CheckContext:
    cfg: VerifyConfig            # full config — typed field access, mypy-checkable
    state: ScanState             # cross-check facts (env02_fired, mem01_fired, ...)

@dataclass
class CheckGroupResult:
    findings: list[InfraFinding]
    passed: list[str]
    skipped: list[SkipRecord]    # typed {check_id, reason} replacing raw dicts

class CheckGroup(Protocol):
    name: str                                    # "memory", "mcp", ...
    provides: frozenset[str]                     # check IDs it owns
    def run(self, ctx: CheckContext) -> CheckGroupResult: ...
```

1. **Migrate the 14 modules mechanically.** Each module's `run(**kwargs)`
   becomes `run(ctx)`; reads move from kwargs to `ctx.cfg.<field>` /
   `ctx.state.<field>`. A renamed config field is now a mypy/AttributeError at
   the *definition* site, not a silently-defaulted kwarg. The 3-tuple unpack
   in `collect()` becomes a typed result. External behavior (audit packet
   shape, CLI output) is unchanged — the 55-test integration suite is the
   regression net.
2. **Composites without magic:** the registry holds an ordered list; groups
   that feed later groups (environment → memory for MEM-05) write facts into
   `ScanState`. Explicit ordering stays — no dependency resolver until a real
   need appears.
3. **Plugin discovery:** after built-ins, load
   `importlib.metadata.entry_points(group="blastcontain_verify.checks")`.
   Each entry point yields a `CheckGroup`. Same `collect()` crash-quarantine
   applies — a broken plugin becomes a `SCAN-<NAME>` finding, never a dead
   scan. Plugin check IDs must not collide with `ALL_CHECK_IDS` (validated at
   load, reported as a scanner error finding).
4. **Trust model, stated plainly:** plugins are arbitrary in-process code.
   Document that installing a plugin == trusting it, and that the hardened
   container is the blast-radius control for the scanner itself.
5. **Docs:** a short "Writing a check plugin" page (cookiecutter-level
   example); update `architecture.md` §4/§6 — this closes the
   "convention vs enforced contract" open question recorded there.

**Acceptance:** mypy passes with the typed contract; a demo external plugin
(in `examples/`) registers via entry point, runs, fails its check, and crashes
safely when sabotaged; doc-drift test (item 6) now reads `provides` from the
registry as the canonical inventory.

---

## Phase 3 — Per-environment verdict policy  *(item 4, size: M)*

`derive_status()` is one global rule. Real orgs gate dev and prod differently
— today `--env` changes which checks run but not how findings are judged.

**Design — declarative policy in config, recorded in the packet:**

```yaml
# blastcontain-verify.yaml
policy:
  default:                      # = current behavior, backward compatible
    quarantine_on: [CRITICAL]
    reject_on: [HIGH, MEDIUM]
  dev:
    quarantine_on: [CRITICAL]
    reject_on: []               # HIGH/MEDIUM reported but APPROVED
  prod:
    quarantine_on: [CRITICAL, HIGH]
    reject_on: [MEDIUM]
```

1. **`derive_status(findings, policy)`** — policy resolution: explicit env
   entry → `default` entry → built-in constants (today's rule). Pure function,
   property-test friendly.
2. **The packet records the applied policy** (resolved thresholds + which env
   matched) in a `policy` block. An auditor must be able to see *what rule*
   produced APPROVED — otherwise per-env policy quietly weakens the
   attestation. Schema additive bump.
3. **Out of scope for v1** (recorded as such): per-check severity overrides,
   waiver workflows with expiry dates, blast-radius-driven thresholds (that
   hook lands with Phase 4). `--skip-checks` + `.blastcontainignore` already
   cover targeted suppression.
4. **Tests:** unit matrix over (env × severity-mix); integration: same dirty
   scan, dev policy → exit 0/APPROVED, prod policy → exit 2/QUARANTINED.

**Acceptance:** identical findings judged differently per environment, with
the judgment rule visible inside the signed packet.

---

## Phase 4 — Blast radius as a real model  *(items 2b + 2c, size: L, design-first)*

Today `blast_radius_factor = TIER_BLAST_WEIGHTS[max_tier]` — a static
multiplier that is reported and never consumed. It is the product's namesake;
it should be the most defensible number in the report.

**Step 1 — a one-page design spec (before any code), proposing:**

> **blast_radius = tier_weight × Σ(capability factors)** where the factors are
> *facts the scan already gathers*:
> - **Reach** — ENV-02/NET-01 (egress open?), API-01 (destructive endpoints),
>   MCP categories `Send`/`Execute` present
> - **Sensitivity** — MEM-01 (PII in context), CRED-01/02 (credentials
>   reachable), MEM-03 (shared memory namespace)
> - **Persistence** — PERM-01, ENV-03/SUP-01 (mutable/unattested weights)
> - **Authority** — charter `trust_tier`, delegation depth (`max_tier`)

**Step 2 — implement:**
1. A `blast_radius` block in the packet: final score **plus the per-factor
   breakdown** ("3.2× because: open egress (+0.8), PII in context (+0.6),
   tier-2 authority (×1.5)…"). The breakdown is the feature — a bare number
   is marketing, an itemized one is an audit artifact.
2. Markdown report gets a Blast Radius section rendering the breakdown.
3. **Make it drive something:** policy (Phase 3) gains an optional
   `quarantine_above: <score>` threshold. MEM-05 stays a check, but its logic
   (PII × egress) becomes the model's flagship composite factor.
4. `--max-tier` stops being a stub: charter-derived by default (Phase 1),
   explicit flag as override, documented as the authority input to the model.

**Acceptance:** two scans differing only in egress produce different scores
with the delta itemized; the spec section explains the formula well enough
for a security engineer to recompute it by hand from the packet.

---

## Phase 5 — Delegate the generic checks  *(item 1, size: L, after the registry)*

Strategy: the proven augmentation pattern (presidio → MEM-01) applied to the
generic checks — **best-of-breed engine when present, existing regex as the
offline fallback, SKIP-with-hint never crash**. Plus explicit repositioning.

1. **CRED-01 → gitleaks** *(engine of choice: battle-tested, huge ruleset)*.
   It is a Go binary, not a pip dep — so: bake it into the container image
   (multi-stage `COPY --from=ghcr.io/gitleaks/gitleaks`), detect on PATH for
   pip installs, `gitleaks` augmentation flag. Map rule IDs into finding
   evidence. Regex fallback unchanged.
2. **CODE-01 → staged.** First `[sast]` extra backed by **bandit**
   (pip-installable, tiny tree — passes the item-7 checklist trivially) for
   Python targets; evaluate **semgrep** later for multi-language, *only after*
   its dependency tree passes the same checklist (the litellm lesson applies
   to scanners too). Regex fallback unchanged.
3. **TLS-01 stays regex** — plaintext-URL detection is honestly adequate;
   deepening it has no buyer.
4. **Repositioning (do this even if the engines slip):** a "Baseline vs
   agent-specific checks" section in README/spec stating plainly: the
   baseline checks are hygiene gates and play well with your existing
   gitleaks/semgrep; the agent-specific surface (MCP combinations, skill
   exfil, PII×egress composites, charter, blast radius) is what only Verify
   does. This converts the "why not gitleaks?" objection into the answer.
5. **Tests:** fixture repos with engine-only and regex-only detections;
   integration asserts both paths (engine present in container, absent in a
   bare pip env).

**Acceptance:** in the container, CRED-01 evidence cites gitleaks rules; on a
bare pip install, the same scan degrades to regex with a visible hint; the
README positions baseline vs moat explicitly.

---

## What this roadmap deliberately does NOT do

- **No rename, no new checks for breadth.** Depth on the moat beats count.
- **No plugin sandboxing** beyond the container — honest documentation of the
  trust model instead of false isolation.
- **No policy DSL** — YAML thresholds only until a user proves the need.
- **No new heavyweight augmentations** until the item-7 checklist exists and
  they pass it.

## Risk register

| Risk | Mitigation |
|---|---|
| Registry refactor destabilizes 14 modules at once | Mechanical migration, one module per commit, 55-test integration suite as the net |
| Blast-radius formula invites bikeshedding | Design-first with a one-pager; ship v1 with the breakdown visible so the formula is criticizable *and fixable* |
| gitleaks binary complicates the pip story | Container-first (where it is free); PATH detection + regex fallback for pip |
| Policy weakens attestation credibility | The applied policy is embedded in the signed packet — weaker gates are visible, never silent |
| Scope creep across phases | Each phase ships independently; 0.4.0 = phases 1–3, 0.5.0 = phases 4–5 |
