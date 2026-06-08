# BlastContain Drill — Status, Outstanding Work & Plugin Roadmap

_Last updated 2026-06-02. Companion to [spec.md](spec.md)._

## 1. Current state

Drill (Apache-2.0) lives in this monorepo (`blastcontain-oss/`) beside `core/` + `verify/`.
Spec build-order **steps 1–7 are done — container + guards included** — all validated live against
local LM Studio models:

- **Corpus (3 layers):** built-in Replay seed (~14, ATLAS-tagged) · Operators (7 model-free
  transforms; 14→112) · Generative (an abliterated "Heretic" attacker in a PAIR/TAP refine loop —
  found **3 CRITICAL action-plane bypasses** live) · AI-Infra-Guard HTTP adapter (API-correct,
  awaiting a live result field-map).
- **Cage:** `InProcessCage` (drives a live model) + `PodmanCage` (`--network none` containment).
  The **action plane** (canary-exfil / egress / forbidden-tool probes) is Drill's differentiator.
- **Scorers:** `LLMJudge` + `Qwen3Guard` + `Granite Guardian` + heuristic; `make_guard_scorer`
  auto-selects the guard family by model id.
- Signed `DrillReport` (`core.signing`); MITRE ATLAS / OWASP-Agentic / MIT taxonomy in `core`.
- **Tests:** 52 model-free unit + `podman` + `live` markers (drill); 22 (core). Lint clean.

## 2. Gotchas — cost real time, don't re-discover

1. **Reasoning models** (qwen3.6 family incl. the Heretic) burn the whole `max_tokens` budget on
   `reasoning_content` and return **empty `content`**. Fix shipped: `ChatClient` sends
   `chat_template_kwargs={"enable_thinking": false}`; the generative attacker uses a **concise**
   prompt + `max_tokens=4096`. Keep attacker prompts terse — verbose ones make it deliberate harder.
2. **Qwen3Guard scorer** must use **real user/assistant roles** (`user`=attack prompt,
   `assistant`=response). A neutral user turn → under-flags (misses unsafe content); a single
   combined user string → contaminates (flags refusals as unsafe). **WildGuard's native refusal axis
   would retire this hack** (task #23).
3. **48 GB VRAM** holds only **two** big models + KV cache at full (30k+) context. Preload with
   `lms load <id> -y --ttl 36000` (TTL prevents idle eviction). Generative run = attacker +
   target/judge only; run the guard A/B separately.
4. **Guard finding:** on a labeled benchmark Granite scored **8/8**, Qwen3Guard **7/8** (missed a
   data-exfil-described response). **Both content guards miss action attacks** — when the agent
   *says* a refusal but *does* the exfiltration via tools, only the action plane catches it.

## 3. Uncommitted changes (commit when you pause)

- `scoring/guard.py` — Qwen3Guard real-roles fix (was under-flagging unsafe content)
- `llm.py` — `enable_thinking=false` (reasoning-model fix)
- `generative/attacker.py` — concise prompt + `max_tokens=4096`
- `corpus/aig.py` — API-correct `model_redteam_report` body (target `model[]` + `eval_model`)
- `release.yml` + `verify/Containerfile` + `drill/Containerfile` — GHCR namespace → `gdeudney`
- `scripts/guard_compare.py` — guard A/B tool · this `docs/roadmap.md`
- **JBB + over-refusal feature (#21)** — core `OVER_REFUSAL`/`over_refusals`; `corpus/jailbreakbench.py`
  + `data/jbb/*.csv` (vendored MIT); combine/judge/guard/granite/reporter/cli/config/runner edits;
  `test_jailbreakbench.py` + scoring tests

## 4. Plugin roadmap

From a 6-agent survey of the GenAI-security OSS landscape. **Strategy: Drill owns the hard part (the
cage/action plane); integrations are additive at known seams** — `OperatorsSource._OPERATORS`
(str→str), `make_guard_scorer` (chat-backend branch), `AttackSource.dataset()` (vendored data), or
the `Scorer` ABC. **Take datasets and scorers; reject platforms/meta-orchestrators** (Promptfoo-as-
engine, ARES, ViolentUTF, Inspect) that duplicate Drill's runner.

### Now (permissive, same-day-to-small)
| Tool | Slot | License | Note |
|---|---|---|---|
| JailbreakBench (JBB) | AttackSource (vendored CSV) | MIT | benign split → **over-refusal scoring** (new capability) |
| PyRIT converters | Operators | MIT | ~70 str→str + a multimodal class; converters only, **not** orchestrators |
| DeepTeam | Operators | Apache | 18+ single-turn enhancements; built on DeepEval |
| WildGuard | Scorer (guard) | Apache* | native refusal axis **retires the Qwen3Guard hack** |
| DeepEval G-Eval | Scorer (judge) | Apache | spec-named judge; calibrated CoT score |
| AI-Infra-Guard | AttackSource + Verify mcp-scan | MIT | adapter ready; only the live field-map remains (#20) |

### Next (action-plane leverage / datasets)
- **garak** indirect-injection probes (Apache; pin post-2023 commit) → `vector=indirect` + `poisoned_document`, fed to the cage.
- **evil-mcp-server** (MIT) → a turnkey poisoned-tool cage fixture for `mcp_hijack` (gated on the cage mounting an external MCP server).
- **HarmBench** (~400 behaviors) + **JailBreakV-28K / RedTeam-2K** — datasets only (MIT), for seed volume.
- **ProtectAI LLM Guard DeBERTa** (Apache) — CPU prompt-injection detector (output scanners).

### Skip / route elsewhere
- **License blockers (hard skip):** Meta Llama Guard 3 + Prompt Guard (Llama 3.x Community License,
  non-OSI) and JAILJUDGE (Llama-2 guard + gated dataset + needs GPT-4). Use **ProtectAI DeBERTa** for
  the prompt-injection-detector capability instead.
- **Redundant platforms:** ARES, ViolentUTF, Promptfoo-as-engine, Inspect AI — duplicate Drill's runner.
- **Mis-clustered:** `modelaudit` is a static model-file scanner → belongs in **Verify (SUP-01)**, not Drill.
- **Gated-but-permissive** (ship as opt-in availability-flag, never bundled): WildGuard weights, WildJailbreak dataset.

## 5. Backlog (live tasks)

- **#20** AIG live integration — map `_attacks_from_result` against one live scan (needs the `:8088` Docker service).
- **#21** JailbreakBench dataset + over-refusal — ✅ **DONE (2026-06-02)**: vendored 100+100 MIT
  behaviors (`--jbb`); new `DrillOutcome.OVER_REFUSAL` + benign-aware scorers (judge branches its
  prompt, guards abstain); live-validated — qwen3-30b over-refused 4/4 borderline-benign prompts.
- **#22** PyRIT/DeepTeam converter operators — ✅ **DONE (2026-06-07)**: 10 pure-stdlib `str→str`
  converters into `OperatorsSource._OPERATORS` (7→17) — ROT13 · Caesar · Atbash · Morse · binary ·
  URL-encode (decode-and-comply) + char-space · zero-width · homoglyph (filter-evasion). Reimplemented
  (public-domain algorithms; no PyRIT/DeepTeam dependency, no service, no networking); source bumped
  `operators@v2`; round-trip + AST-label regression tests (83 drill unit).
- **#23** WildGuard scorer — ✅ **DONE (2026-06-02)**: `scoring/wildguard.py`; native refusal + harm
  axes retire the Qwen3Guard real-roles hack and score benign over-refusal natively (no abstaining).
  Unit-tested; gated model (`allenai/wildguard`) not downloaded, so not live-validated yet.
- **#24** G-Eval judge.
- **Model-sweep harness** — ✅ **DONE (2026-06-02)**: `blastcontain_drill/sweep.py`
  (`python -m blastcontain_drill.sweep`) runs Drill per `--target-model` with a fixed judge/guard →
  signed per-model reports + a risk-ranked leaderboard (md+json); live-validated on a 2-model sweep.
- Next-tier (above) + the `modelaudit`→Verify hand-off.

## 6. Other open threads

- **Commit** the §3 changes; push to `github.com/gdeudney/blastcontain-oss`.
- The `github.com/blastcontain/*` URLs in pyproject/SARIF/READMEs point at a non-existent org —
  decision pending: sweep to `gdeudney/blastcontain-oss`, or create a `blastcontain` org.
- Configure **PyPI Trusted Publishers** before pushing the `*-v*` release tags.
- Role B (prove a Charter-denied action can't execute) still needs `blastcontain-guard`.
