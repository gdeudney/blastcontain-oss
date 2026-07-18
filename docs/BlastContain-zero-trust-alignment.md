# BlastContain — Zero Trust Alignment

**Mapping BlastContain to Anthropic's *Zero Trust for AI Agents* framework**
Version 0.1 — Draft | 2026-05-31 | Audience: Security leaders, Compliance, Product, Buyers

> Reference: Anthropic, *Zero Trust for AI Agents — A security framework for deploying autonomous AI
> agents in the enterprise* (May 2026), grounded in NIST SP 800-207 and the NSA Zero-Trust
> Implementation Guides (ZIGs). This document shows that **BlastContain operationalizes that
> framework** — same principles, same vocabulary, same workflow — and uses the paper's three-tier
> maturity model to position BlastContain's controls and a concrete gap roadmap.

> **Status legend:** ✅ supported · 🟡 partial / via enforcement plane · ⬜ gap (roadmap)

---

## 1. Why this matters

Anthropic's framework is becoming a reference point for enterprise agent security, and it aligns
with HIPAA, FINRA, GDPR, FedRAMP, and the EU AI Act. BlastContain implements its controls almost
one-for-one — which means a buyer or regulator can read "we follow Anthropic's Zero Trust for AI
Agents" and BlastContain is the platform that *proves* it. This doc is the crosswalk.

## 2. The framework in one page

- **Three principles:** *Never trust, always verify* · *Assume breach* · *Least privilege* — plus
  **Least Agency** (OWASP: restrict what each agent tool can do, how often, where) and **blast
  radius** as the unit of exposure.
- **The design test — "impossible, not tedious":** prefer a control that *removes* a capability over
  one that throttles it; friction-only controls (rate limits, extra hops, SMS MFA) fail against
  agentic attackers with unlimited patience.
- **Three maturity tiers:** **Foundation** (raised floor — crypto identity, short-lived tokens,
  identity isolation, automated triage are now entry requirements) → **Enterprise** (target for most)
  → **Advanced** (regulated / high-stakes).
- **An 8-phase implementation workflow** and a Part V on **defensive operations at machine speed**.

## 3. Principle alignment

| ZT principle | How BlastContain embodies it |
|---|---|
| Never trust, always verify | No agent registers without **Verify**; no agent runs without a signed **Charter**; AGT evaluates **every** action (continuous authorization, verified). |
| Assume breach | The Charter axiom is "architected for breach" — least-privilege concerns, blast-radius pricing (MPL), quarantine on CRITICAL. The product is literally named for containing the blast radius. |
| Least privilege / **Least Agency** | The concern model + AGT **deny-by-default** allowlist restrict *what each tool can do* — exactly Least Agency. |
| **Impossible, not tedious** | Mirrored in the make-or-break axiom (charter-spec §1) and AGT's "structurally impossible, not unlikely." Concerns compile to hard `deny` (autonomous) — capability removal, not throttling. |

## 4. Vocabulary alignment

| Paper term | BlastContain |
|---|---|
| Blast radius | product name + Ledger Trust-Aware Blast Radius / MPL |
| Least Agency | intent/concern model → AGT deny-by-default |
| Confused deputy / **unscoped privilege inheritance** | charter-spec §2.4 — capability laundering / weakest-link rule (AGT ADR-0014 Parent-Deny-Immutable) |
| Memory-based privilege retention | secrets + tenant-memory concerns (CRED-01/02, MEM-03) |
| Explicit trust boundaries (verify identity before accepting delegated tasks) | delegation graph + AGT `did:mesh:` trust handshake |
| Tool allow-listing (deny-by-default) | `permitted_tools` → AGT MCP Security Gateway |
| Escalation triggers / HITL for high-risk | `hitl_config` + `require_approval` + autonomy model |
| Shadow AI | Discovery |
| AI governance committee + approval | Organizational Standards + central sign-off |
| Continuous policy enforcement in pipelines | CI/CD gate + Repository Scanner + `push_to_agt` |
| Signed configurations | the signed Charter |

## 5. Capability-domain mapping (paper Part III)

| Paper domain | BlastContain | Fit |
|---|---|---|
| Identity & authentication | AGT `did:mesh:` Ed25519, signed Charter, lifecycle creation→retirement | strong |
| Service authentication (short-lived tokens, mTLS) | enforcement plane / infra (AGT) — *not Charter-required yet* | 🟡 gap |
| Permission models (RBAC→ABAC→continuous) | concerns → AGT policy, deny-by-default, per-action eval | strong; ABAC context 🟡 |
| Privilege scoping (static→dynamic→JIT) | static allowlists ✅; HITL elevation 🟡; JIT/JEA ⬜ | partial |
| Resource boundaries (isolation→sandbox→hardware) | Verify ENV-01/PRIV/CAP/DISK, AGT rings/VFS | strong; hardware attest ⬜ |
| Action logging (logs→immutable→SIEM) | Ledger signed Audit Packets, immutable retention | strong; SIEM export ⬜ |
| Traceability (request IDs→OTel→provenance) | Ledger OTEL/CloudEvents ingest, delegation graph | strong |
| Baseline / anomaly / response | Drift Tracker, Pattern Detection, Quarantine Signal | good; ML anomaly ⬜ |
| Input / output controls (sanitization, spotlighting, PII, HITL) | NeMo/Cisco/AGT enforcers, "no PII"/"content-safe" concerns, `require_approval` | good (optional enforcers) |
| Configuration integrity (version→signed→immutable) | versioned + **signed** Charter; Verify SUP-01/ENV-03 | strong |
| Recovery (rollback→auto→self-heal) | rollback §7.3, recertification | good; auto-rollback ⬜ |
| **AI governance policies (AUP→committee→continuous)** | **the core product** — Standards, CI/CD gate, Repository Scanner | strong |

## 6. Implementation-workflow mapping (paper Part IV)

| Phase | Paper | BlastContain |
|---|---|---|
| 1 | Identify requirements | Charter scope + Organizational Standards |
| 2 | Manage supply-chain risk | **Verify** SUP-01; *AI-BOM / OpenSSF Scorecard ⬜* |
| 3 | Define agent boundaries | **Charter** authoring (scope→autonomy→concerns) + blast-radius |
| 4 | Defend prompt injection | enforcement plane (NeMo/AGT PromptDefense) + **Drill** |
| 5 | Secure tool access | `permitted_tools` + MCP-01 + AGT gateway (deny-by-default) |
| 6 | Protect credentials | CRED-01/02; *short-lived-token concern ⬜* |
| 7 | Safeguard memory | MEM-03; *context-integrity + retention TTL ⬜* |
| 8 | Measure what matters | Ledger; *dwell-time + coverage metrics ⬜* |
| V | Defensive ops / Agentic SOAR | adjacent — **Drill** (adversarial test) + Quarantine (auto-containment) |

> The paper's workflow *is* BlastContain's tools-and-lifecycle, in order.

## 7. Three-tier maturity alignment

The paper's **Foundation / Enterprise / Advanced** tiers give BlastContain a maturity model to target.
Proposal: align `base_strictness` so a Charter can **declare a ZT tier** and compile the matching
control depth.

| ZT capability | Foundation | Enterprise | Advanced |
|---|---|---|---|
| Identity | AGT `did:mesh:` ✅ | + cert lifecycle (AGT) 🟡 | hardware/HSM attest ⬜ |
| Service auth | short-lived tokens 🟡⬜ | mTLS + pinning 🟡 | hardware-bound ⬜ |
| Permissions | deny-by-default allowlist ✅ | ABAC context 🟡 | continuous authz ✅ |
| Privilege scoping | static least-priv ✅ | dynamic elevation (HITL) 🟡 | JIT/JEA auto-expire ⬜ |
| Resource boundaries | identity isolation ✅ | sandbox (Verify ENV-01) ✅ | hardware isolation 🟡 |
| Logging | comprehensive (Ledger) ✅ | immutable + signed ✅ | real-time SIEM ⬜ |
| Traceability | request/scan IDs ✅ | OTel distributed ✅ | full provenance 🟡 |
| Baseline/anomaly | Pattern Detection 🟡 | Drift Tracker 🟡 | ML behavioral ⬜ |
| Input/output | PII/pattern (enforcers) 🟡 | semantic (NeMo/Cisco) 🟡 | classifiers + spotlighting + HITL 🟡 |
| Config integrity | versioned Charter ✅ | signed Charter ✅ | immutable + attest 🟡 |
| Recovery | rollback ✅ | auto-rollback + health ⬜ | self-healing ⬜ |
| Governance | Standards (AUP) ✅ | committee + sign-off ✅ | continuous pipeline ✅ |
| Memory | MEM-03 isolation ✅ | context-integrity ⬜ | retention TTL + quarantine 🟡 |

**Read:** BlastContain already lands most of **Foundation and Enterprise**; the open work is
concentrated in **Advanced** (hardware identity, JIT, ML anomaly, SIEM/self-healing) plus a few
Foundation/Enterprise gaps worth closing early (short-lived tokens, memory integrity, dwell/coverage).

## 8. Gap analysis & roadmap (near-term)

Near-term, ordered by leverage (further-out items in §10):

| # | Gap | Where | Priority |
|---|---|---|---|
| 1 | **Tier maturity model** — align `base_strictness` to Foundation/Enterprise/Advanced; let a Charter target a tier | Charter §3.4 | high (free credibility) |
| 2 | **Dwell-time + coverage metrics** — the paper says instrument these *first* | Ledger | high |
| 3 | **Short-lived-credential concern** — positive control, not just CRED-02 detection | Charter catalog | high (raised Foundation floor) |
| 4 | **JIT / JEA dynamic privilege** with auto-expiry | Charter + lifecycle | medium |
| 5 | **Memory context-integrity validation + retention TTL** | Charter catalog + Verify | medium |
| 6 | **ABAC context-aware concerns** (time-of-day, risk score, step-up) | Charter → AGT condition rules | medium |
| 7 | **AI-BOM + OpenSSF Scorecard** dependency health | Verify / Discovery | medium |
| 8 | **SIEM streaming export** from the Ledger | Ledger | medium |
| 9 | **Auto-rollback with health checks** | lifecycle §7.3 | low |
| 10 | **Hardware-bound identity / attestation** (Advanced) | AGT integration | low (longer-term) |

## 9. Regulatory crosswalk

The paper notes Zero Trust aligns with HIPAA, FINRA, GDPR, FedRAMP, and the **EU AI Act** — the same
regimes BlastContain's Audit Packet targets (charter-spec §7.3 recertification = Art. 14 incident
response; transparency labels = Art. 50; MIT + OWASP-mapped findings = Art. 12 documentation). The
Zero Trust alignment and the EU AI Act mapping reinforce each other in one signed audit trail.

## 10. Horizon — further-out items

A second pass over the paper surfaces a deeper layer beyond §8 — further-out, but worth tracking.

**★ Top three (highest leverage):**
1. **MITRE ATT&CK mapping** — tag Drill scenarios + Ledger findings with ATT&CK technique IDs
   (prioritise lateral movement + credential access). Cheap, and makes BlastContain legible to every
   existing SOC. Today we map MIT + OWASP only.
2. **Risk-score-driven dynamic authorization** — act on AGT's dynamic 0–1000 trust score (it decays
   on misbehaviour): trust drops → auto-tighten the Charter / quarantine. Unlocks the Advanced
   "continuous authorization, revoke when risk changes" tier from a signal we already receive.
3. **Govern our own defensive agents + AI finding-triage** — the Part V theme. Put a model at the
   front of the findings queue (drafts a disposition before a human sees it; "automate bookkeeping,
   not decisions"), and give BlastContain's own automation Charters. Dogfooding = credibility.

**By theme:**

| Theme | Item | Home | Priority |
|---|---|---|---|
| Detection / SOC | MITRE ATT&CK mapping ★ | Ledger / Drill | high |
| Detection / SOC | Per-agent threat-coverage report (which T1–T15 / ATT&CK a Charter closes vs leaves open) | Ledger | high |
| Adaptive control | Risk-score-driven dynamic authorization ★ | Charter + Ledger | high |
| Govern automation | AI first-pass finding triage ★ | Ledger | high |
| Govern automation | Charter-govern BlastContain's own defensive agents (dogfood) | Platform | medium |
| Design discipline | **"Impossible vs tedious" control classifier** — tag each compiled control hard-barrier vs friction; warn on friction-reliance | Charter | medium (novel, on-brand) |
| Operations | Emergency-change / break-glass ops path (pre-authorised approvers + evidence for offline / rotate / block) | Lifecycle | medium |
| Recovery | Behavioural-baseline capture + restore (known-good behavioural snapshot, beyond config rollback) | Ledger | medium |
| Resilience | Fleet-scale / concurrent-incident Drill mode ("five at once") | Drill | medium |
| Input controls | Spotlighting / input-isolation as explicit concerns (delimit untrusted content; isolated context for web/doc input) | Charter catalog | medium |
| Identity | PKI / X.509 + CRL/OCSP option alongside `did:mesh:` | AGT integration | low |
| Supply chain | Reachability analysis for vuln remediation | Verify | low |
| Identity (Advanced) | Confidential computing / enclaves (SEV/TDX) | infra | low |

---

## See also

- [BlastContain-charter-spec.md](BlastContain-charter-spec.md) — the controls this maps to
- [BlastContain-platform-spec.md](BlastContain-platform-spec.md) — architecture & components
- Anthropic, *Zero Trust for AI Agents* (May 2026)
