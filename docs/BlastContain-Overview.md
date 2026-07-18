# BlastContain

> ⚠️ **Historical / superseded vision doc (pre-Guard, pre-AGT-v4).** This early overview predates the
> cage trilogy and the Guard enforcer, still marks Drill as "in development" (now built), and anchors on
> EU AI Act Art. 15 where the current specs cite Art. 12 / 14 / 50. Kept for history only — for current
> state start at [BlastContain-platform-spec.md](BlastContain-platform-spec.md) and
> [BlastContain-roadmap.md](BlastContain-roadmap.md).

**Containment for AI agents.** Pre-deployment compliance scanning, runtime red-teaming, shadow-agent discovery, and a managed governance platform — built around the public MIT AI Risk Repository taxonomy, distributed as Apache 2.0 open source, with a commercial platform for organisations that need org-scale governance.

---

## TL;DR

Modern enterprises are deploying AI agents faster than they can secure them. The agents read your data, call your APIs, ship to production from a developer's laptop, and have credentials a traditional SAST scanner has no idea how to reason about. When something goes wrong — prompt injection, a leaked tool, a runaway delegation chain — the blast radius is measured in customer data, infrastructure access, and regulatory exposure.

BlastContain is the security tooling layer for agentic systems. Three open-source tools (Verify, Drill, Discovery) sit in the agent's development and deployment path; a commercial Platform aggregates their findings, enforces signed policies (Charters), and produces the audit trail your regulators expect.

The tools work standalone. The Platform adds org-scale governance. Both speak the same wire format and the same threat taxonomy.

---

## The problem

AI agents are not traditional applications, and they break the assumptions of traditional security tooling.

| Assumption (traditional SAST/DAST) | Reality (AI agent) |
|---|---|
| Behaviour is deterministic — you can enumerate code paths | Behaviour is probabilistic — emergent from a prompt and a tool list |
| Privileges are static — declared in IAM policies | Privileges are conferred at runtime by tool descriptions in the prompt |
| Input validation is at the API boundary | Input validation is a hope — the LLM rewrites everything |
| The attack surface is the application | The attack surface includes the entire MCP server ecosystem the agent talks to |
| Deployment artefacts are immutable container images | Deployment artefacts include skill definitions, model weights, system prompts, and a delegation graph |
| A compromised process affects one application | A compromised agent can chain through other agents, exfiltrate via DNS, or drop persistence in /etc/cron.d |

The result: every existing security category — code scanning, dependency scanning, runtime EDR, secrets management — misses the things that make agents uniquely dangerous.

BlastContain is built specifically for these gaps.

---

## What BlastContain does

Three open-source tools cover the lifecycle. A commercial platform ties them together.

### 1. Verify — pre-deployment compliance scanner

Runs inside the agent's container before it's allowed to register. Probes 27 security checks across 14 categories:

- **Environment**: kernel isolation (gVisor), egress restriction, model weight mutability
- **Credentials**: hardcoded secrets on disk, live credentials in process env, wildcard API capability
- **Process**: running as root, dangerous Linux capabilities
- **Network**: DNS exfiltration channel, external listeners
- **Memory**: unmasked PII in context, vector store tenant isolation, viable PII exfiltration path
- **MCP**: unapproved tools, missing auth, dangerous capability combinations (Read+Send, Credential+Execute)
- **Code**: dangerous execution patterns (`eval`, `pickle.load`, `shell=True`)
- **Supply chain**: model weights without attestation
- **Skills**: exfiltration-capable tools (`http_post`, `upload_file`)
- **APIs**: destructive endpoints, unauthenticated endpoints
- **Transport**: plaintext HTTP

Output: a Markdown compliance report, a cryptographically signed JSON audit packet (Ed25519), and SARIF 2.1.0 that lands directly in GitHub Code Scanning. Every finding maps to the public [MIT AI Risk Repository](https://airisk.mit.edu/) taxonomy.

```bash
pip install blastcontain-verify
blastcontain-verify --agent-id my-agent --env prod --search-path ./src \
  --sarif scan.sarif --output audit.json
```

### 2. Drill — runtime probing and red-team simulation

*Status: in development.* Where Verify scans static artefacts, Drill probes the live agent: prompt-injection chains, delegation-graph traversal, tool-capability fuzzing, and the eight-step quarantine chain that validates an agent's incident response works end-to-end.

### 3. Discovery — shadow AI and agent discovery

*Status: in development.* Most organisations don't know how many AI agents they have. Discovery is an agentless network-and-endpoint scanner that finds them — running on developer laptops, hidden in CI/CD pipelines, embedded in SaaS integrations — and inventories what they touch.

### 4. Core — the shared library

`blastcontain-core` is the open-source package every BlastContain tool depends on:

- The MIT AI Risk Repository taxonomy mapping
- The Charter schema (agent policy contract)
- Audit packet signing (Ed25519 + HMAC fallback)
- SARIF 2.1.0 emit/parse
- Common scan-result types

Tools depend on it via PyPI. The closed-source Platform consumes the same types, so everything in the ecosystem is wire-compatible by construction.

### 5. Platform — the commercial offering

The Platform is what you reach for once you have more than a handful of agents and more than one team deploying them. It provides:

- **Ledger** — aggregated audit-packet storage with retention, search, and trend analysis
- **Charter management** — central policy-as-code with versioning, approval workflows, drift detection
- **Multi-team governance** — RBAC, SSO/SCIM, organisation-wide allow/deny lists
- **Cross-tool correlation** — Discovery finds an agent → Verify scans it → Drill probes it → Charter enforces it, all stitched together
- **Compliance reporting** — EU AI Act Article 15 transparency labels, MIT-AI-Risk dashboards across the estate, SOC 2 / ISO 42001 evidence collection
- **Signed Charter attestation** — KMS-backed organisation signing keys, cryptographic proof of policy

The Platform doesn't replace the tools; it operates on what they produce.

---

## What's open source vs commercial

| Layer | Open source (Apache 2.0) | Commercial Platform |
|---|---|---|
| **Scanning logic** | All checks, all rules, all MIT mappings | — |
| **Reporting** | Markdown reports, JSON audit packets, SARIF 2.1.0 | — |
| **Signing** | Ed25519 self-signing with your own key | KMS-backed org signing keys |
| **Charter** | Schema; local `charter.yaml` files; runtime enforcement | Central storage, versioning, approval workflows, drift detection |
| **Discovery** | All probing logic, agentless scans | Cross-environment aggregation, asset graph |
| **Drill** | All probe modules, quarantine simulator | Test history, regression tracking |
| **Standalone usage** | All three tools run without the Platform | — |
| **Multi-agent operation** | One scan at a time | Ledger across all agents, all teams |
| **Identity / RBAC** | — | SSO, SCIM, RBAC, audit logs |
| **Exception workflow** | `.blastcontainignore` per repo | Org-wide exception management with approver chain |
| **Compliance evidence** | Per-scan SARIF + audit packets | EU AI Act Art. 15 dashboards, SOC 2 / ISO 42001 evidence packs |
| **Cross-tool correlation** | — | Discovery → Verify → Drill stitched together |

**The rule:** if it changes a single agent's posture, it's open source. If it's a multi-team, multi-agent, audit-and-governance concern, it's the Platform.

---

## Why open source the tools?

Security scanners are bought by paranoid buyers, and paranoid buyers don't trust closed-source scanners. Every successful security tool of the last decade — Trivy, Semgrep, gitleaks, Bandit, Falco, Checkov — distributes its scanning engine as open source. Where they monetise is on the dashboards, the multi-tenant SaaS, and the enterprise integrations. We're doing the same.

The practical implications:

- **Verify can be vendored, reviewed, and audited line-by-line** by your security team before you trust its findings
- **You can self-host** — Verify runs in a hardened Podman container with `--read-only --cap-drop ALL --network none`. The Platform is optional.
- **The Charter schema is public** — you can write a `charter.yaml` and have Verify enforce `permitted_tools` against MCP-01 without touching the Platform. The Platform adds central management on top of the same schema.
- **No telemetry by default** — the OSS tools never call home. You explicitly point them at a Platform URL if you want server-mode operation.

We commit to Apache 2.0 in perpetuity. We will not do a BUSL/SSPL relicensing later — that's the model that has triggered every major OSS fork of the last five years (OpenSearch, OpenTofu, Valkey), and we have no interest in joining that list.

---

## Standards alignment

BlastContain plugs into the security ecosystem you already use.

| Standard | How BlastContain uses it |
|---|---|
| [MIT AI Risk Repository](https://airisk.mit.edu/) | Every finding maps to a domain, causal ID, and label from MIT v4. The mapping is in OSS — anyone can audit it. |
| [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) | First-class output format. Uploads directly to GitHub Code Scanning, GitLab Security Dashboard, Sonar, Snyk, and IDE extensions. |
| [Sigstore / Ed25519](https://www.sigstore.dev/) | Audit packets are signed with Ed25519 by default. Public key embedded in the packet for independent verification. |
| EU AI Act Article 15 | Charter schema includes a `transparency_label` field for consumer-facing AI system disclosure. |
| NIST AI Risk Management Framework | MIT AI Risk Repository maps cleanly to NIST AI RMF; BlastContain reports compose into NIST-aligned evidence. |
| MCP (Model Context Protocol) | First-class scanning of MCP server configs and live MCP endpoints via the Cisco AI MCP Scanner integration. |

---

## Getting started

### As an open-source user

You need: a Python 3.11+ environment, Podman or Docker, and a project to scan.

```bash
# Install
pip install "blastcontain-verify[full]"

# Or use the hardened container
podman run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  --network none --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "$PWD:/scan:ro" -v "$PWD/reports:/reports:rw" \
  ghcr.io/blastcontain/verify:latest \
  --agent-id my-agent --env prod --search-path /scan \
  --sarif /reports/scan.sarif --output /reports/audit.json
```

```yaml
# .github/workflows/security.yml
- name: BlastContain Verify
  run: blastcontain-verify --sarif scan.sarif --agent-id ${{ github.repository }}
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: scan.sarif }
```

Read [the spec](https://github.com/blastcontain/verify/blob/main/docs/spec.md) for the full check inventory.

### As a platform prospect

If you're running more than a handful of agents, or you have a compliance team that needs evidence, the Platform makes the open-source tooling enterprise-grade. Reach out: hello@blastcontain.io

---

## When you need the Platform

You're a Platform candidate when any of these is true:

- You have **more than five AI agents** in production across more than one team
- You need **a central audit trail** of every scan, every finding, every remediation
- You need **policy as code** with approval workflows — not YAML files in scattered repos
- You're preparing for **SOC 2, ISO 42001, or EU AI Act compliance** and need evidence collection
- You want to **enforce Charters at deploy time** — agents that fail Verify can't register
- You need to **correlate Discovery, Verify, and Drill** findings into a single risk view

The Platform doesn't replace the OSS tools. It runs above them.

---

## Why now

Three forces are converging:

1. **Agent deployments are accelerating.** Enterprise AI agent deployment in 2026 looks like enterprise web app deployment in 2010 — fast, sprawling, ungovernable. The security tooling needs to exist before the breach, not after.
2. **The MCP ecosystem is exploding.** Every new MCP server is a potential capability the agent can exercise. The combinatorial explosion of `tool_a + tool_b` dangerous pairs is exactly the kind of problem static analysis is good at.
3. **Regulation is arriving.** EU AI Act Article 15 (transparency obligations) took effect in 2026. NIST AI RMF compliance is becoming a procurement requirement. Auditors are asking "how do you know your agents are doing what you said they do?" and existing tooling doesn't answer that question.

BlastContain answers it.

---

## Differentiation

Where BlastContain fits in the security tool landscape:

| Tool | Primary scope | BlastContain difference |
|---|---|---|
| **Semgrep / Bandit / SonarQube** | Source code SAST | We scan the agent's runtime environment and tool/MCP/Charter declarations, not just code. |
| **Snyk / Dependabot** | Dependency CVEs | We check model weight attestation, MCP tool combinations, and runtime egress, not package versions. |
| **Wiz / Lacework / Orca** | Cloud workload posture | We're agent-specific; their checks don't know what an "MCP server" is. |
| **Falco / Tetragon** | Runtime EDR | They detect anomalous syscalls; we prevent bad configurations from being deployed in the first place. |
| **Microsoft Presidio** | PII detection in text | We use Presidio as an augmentation (MEM-01) but extend it with PII-exfiltration-path reasoning. |
| **Cisco AI Defense** | LLM safety classifiers | We integrate their MCP Scanner and Skill Scanner; we don't replace LLM-level safety. |
| **AGT (Agent Governance Toolkit)** | Runtime policy enforcement | We use AGT as an augmentation; we focus on pre-deployment posture, not runtime enforcement. |

We're not trying to replace the security stack. We're filling the gap that opens when traditional tools meet agentic systems.

---

## Pricing model

- **All three OSS tools — Verify, Drill, Discovery — are free.** Apache 2.0. Forever.
- **`blastcontain-core` is free.** Apache 2.0. The Charter schema, MIT mapping, signing, and SARIF emission are all OSS.
- **The Platform is paid.** Pricing is per-agent per month, with tiers based on retention period and compliance feature set. Contact sales for current pricing.
- **No "open core trap."** The OSS tools are not deliberately crippled to upsell the Platform. They are fully functional standalone — they were, in fact, built standalone first.

---

## Roadmap

**Shipped (2026 Q1–Q2):**

- `blastcontain-verify` 0.3.0 — 27 checks, MIT mapping, SARIF output, Ed25519 signing, hardened container
- `blastcontain-core` 0.1.0 — shared types, Charter schema, signing, SARIF
- Cisco AI MCP Scanner + Cisco AI Skill Scanner integration
- AGT PromptDefenseEvaluator + SupplyChainGuard integration

**In progress (2026 Q3):**

- `blastcontain-drill` — runtime probing and quarantine simulation
- Charter as policy-as-code, signed by an organisation key
- Platform private beta — Ledger + multi-agent dashboards

**Planned (2026 Q4):**

- `blastcontain-discovery` — agentless shadow-AI discovery
- Sigstore keyless signing for audit packets
- SOC 2 Type II evidence collection in Platform
- Public Platform GA

---

## A short worked example

Here's what a real Verify run looks like against a deliberately-broken sample agent:

```
============================================================
  BlastContain Verify  |  Agent: customer-support  |  Env: prod
============================================================
  Augmentation active:  presidio, cisco_mcp, cisco_skill, agt
  Running checks...

  ❌ API-01      HIGH      Destructive API Permissions in Agent Tool Spec
  ❌ API-02      HIGH      Destructive Endpoints Without Authentication
  ✅ CAP-01      PASS
  ❌ CODE-01     CRITICAL  Dangerous Code Execution Pattern Detected
  ❌ CRED-01     CRITICAL  Hardcoded Secrets Found in Source Files
  ⏭ CRED-02     SKIP      User-requested skip (--skip-checks)
  ✅ CRED-03     PASS
  ✅ DISK-02     PASS
  ✅ ENV-01      PASS
  ❌ ENV-02      HIGH      Network Egress Unrestricted
  ✅ ENV-03      PASS
  ❌ LOCAL-01    CRITICAL  Agent Running on Developer Workstation
  ❌ MCP-02      HIGH      MCP Server Without Authentication
  ❌ MCP-03      CRITICAL  Dangerous MCP Tool Combination Detected (3 pairs)
  ❌ MEM-01      MEDIUM    Unmasked PII Found in Session Context
  ❌ MEM-05      CRITICAL  Viable PII Exfiltration Path Confirmed
  ❌ NET-01      HIGH      DNS Exfiltration Channel Open
  ✅ NET-02      PASS
  ❌ SKILL-01    HIGH      Exfiltration-Capable Skill Tool Detected
  ✅ SUP-01      PASS
  ❌ TLS-01      HIGH      Plaintext HTTP Endpoints Detected

  Status:     🔴 QUARANTINED
  Critical:   5
  High:       7
  Medium:     1
  Passed:     6
  Skipped:    1
  Blast rad:  2.5x (TIER_2)

  Report:     /reports/report.md
  Audit:      /reports/audit.json   (Ed25519, key_id=ed25519-prod-2026-q2)
  SARIF:      /reports/scan.sarif
============================================================
```

Every line above is a real check from the open-source scanner. Every finding maps to MIT AI Risk Repository. The audit packet is independently verifiable. The SARIF lands in GitHub Code Scanning. The Platform aggregates this across every agent in your fleet.

---

## Links

- **Source:** github.com/blastcontain (org)
- **Verify:** github.com/blastcontain/verify
- **Core:** github.com/blastcontain/core
- **Documentation:** docs.blastcontain.io
- **Container image:** ghcr.io/blastcontain/verify
- **Sales:** hello@blastcontain.io
- **Security disclosure:** security@blastcontain.io
- **MIT AI Risk Repository:** airisk.mit.edu

---

## License

The Verify, Drill, Discovery, and Core packages are licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0). The BlastContain name and logo are trademarks of BlastContain Inc.; commercial use of the names requires permission.

The BlastContain Platform is proprietary software available under a commercial subscription.
