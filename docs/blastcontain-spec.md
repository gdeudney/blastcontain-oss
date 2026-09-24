# BlastContain — Platform Specification

> **Historical draft preserved from PR #20.** Implementation/status claims need
> reconciliation; see [review scope](README.md).

**Agent Governance Platform**  
Version 1.0 — Draft | 2026 | Audience: Engineering, Security, DevOps, Product

> **Superseded:** this is the original v1.0 platform spec, kept for history. The current umbrella
> spec is [BlastContain-platform-spec.md](BlastContain-platform-spec.md) (see its §8 Spec Index for
> the full, maintained spec set). Where the two disagree, the newer spec set wins.

---

## Contents

1. [What BlastContain Is](#1-what-blastcontain-is)
2. [Release Strategy](#2-release-strategy)
3. [Repository Structure](#3-repository-structure)
4. [Environments](#4-environments)
5. [Sovereign Stack](#5-sovereign-stack)
6. [Tool: blastcontain-verify](#6-tool-blastcontain-verify)
7. [Tool: blastcontain-drill](#7-tool-blastcontain-drill)
8. [Tool: blastcontain-discovery](#8-tool-blastcontain-discovery)
9. [Platform: Charter](#9-platform-charter)
10. [Platform: Ledger](#10-platform-ledger)
11. [Regulatory Compliance](#11-regulatory-compliance)

---

## 1. What BlastContain Is

BlastContain is a one-stop governance platform for agent deployments. Every security tool in your stack watches one layer. BlastContain governs the entire agent lifecycle — from discovery through deployment, policy enforcement, continuous audit, and adversarial testing.

**Five components. One platform.**

| Component | Install / Deploy | What it does | When |
|---|---|---|---|
| **Verify** | `pip install blastcontain-verify` | Pre-deployment environmental compliance scanner. 24 checks. Signed audit packet. | Before every registration and release |
| **Charter** | Platform (server) | Agent policy constitution. Defines what the agent is allowed to do, what tools it may hold, what environment it must run in. | At design time and on every release |
| **Ledger** | Platform (server) | Continuous audit trail. Stores all findings, assigns financial exposure, provides fleet-wide compliance dashboard. | Continuously |
| **Drill** | `pip install blastcontain-drill` | Adversarial red-team scanner. Runs attack scenarios, produces a single signed DrillReport. | Scheduled and pre-release |
| **Discovery** | `pip install blastcontain-discovery` | Shadow AI and agent enumeration. Finds agents and models not registered in the Ledger. | On a schedule (daily / weekly) |

**The integration guarantee:** An agent cannot register without passing Verify. An agent without a Charter cannot be registered. Every runtime event flows into the Ledger. Every Drill report is attached to the Ledger. Every Discovery finding triggers a Verify run for the newly found agent.

**The governing question:** Is every agent in this environment known, policy-bound, continuously monitored, financially priced, and adversarially tested — and can you prove it to a regulator?

---

## 2. Release Strategy

Each component ships independently. The platform is built and proven piece by piece.

```
Phase 1  blastcontain-verify     Harden, test, publish to PyPI
Phase 2  Charter + GUI           Define what agents are allowed to do
Phase 3  Verify ↔ Charter        Scan against the registered policy
Phase 4  Ledger                  Continuous audit trail, fleet dashboard
Phase 5  AGT enforcement         Charter deny decisions block execution
Phase 6  blastcontain-discovery  Find unknown agents, trigger Verify
Phase 7  blastcontain-drill      Prove controls work adversarially
```

Each phase releases a working, useful product. Nothing waits on everything else.

---

## 3. Repository Structure

```
blastcontain/
│
├── tools/
│   │
│   ├── blastcontain-verify/                  # pip install blastcontain-verify
│   │   ├── pyproject.toml
│   │   └── blastcontain_verify/
│   │       ├── __init__.py
│   │       ├── cli.py                        # Click entry point
│   │       ├── config.py                     # Load blastcontain-verify.yaml + CLI flags
│   │       ├── models.py                     # InfraFinding, ScanResult, _make_finding
│   │       ├── constants.py                  # _MIT, _FINDING_TYPE, all patterns
│   │       ├── augmentation.py               # try/except imports, availability flags
│   │       ├── scanner.py                    # Orchestrator — calls checks/, ~100 lines
│   │       ├── reporter.py                   # Markdown report + JSON audit packet
│   │       └── checks/
│   │           ├── __init__.py
│   │           ├── environment.py            # ENV-01, ENV-02, ENV-03
│   │           ├── filesystem.py             # DISK-01, DISK-02
│   │           ├── credentials.py            # CRED-01, CRED-02, CRED-03
│   │           ├── process.py                # PRIV-01, CAP-01
│   │           ├── network.py                # NET-01, NET-02
│   │           ├── persistence.py            # PERM-01
│   │           ├── memory.py                 # MEM-01, MEM-03, MEM-05
│   │           ├── skills.py                 # SKILL-01, SKILL-02
│   │           ├── api.py                    # API-01, API-02
│   │           ├── mcp.py                    # MCP-01, MCP-02, MCP-03
│   │           ├── code.py                   # CODE-01
│   │           ├── supply_chain.py           # SUP-01
│   │           ├── tls.py                    # TLS-01
│   │           └── local.py                  # LOCAL-01
│   │
│   ├── blastcontain-drill/                   # pip install blastcontain-drill
│   │   ├── pyproject.toml
│   │   └── blastcontain_drill/
│   │       ├── __init__.py
│   │       ├── cli.py
│   │       ├── config.py
│   │       ├── models.py                     # DrillFinding, DrillReport
│   │       ├── runner.py                     # Orchestrator — sequences scenarios
│   │       ├── reporter.py                   # Markdown report + signed DrillReport JSON
│   │       └── scenarios/
│   │           ├── __init__.py
│   │           ├── prompt_injection.py       # Adversarial prompt injection chains
│   │           ├── trust_boundary.py         # Trust boundary probes
│   │           ├── delegation_abuse.py       # Delegation chain abuse
│   │           ├── mcp_hijack.py             # MCP tool hijacking scenarios
│   │           ├── data_exfiltration.py      # End-to-end exfiltration attempts
│   │           └── jailbreak.py              # Content policy evasion
│   │
│   └── blastcontain-discovery/               # pip install blastcontain-discovery
│       ├── pyproject.toml
│       └── blastcontain_discovery/
│           ├── __init__.py
│           ├── cli.py
│           ├── config.py
│           ├── models.py                     # DiscoveredAsset, DiscoveryReport
│           ├── scanner.py                    # Orchestrator — runs all scanners
│           ├── reporter.py                   # Markdown report + signed JSON
│           └── scanners/
│               ├── __init__.py
│               ├── network.py                # Port scan for agent API endpoints
│               ├── process.py                # Running process enumeration
│               ├── git.py                    # Repo scan for model files + agent configs
│               ├── mcp.py                    # Running MCP server detection
│               ├── registry.py               # Cross-reference against Ledger
│               └── bootstrap.py              # Draft Charter generation for new agents
│
├── server/                                   # Core platform — Charter + Ledger + GUI
│   ├── blastcontain/
│   │   ├── __init__.py
│   │   ├── charter/
│   │   │   ├── schema.py                     # CharterSchema dataclass
│   │   │   ├── validator.py                  # Charter validation rules
│   │   │   ├── compiler.py                   # Charter → AGT Rego/Cedar policy
│   │   │   ├── comparator.py                 # Diff charter versions, detect drift
│   │   │   └── recertification.py            # Quarantine lift protocol
│   │   ├── ledger/
│   │   │   ├── store.py                      # Finding persistence + query
│   │   │   ├── mpl.py                        # Maximum Probable Loss calculator
│   │   │   └── blast_radius.py               # Trust-aware blast radius engine
│   │   ├── telemetry/
│   │   │   └── otel.py                       # OTel span ingestion
│   │   ├── db/
│   │   │   ├── migrations/
│   │   │   └── models.py
│   │   ├── audit/
│   │   │   └── packet.py                     # Audit packet assembly + signing
│   │   └── api/
│   │       ├── agents.py                     # /v1/agents endpoints
│   │       ├── findings.py                   # /v1/findings endpoints
│   │       ├── charters.py                   # /v1/charters endpoints
│   │       └── fleet.py                      # /fleet, /violations, /stream
│   └── server.py                             # FastAPI app entry point
│
├── tests/
│   ├── containers/
│   │   ├── compose.yaml
│   │   ├── Containerfile.server
│   │   ├── Containerfile.verify
│   │   ├── Containerfile.drill
│   │   ├── Containerfile.discovery
│   │   ├── Containerfile.agent
│   │   └── Containerfile.multiagent
│   ├── scenarios/
│   │   ├── agent.py
│   │   └── multiagent_scenario.py
│   └── tools/
│       ├── verify/
│       │   ├── checks/
│       │   │   ├── test_environment.py
│       │   │   ├── test_filesystem.py
│       │   │   ├── test_credentials.py
│       │   │   ├── test_process.py
│       │   │   ├── test_network.py
│       │   │   ├── test_persistence.py
│       │   │   ├── test_memory.py
│       │   │   ├── test_skills.py
│       │   │   ├── test_api.py
│       │   │   ├── test_mcp.py
│       │   │   ├── test_code.py
│       │   │   ├── test_supply_chain.py
│       │   │   ├── test_tls.py
│       │   │   └── test_local.py
│       │   ├── test_scanner.py
│       │   ├── test_reporter.py
│       │   ├── test_cli.py
│       │   └── test_config.py
│       ├── drill/
│       │   ├── test_runner.py
│       │   ├── test_reporter.py
│       │   └── test_scenarios.py
│       └── discovery/
│           ├── test_scanner.py
│           ├── test_reporter.py
│           └── scanners/
│               ├── test_network.py
│               ├── test_process.py
│               └── test_git.py
│
├── docs/
│   ├── blastcontain-spec.md                  # This file
│   └── blastcontain-verify-spec.md           # Detailed Verify engineering spec
│
├── pyproject.toml                            # Root workspace config
├── requirements-base.txt
└── README.md
```

---

## 4. Environments

Every agent has a separate Charter per environment. An agent's identity key is `(agent_id, environment)` — not just `agent_id`.

| Environment | Enforcement level | AGT blocking | Quarantine |
|---|---|---|---|
| `dev` | Informational — findings shown, not blocking | Off | No |
| `uat` | REJECTED/QUARANTINED blocks promotion | Optional | Manual lift |
| `staging` | Same as UAT | Optional | Manual lift |
| `prod` | Full enforcement | On | Auto, requires recertification |
| `local_developer_workstation` | Informational + LOCAL-01 CRITICAL | Off | No |

**Promotion workflow:**

```
Author Charter (dev) → Verify passes at dev
         ↓
Promote to UAT → Charter diff shown → Verify must pass at UAT
         ↓
Promote to prod → Charter diff shown → Verify must pass at prod → sign-off required
```

Promotion is a deliberate governance action, not an automatic pipeline step. A Charter promoted to `prod` must explicitly address every CRITICAL finding from the `uat` scan.

`blastcontain-verify --env` drives both which Charter is fetched (server mode) and which enforcement level applies to findings.

---

## 5. Sovereign Stack

BlastContain integrates with the enterprise AI defence stack. AGT and Cisco AI Defense run in-process inside each agent. BlastContain runs above them — consuming their signals, enforcing policy consequences, and producing the unified audit record.

| Layer | Component | Role |
|---|---|---|
| **Foundation** | Cisco AI Defense | Network defence, shadow AI detection, MCP inspection, model weight scanning, prompt inspection, data classification. In-process SDK. Base value for MPL calculation. |
| **Framework** | Microsoft AGT | Agent identity (Ed25519 DIDs), policy engine (Rego/Cedar), KernelSpace lifecycle events, MCP Security Gateway (default-deny), PromptDefenseEvaluator, red-team scenario library. In-process SDK. Receives Charter policy and Quarantine Signals from BlastContain. |
| **Platform** | BlastContain | Charter authoring and enforcement, pre-deployment Verify scanning, continuous Ledger audit trail, adversarial Drill reporting, fleet Discovery. Consumes AGT and Cisco signals. Produces the unified Audit Packet. |
| **Agent Process** | Runtime | AGT KernelSpace + Cisco `agentsec.protect()` initialised at agent startup. BlastContain Verify runs as a pre-registration sidecar. All three layers active simultaneously. |

**AGT active enforcement note:** AGT's PolicyEngine returns ALLOW/DENY decisions with sub-millisecond latency. When `push_to_agt()` in `charter/compiler.py` is implemented (currently a stub), Charter deny decisions will prevent tool execution before it occurs — not log it after. This is Phase 5 of the release strategy and the difference between BlastContain being a governance record and a governance control.

---

## 6. Tool: blastcontain-verify

**Pre-Deployment Environmental Compliance Scanner**

```bash
pip install blastcontain-verify
pip install "blastcontain-verify[full]"   # + Cisco + AGT + Presidio + PyYAML
```

Runs inside the agent's environment before registration. Probes 24 security dimensions across 14 check groups. Produces a cryptographically signed Audit Packet and a Markdown compliance report. Works standalone (local mode) or posts to the Ledger (server mode).

### 6.1 Invocation

```bash
# Local mode
blastcontain-verify --agent-id my-agent --env prod

# With config file
blastcontain-verify --config blastcontain-verify.yaml

# Server mode — posts findings to Ledger
blastcontain-verify \
  --agent-id my-agent \
  --env prod \
  --blastcontain-url http://blastcontain-server:8080 \
  --report ./report.md \
  --output ./audit.json
```

### 6.2 Config file (`blastcontain-verify.yaml`)

```yaml
agent_id: my-agent
environment: prod
search_path: ./src
skills_dir: ./skills          # defaults to search_path if not set
api_spec: ./openapi.yaml
mcp_config: ./mcp-servers.json
model_dir: /models/
context_file: ./context.txt
output: ./audit/packet.json
report: ./reports/latest.md
blastcontain_url: http://blastcontain-server:8080
cisco_api_key: ""             # enables PROMPT_DEFENSE analyzer
```

### 6.3 CLI flags

| Flag | Default | Description |
|---|---|---|
| `--agent-id` | required | Agent identifier |
| `--config / -c` | `blastcontain-verify.yaml` | Config file path |
| `--env` | `staging` | `dev` \| `uat` \| `staging` \| `prod` \| `local_developer_workstation` |
| `--search-path` | `.` | Root path for source and secret scanning |
| `--skills-dir` | `--search-path` | Skill code directory. Defaults to search-path. SKILL-02 is `NOT_SCANNED` if absent. |
| `--api-spec` | None | OpenAPI 3.0 JSON/YAML. `servers[]` must include FQDNs for live probing. |
| `--mcp-config` | None | MCP server config (Claude-style `mcpServers` JSON) |
| `--model-dir` | `/models/` | Model weights directory |
| `--context-file` | None | Session context text for PII scanning |
| `--output` | None | Signed JSON Audit Packet path |
| `--report` | None | Markdown report path |
| `--blastcontain-url` | `$BLASTCONTAIN_URL` | Server URL. Omit for local mode. |
| `--dry-run` | False | Skip server POST |
| `--acknowledge-risk` | False | Exit 0 even on CRITICAL |
| `--max-tier` | 0 | Highest TrustTier in delegation chain |

### 6.4 Exit codes

| Code | Status | Condition |
|---|---|---|
| 0 | APPROVED | No findings |
| 1 | REJECTED | HIGH or MEDIUM findings only |
| 2 | QUARANTINED | At least one CRITICAL finding |
| 3 | ERROR | Could not reach BlastContain server |

### 6.5 Check inventory

| Group | Check IDs | What it covers |
|---|---|---|
| Environment | ENV-01, ENV-02, ENV-03 | Kernel isolation, network egress, model weight mutability |
| Filesystem | DISK-01, DISK-02 | Root filesystem write access |
| Credentials | CRED-01, CRED-02, CRED-03 | Secrets on disk, env vars, wildcard API caps |
| Process | PRIV-01, CAP-01 | Elevated privilege, Linux capabilities |
| Network | NET-01, NET-02 | DNS egress, external listeners |
| Persistence | PERM-01 | Startup and cron write access |
| Memory | MEM-01, MEM-03, MEM-05 | PII in context, namespace isolation, exfil path |
| Skills | SKILL-01, SKILL-02 | MCP tool exfil capability, Cisco skill scan |
| APIs | API-01, API-02 | Destructive permissions, unauthenticated endpoints |
| MCP Servers | MCP-01, MCP-02, MCP-03 | Unapproved tools, missing auth, dangerous combos |
| Code | CODE-01 | Dangerous execution patterns |
| Supply Chain | SUP-01 | Model weight attestation |
| Transport | TLS-01 | Plaintext inter-agent channels |
| Local | LOCAL-01 | Developer workstation detection |

#### ENV-01 — Kernel Isolation Missing
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | `dmesg` for gVisor signal → `/proc/sys/kernel/osrelease` for host kernel signatures (ubuntu, fedora, debian, arch, centos, rhel, amazon). Non-Linux fails immediately. |
| **Fix** | `docker run --runtime=runsc` / Kubernetes `runtimeClassName: gvisor` |
| **Refs** | https://gvisor.dev/docs/user_guide/quick_start/docker/ |

#### ENV-02 — Network Egress Unrestricted
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | TCP connect to `8.8.8.8:53` |
| **Fix** | `--network=none` / Compose `internal: true` / Kubernetes NetworkPolicy `policyTypes: [Egress]` |

#### ENV-03 — Model Weight Directory Writable
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Write `.agall_canary.tmp` to `model_dir` |
| **Fix** | `-v /path/to/models:/models:ro` / Kubernetes `readOnly: true` on volumeMount |

#### DISK-01 — Filesystem Writable (Developer Workstation)
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Write `~/.agall_root_canary.tmp`. Fires when env contains `workstation` or `local`. |
| **Fix** | Run inside container even on dev machines |

#### DISK-02 — Container Root Filesystem Writable
| | |
|---|---|
| **Severity** | MEDIUM |
| **Probe** | Same canary write. Fires when env is not a workstation. |
| **Fix** | `--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m` |

#### CRED-01 — Hardcoded Secrets on Disk
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Walk `search_path` for `.env`, `.yaml`, `.json`, `.conf` etc. Pattern match: `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AZURE_CLIENT_SECRET`, `DATABASE_PASSWORD`, `SECRET_KEY` |
| **Fix** | Move to secrets manager. Rotate immediately — assume compromised. |

#### CRED-02 — Live Credentials in Process Environment
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Scan `os.environ` for secret key names or token value prefixes: `ghp_`, `sk-ant-`, `sk-`, `xoxb-`, `AKIA`, `ASIA` |
| **Fix** | Secrets injection as files, not env vars. Unset after reading. |

#### CRED-03 — Wildcard API Capability
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | Scan tool spec for `/*`, `"*"`, `':*'`. Also runs Cisco MCP Scanner + AGT MCPSecurityScanner. |
| **Fix** | Replace wildcards with explicit endpoint allowlists in Charter. |

#### PRIV-01 — Elevated Process Privilege
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | `os.getuid() == 0` (Linux/macOS) / `IsUserAnAdmin()` (Windows) |
| **Fix** | `USER agent` in Containerfile / `runAsNonRoot: true` in Kubernetes |

#### CAP-01 — Dangerous Linux Capabilities
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | `/proc/self/status` `CapEff`. Flags: `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO` |
| **Fix** | `--cap-drop ALL` / `capabilities: drop: [ALL]` |

#### NET-01 — DNS Exfiltration Channel Open
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | UDP DNS query for `google.com` to `8.8.8.8:53` |
| **Fix** | Block UDP/53 egress. Redirect to internal resolver. |

#### NET-02 — External Network Listeners
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | `/proc/net/tcp`, `/proc/net/tcp6`, `netstat` — LISTEN on `0.0.0.0` or `::` |
| **Fix** | Bind to `127.0.0.1` explicitly. `--publish 127.0.0.1:8080:8080`. |

#### PERM-01 — Persistence Location Write Access
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Write-probe startup paths by platform. Linux: `~/.bashrc`, `/etc/cron.d`. macOS: `~/Library/LaunchAgents`. Windows: `%APPDATA%\...\Startup`. |
| **Fix** | `--read-only` filesystem. Non-root user without home directory write access. |

#### MEM-01 — Unmasked PII in Session Context
| | |
|---|---|
| **Severity** | MEDIUM (→ MEM-05 CRITICAL if egress open) |
| **Probe** | Presidio `AnalyzerEngine` → Cisco `ChatInspectionClient` → AGT `PromptDefenseEvaluator`. Fallback: keyword + regex patterns. |
| **Fix** | Presidio Anonymizer at context ingestion. Never pass raw user data into agent context. |

#### MEM-05 — Viable PII Exfiltration Path
| | |
|---|---|
| **Severity** | CRITICAL |
| **Condition** | MEM-01 fires AND ENV-02 fires (PII present + egress open) |
| **Fix** | Fix both ENV-02 (block egress) AND MEM-01 (mask PII). |

#### MEM-03 — Memory Store Lacks Tenant Namespace Isolation
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Env vars + config files for Vector DB / Redis connections. Flags generic namespaces: `default`, `prod`, `shared`, `global`, `vectors`. Flags Pinecone with no `PINECONE_NAMESPACE`. Flags Redis database 0. |
| **Fix** | `PINECONE_NAMESPACE=tenant_{agent_id}` / `QDRANT_COLLECTION=agent_{id}_v1` / Redis db > 0 |

#### SKILL-01 — Exfiltration-Capable Skill
| | |
|---|---|
| **Severity** | HIGH (→ CRITICAL if PII present) |
| **Probe** | Tool name + description pattern match: `http_post`, `send_email`, `exec`, `upload_file`, `s3_put`, `data_export` etc. |
| **Fix** | Remove exfiltration-capable tools. Scope with AGT PolicyEngine allowlist. |

#### SKILL-02 — Cisco AI Skill Scanner Findings
| | |
|---|---|
| **Severity** | Mapped from Cisco `max_severity`: CRITICAL→CRITICAL, HIGH→HIGH, MEDIUM→MEDIUM, LOW/INFO→note only |
| **Probe** | `SkillScanner.scan_skill(skills_dir)`. Skipped if package not installed. |
| **Fix** | Review Cisco findings individually. Remove or scope flagged capabilities. |

#### API-01 — Destructive API Permissions
| | |
|---|---|
| **Severity** | CRITICAL (wildcard confirmed live), HIGH (wildcard unconfirmed or named confirmed), MEDIUM (named unconfirmed) |
| **Probe** | Parse OpenAPI spec for `DELETE`, `PUT`, `PATCH`, destructive `POST`. OPTIONS live probe to `servers[]` FQDNs. |
| **Fix** | Remove from agent tool list or scope to specific resource IDs. Register in Charter `permitted_apis`. |

#### API-02 — Unauthenticated Endpoints
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | OpenAPI spec — paths with no security scheme on destructive endpoints |
| **Fix** | Add `security: [{bearerAuth: []}]` to all path definitions. Enforce at API gateway. |

#### MCP-01 — Unapproved MCP Tool
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | `scan_remote_server_tools()` / `scan_stdio_server_tools()` vs Charter `permitted_tools`. Also runs AGT MCPSecurityScanner. |
| **Fix** | Register all tools in Charter `permitted_tools`. Use AGT MCP Security Gateway (default-deny). |

#### MCP-02 — MCP Server Without Authentication
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | MCP config entries with no auth scheme or `http://` URLs |
| **Fix** | Add API key or OAuth. Use `https://`. Bind to `127.0.0.1` if auth unavailable in dev. |

#### MCP-03 — Dangerous MCP Tool Combination
| | |
|---|---|
| **Severity** | CRITICAL |
| **Probe** | Categorise all tools into Read / Execute / Send / Write / Credential. Flag dangerous pairs. |

**Capability categories:**

| Category | Example tools |
|---|---|
| Read | `read_file`, `query_db`, `list_dir`, `get_object`, `search` |
| Execute | `exec`, `shell_exec`, `run_command`, `eval`, `execute_script` |
| Send | `http_post`, `send_email`, `upload_file`, `s3_put`, `webhook` |
| Write | `write_file`, `delete_file`, `insert_db`, `update_db` |
| Credential | `get_secret`, `read_env`, `aws_credentials`, `oauth_token` |

**Dangerous pairs:**

| Combination | Attack pattern | Severity |
|---|---|---|
| Read + Send | Exfiltrate data | CRITICAL |
| Credential + Send | Steal credentials | CRITICAL |
| Execute + Write | Execute payload, persist | CRITICAL |
| Read + Execute | Read and execute attacker file | CRITICAL |
| Write + Execute | Drop and run binary | CRITICAL |
| Read + Write | Read then corrupt data | HIGH |

#### CODE-01 — Dangerous Code Execution Patterns
| | |
|---|---|
| **Severity** | CRITICAL: `eval()`, `exec()`, `os.system()`, `shell=True` / HIGH: `pickle.loads()`, `yaml.load()`, `__import__()` |
| **Probe** | Walk `search_path` for `.py .js .ts .rb .go .java .cs .php`. Binary pattern scan. |
| **Fix** | `ast.literal_eval()` instead of `eval()`. `subprocess.run(shell=False)`. `yaml.safe_load()`. `json` instead of `pickle`. |

#### SUP-01 — Model Weights Without Attestation
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | `model_dir` contains `.bin .pt .gguf .safetensors .onnx` etc. without `.sha256 .sig .asc` or `manifest.json` alongside. Cisco `ModelScanClient` if available. |
| **Fix** | `sha256sum model.bin > model.bin.sha256`. Verify at load time. |

#### TLS-01 — Plaintext HTTP Endpoint
| | |
|---|---|
| **Severity** | HIGH |
| **Probe** | Regex scan all spec files for `http://` URLs |
| **Fix** | Replace all `http://` with `https://`. Use `mkcert` for local dev TLS. |

#### LOCAL-01 — Agent Running on Developer Workstation
| | |
|---|---|
| **Severity** | HIGH (→ CRITICAL if live API credentials in env) |
| **Probe** | Home path `/Users/` or `\Users\`. IDE env vars: `VSCODE_PID`, `CURSOR_TRACE_ID`, `JETBRAINS_IDE`. IDE config dirs: `~/.vscode`, `~/.cursor`, `~/.idea`. |
| **Fix** | Run inside container or microVM even on developer machines. |

### 6.6 Augmentation

All augmentation is optional and additive. Ephor's own checks always run. Third-party scanners add signal on top.

| Package | Availability flag | Adds to |
|---|---|---|
| `presidio-analyzer` | `PRESIDIO_AVAILABLE` | MEM-01, MEM-05 |
| `cisco-aidefense-sdk` | `CISCO_SDK_AVAILABLE` | MEM-01, MEM-05, SUP-01 |
| `cisco-ai-mcp-scanner` | `CISCO_MCP_AVAILABLE` | CRED-03, MCP-01/02/03 |
| `cisco-ai-skill-scanner` | `CISCO_SKILL_AVAILABLE` | SKILL-02 |
| `agent-governance-toolkit` | `AGT_AVAILABLE` | CRED-03, MEM-01, MCP-01 |

**MCP Scanner analyzers used in Verify:**

| Analyzer | Needs key | Used |
|---|---|---|
| `API` | No | ✅ Always |
| `YARA` | No | ✅ Always |
| `READINESS` | No | ✅ Always |
| `PROMPT_DEFENSE` | Cisco key | ✅ If `CISCO_AIDEFENSE_API_KEY` set |
| `LLM` | LLM key | ❌ Breaks offline guarantee. Belongs in Drill. |
| `VIRUSTOTAL` | VT key | ❌ Out of scope for pre-deployment scan. |

### 6.7 Report format

```markdown
# BlastContain Verify — Agent Compliance Report

Agent: my-agent | Environment: prod | Status: 🔴 QUARANTINED
Scanned: 2026-05-22T14:32:01 UTC | Blast Radius: 4.0x

## Summary

| Group       | 🔴 CRITICAL | 🟠 HIGH | 🟡 MEDIUM | ✅ PASS | ⏭ SKIP |
|-------------|-------------|---------|-----------|---------|--------|
| Environment | 1           | 0       | 0         | 2       | 0      |
| ...         |             |         |           |         |        |
| **Total**   | **3**       | **2**   | **1**     | **18**  | **3**  |

## 🔴 Critical Findings

### ENV-01 — Shared Host-Kernel Environment Detected

**Severity:** CRITICAL | **MIT Risk:** MIT-SYS-02

**What happened**
...

**Why it matters**
...

**How to fix**
...

**References**
- https://...

## ✅ Passed Checks

| Check ID | Name                             |
|----------|----------------------------------|
| ENV-02   | Network Egress Blocked           |
| PRIV-01  | Agent Running as Non-Root        |

## ⏭ Skipped Checks

| Check ID | Reason                                    |
|----------|-------------------------------------------|
| MCP-01   | --mcp-config not provided                 |
| SKILL-02 | cisco-ai-skill-scanner not installed      |
```

---

## 7. Tool: blastcontain-drill

**Adversarial Red-Team Scanner**

```bash
pip install blastcontain-drill
pip install "blastcontain-drill[full]"   # + AGT + Cisco adversarial suites
```

Runs attack scenarios against a registered agent and produces a single signed DrillReport. Proves governance controls work before a real incident occurs. Same Audit Packet format as Verify — posts to the Ledger in server mode.

### 7.1 Invocation

```bash
# Local mode — run against a target agent
blastcontain-drill \
  --agent-id my-agent \
  --agent-url http://agent:8080 \
  --env prod \
  --report ./drill-report.md \
  --output ./drill-packet.json

# With Charter from file
blastcontain-drill \
  --agent-id my-agent \
  --agent-url http://agent:8080 \
  --charter ./charter.json \
  --env prod

# Server mode — fetch Charter from Ledger, post results
blastcontain-drill \
  --agent-id my-agent \
  --agent-url http://agent:8080 \
  --env prod \
  --blastcontain-url http://blastcontain-server:8080 \
  --report ./drill-report.md
```

### 7.2 Config file (`blastcontain-drill.yaml`)

```yaml
agent_id: my-agent
agent_url: http://agent:8080
environment: prod
charter: ./charter.json          # optional — pulled from server if blastcontain_url set
scenarios:                       # optional — defaults to all
  - prompt_injection
  - trust_boundary
  - mcp_hijack
  - data_exfiltration
  - jailbreak
output: ./drill/packet.json
report: ./drill/report.md
blastcontain_url: http://blastcontain-server:8080
```

### 7.3 CLI flags

| Flag | Default | Description |
|---|---|---|
| `--agent-id` | required | Target agent identifier |
| `--agent-url` | required | Target agent API endpoint |
| `--config / -c` | `blastcontain-drill.yaml` | Config file path |
| `--env` | `staging` | Target environment |
| `--charter` | None | Local Charter JSON. Pulled from server if `--blastcontain-url` set. |
| `--scenarios` | all | Comma-separated scenario list |
| `--output` | None | Signed DrillReport JSON path |
| `--report` | None | Markdown report path |
| `--blastcontain-url` | `$BLASTCONTAIN_URL` | Server URL for Charter fetch and result posting |
| `--dry-run` | False | Skip server POST |

### 7.4 Exit codes

| Code | Status | Condition |
|---|---|---|
| 0 | PASSED | No bypasses detected |
| 1 | PARTIAL | Some scenarios bypassed defences |
| 2 | FAILED | Critical bypasses confirmed |
| 3 | ERROR | Could not reach agent or server |

### 7.5 Scenario inventory

| Scenario | Module | AGT | Cisco | What it tests |
|---|---|---|---|---|
| Prompt Injection | `scenarios/prompt_injection.py` | `PromptDefenseEvaluator` | `ChatInspectionClient` | Adversarial prompts attempting to override agent instructions |
| Trust Boundary | `scenarios/trust_boundary.py` | KernelSpace probes | — | Cross-agent trust boundary violations |
| Delegation Abuse | `scenarios/delegation_abuse.py` | PolicyEngine | — | Delegation chain escalation attempts |
| MCP Hijack | `scenarios/mcp_hijack.py` | `MCPSecurityScanner` | `cisco-ai-mcp-scanner` | MCP tool hijacking via malicious server responses |
| Data Exfiltration | `scenarios/data_exfiltration.py` | `PromptDefenseEvaluator` | `ChatInspectionClient` | End-to-end exfiltration pipeline attempts |
| Jailbreak | `scenarios/jailbreak.py` | — | `ChatInspectionClient` | Content policy evasion and constraint bypass |

### 7.6 DrillReport format

```markdown
# BlastContain Drill — Adversarial Test Report

Agent: my-agent | Environment: prod | Status: 🟠 PARTIAL
Drilled: 2026-05-22T16:00:00 UTC | Scenarios run: 6 | Bypasses: 2

## Summary

| Scenario          | Result   | Detection latency | Blocked by        |
|-------------------|----------|-------------------|-------------------|
| Prompt Injection  | ✅ HELD  | 12ms              | AGT PromptDefense |
| Trust Boundary    | ✅ HELD  | 8ms               | AGT PolicyEngine  |
| Delegation Abuse  | 🟠 BYPASS | —                | Not detected      |
| MCP Hijack        | ✅ HELD  | 45ms              | Cisco MCP Scanner |
| Data Exfiltration | 🔴 BYPASS | —                | Not detected      |
| Jailbreak         | ✅ HELD  | 23ms              | Cisco ChatInspect |

## 🔴 Bypasses Detected

### DATA-EXFIL-01 — Exfiltration Pipeline Succeeded
...

## Comparison to baseline
Previous drill: 2026-05-15 | Regressions: 1 | Improvements: 0
```

### 7.7 Module structure

```
blastcontain_drill/
├── cli.py          # Click entry point. --agent-url, --charter, --scenarios
├── config.py       # Load blastcontain-drill.yaml + CLI flags
├── models.py       # DrillFinding, DrillReport, ScenarioResult
├── runner.py       # Sequences scenarios, measures detection latency, collects results
├── reporter.py     # write_drill_report(), write_drill_packet()
└── scenarios/
    ├── __init__.py
    ├── base.py              # BaseScenario abstract class
    ├── prompt_injection.py  # AGT PromptDefenseEvaluator + Cisco ChatInspectionClient
    ├── trust_boundary.py    # AGT KernelSpace probes
    ├── delegation_abuse.py  # AGT PolicyEngine delegation chain tests
    ├── mcp_hijack.py        # Cisco MCP Scanner + AGT MCPSecurityScanner
    ├── data_exfiltration.py # End-to-end pipeline construction + attempt
    └── jailbreak.py         # Cisco adversarial suite
```

---

## 8. Tool: blastcontain-discovery

**Shadow AI and Agent Discovery Engine**

```bash
pip install blastcontain-discovery
pip install "blastcontain-discovery[full]"   # + AGT Shadow AI + Cisco scanners
```

Runs on a schedule. Finds agents and models already running in the environment that have not been registered. Cross-references against the Ledger registry. Triggers Verify for every newly found agent. Bootstraps a draft Charter for each one.

### 8.1 Invocation

```bash
# Local mode — scan a network range
blastcontain-discovery \
  --env prod \
  --network 10.0.0.0/24 \
  --report ./discovery.md \
  --output ./discovery-packet.json

# Server mode — cross-reference against Ledger
blastcontain-discovery \
  --env prod \
  --network 10.0.0.0/24 \
  --blastcontain-url http://blastcontain-server:8080 \
  --trigger-verify \
  --bootstrap-charter \
  --report ./discovery.md
```

### 8.2 Config file (`blastcontain-discovery.yaml`)

```yaml
environment: prod
network: 10.0.0.0/24               # CIDR range to scan
search_path: ./repos                # Git repos to scan
process_scan: true                  # Enumerate running processes
output: ./discovery/packet.json
report: ./discovery/report.md
blastcontain_url: http://blastcontain-server:8080
trigger_verify: true                # Auto-run Verify on newly found agents
bootstrap_charter: true             # Generate draft Charter for new agents
schedule: "0 2 * * *"              # Cron — run daily at 02:00
```

### 8.3 CLI flags

| Flag | Default | Description |
|---|---|---|
| `--env` | `prod` | Target environment |
| `--config / -c` | `blastcontain-discovery.yaml` | Config file |
| `--network` | None | CIDR range for network scan (e.g. `10.0.0.0/24`) |
| `--search-path` | `.` | Root path for git repo and model file scanning |
| `--process-scan` | True | Enumerate running processes for agent frameworks |
| `--output` | None | Signed DiscoveryReport JSON |
| `--report` | None | Markdown report |
| `--blastcontain-url` | `$BLASTCONTAIN_URL` | Server URL for registry cross-reference |
| `--trigger-verify` | False | Auto-run Verify on each newly discovered agent |
| `--bootstrap-charter` | False | Generate draft Charter for each new agent |
| `--dry-run` | False | Skip Verify triggers and Charter bootstrap |

### 8.4 Scanner inventory

| Scanner | Module | AGT | Cisco | What it finds |
|---|---|---|---|---|
| Network | `scanners/network.py` | — | `cisco-ai-mcp-scanner` | Agent API endpoints, MCP servers, LLM inference ports on network range |
| Process | `scanners/process.py` | Shadow AI Discovery | — | Running processes with agent framework signatures (LangChain, AutoGen, CrewAI, Semantic Kernel) |
| Git | `scanners/git.py` | — | — | Model weight files, LLM configs, agent entrypoints in repositories not linked to a registered Charter |
| MCP | `scanners/mcp.py` | `MCPSecurityScanner` | `cisco-ai-mcp-scanner` | Running MCP servers not in the Ledger registry |
| Registry | `scanners/registry.py` | — | — | Cross-reference all found assets against Ledger. Classifies: registered, known-unverified, unknown (shadow AI) |
| Bootstrap | `scanners/bootstrap.py` | PolicyEngine | — | Generates draft Charter from observed tool usage, network access, and file permissions |

### 8.5 Asset classification

| Classification | Meaning | Action |
|---|---|---|
| **Registered** | Found in Ledger with valid Charter and passing Verify | ✅ No action |
| **Known — unverified** | In Ledger but Verify not run recently or not passing | 🟡 Trigger Verify |
| **Unknown — shadow AI** | Not in Ledger at all | 🔴 Trigger Verify + bootstrap Charter |

### 8.6 Discovery report format

```markdown
# BlastContain Discovery — Fleet Discovery Report

Environment: prod | Scanned: 2026-05-22T02:00:00 UTC
Assets found: 14 | Registered: 11 | Shadow AI: 3

## 🔴 Shadow AI Detected (3)

### agent-unknown-192.168.1.45:8080
**Type:** LangChain agent (detected via process enumeration)
**Network:** Listening on 0.0.0.0:8080
**Tools detected:** read_file, http_post, execute_command
**Risk:** Exfiltration-capable tool combination (Read + Send + Execute)
**Action:** Verify triggered. Draft Charter bootstrapped at ./charters/draft_agent_unknown_1.json

...

## 🟡 Known — Unverified (2)

## ✅ Registered (11)

## Draft Charters Generated
- ./charters/draft_agent_unknown_1.json
- ./charters/draft_agent_unknown_2.json
- ./charters/draft_agent_unknown_3.json
```

### 8.7 Module structure

```
blastcontain_discovery/
├── cli.py
├── config.py
├── models.py       # DiscoveredAsset, DiscoveryReport, AssetClassification
├── scanner.py      # Orchestrator — runs all scanners, merges results
├── reporter.py     # write_discovery_report(), write_discovery_packet()
└── scanners/
    ├── __init__.py
    ├── base.py              # BaseScanner abstract class
    ├── network.py           # Port scan, HTTP probe for agent endpoints
    ├── process.py           # psutil + AGT Shadow AI Discovery
    ├── git.py               # Walk repos for models, configs, entrypoints
    ├── mcp.py               # Cisco MCP Scanner for running servers
    ├── registry.py          # GET /v1/agents from Ledger, classify results
    └── bootstrap.py         # Draft Charter from observed capabilities
```

---

## 9. Platform: Charter

**Agent Policy Constitution**

The Charter is the signed contract between the organisation and an agent. It defines what the agent is allowed to do. Without a Charter, the agent cannot register.

### 9.1 Charter schema

```json
{
  "agent_id": "my-agent",
  "environment": "prod",
  "version": "1.2.0",
  "trust_tier": 1,
  "signed_at": "2026-05-22T10:00:00Z",
  "signed_by": "did:key:z6Mk...",
  "permitted_tools": [
    "query_db",
    "send_notification"
  ],
  "permitted_apis": [
    { "url": "https://api.internal.company.com/v2", "methods": ["GET", "POST"] }
  ],
  "mcp_servers": [
    { "name": "data-mcp", "url": "https://mcp.internal:3001" }
  ],
  "environment_constraints": {
    "read_only_rootfs": true,
    "egress_blocked": true,
    "max_trust_tier": 1,
    "verify_required": true
  },
  "remediation_proof": null
}
```

### 9.2 Charter features

| Feature | Description |
|---|---|
| Charter Authoring | GUI + CLI for defining agent identity, tool allowlist, trust tier, environment constraints, delegation rules |
| Charter Compiler | Translates Charter JSON to AGT Rego/Cedar policy. Charter is the single source of truth. |
| Version Control | Every Charter is versioned and signed. Diff between versions surfaces capability creep automatically. |
| Repository Scanner | Validates Charter on every commit. Missing or invalid Charter blocks staging/prod promotion. |
| Comparative Analysis | Compares declared Charter intent against Ledger-observed behaviour. Detects drift. |
| Recertification Protocol | Agent cannot be re-registered after CRITICAL quarantine until a new Charter version explicitly addresses the triggering FindingType. Produces Proof of Remediation artifact. |
| Environment Constraints | Charter mandates specific Verify pass conditions (`read_only_rootfs: true`, `egress_blocked: true`, etc.) |
| Per-environment Charters | `(agent_id, environment)` is the unique identity key. Dev, UAT, and prod Charters are independent documents with independent version histories. |
| `push_to_agt()` | **Currently a stub.** When implemented: Charter deny decisions are enforced by AGT PolicyEngine at runtime. Blocked actions do not execute. This is Phase 5. |

### 9.3 API endpoints (server)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/charters` | Create or update a Charter |
| `GET` | `/v1/charters/{agent_id}?env={env}` | Fetch Charter for agent + environment |
| `GET` | `/v1/charters/{agent_id}/diff?from={v1}&to={v2}` | Diff two Charter versions |
| `POST` | `/v1/charters/{agent_id}/promote` | Promote Charter from one env to another |
| `POST` | `/v1/charters/{agent_id}/recertify` | Submit Proof of Remediation to lift quarantine |

---

## 10. Platform: Ledger

**Continuous Audit Trail and Compliance Observation**

Every finding, every registration, every Charter change, every runtime event — recorded, signed, and financially priced.

### 10.1 Ledger features

| Feature | Description |
|---|---|
| Signed Audit Packets | Stores cryptographically signed JSON packets from Verify, Drill, and Discovery. SHA-256 HMAC over findings + metadata. |
| MPL Calculator | Maximum Probable Loss formula: `(Base Value × Volume Factor) × Regulatory Multiplier × Blast Radius × Business Context × TrustTier`. Dollar exposure on every finding. |
| Trust-Aware Blast Radius | Tracks TrustTier of every agent in the delegation chain. TIER_3 agent in chain = 4.0x blast amplifier. |
| Fleet Dashboard | `/fleet` — real-time compliance across all agents. `/violations` — live finding stream. `/stream` — SSE event feed. |
| Pattern Detection | Repeated findings of the same type in 24h trigger PatternAlert to Technical Owner. |
| Charter Drift Tracker | Detects behavioural drift across releases without Charter changes. |
| MIT AI Risk Mapping | Every finding mapped to MIT AI Risk Repository v4 Domain and Causal ID. Audit Packets readable by global regulators. |
| Evidence Scrubbing | PII/PHI SHA-256 hashed before persistence. GDPR and EU AI Act data minimisation compliant. |
| Retention + Query API | Immutable finding history. Query by agent, finding type, severity, time window, MIT domain. |
| AGT Event Ingestion | KernelSpace policy evaluation decisions, trust boundary crossings, capability grants streamed as Ledger entries. |
| Cisco Telemetry Ingestion | Inference-time policy violations, prompt inspection results, model scan events ingested as Ledger entries. |

### 10.2 API endpoints (server)

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/agents/{id}/findings` | Ingest findings from Verify, Drill, Discovery |
| `GET` | `/v1/agents/{id}/findings` | Query findings for an agent |
| `GET` | `/fleet` | Fleet-wide compliance status |
| `GET` | `/violations` | All findings across fleet |
| `GET` | `/stream` | SSE stream of live findings |
| `GET` | `/health` | Server health check |

### 10.3 MIT AI Risk Repository mapping (key checks)

| Finding | MIT Domain | MIT Causal ID |
|---|---|---|
| ENV-01: Kernel Isolation Missing | System Deficiencies | MIT-SYS-02 |
| ENV-02: Egress Unrestricted | Exfiltration Vectors | MIT-NET-05 |
| CRED-01: Secrets on Disk | Identity Abuse | MIT-ID-01 |
| CRED-02: Env Credentials | Identity Abuse | MIT-ID-02 |
| MEM-05: PII Exfiltration Path | Data Security Failures | MIT-DATA-11 |
| SKILL-01: Exfil-Capable Skill | Tool Vetting Lack | MIT-TOOL-04 |
| API-01: Destructive API Active | Tool Vetting Lack | MIT-TOOL-05 |
| CODE-01: Dangerous Code Pattern | Unsafe Code Execution | MIT-CODE-01 |
| charter.drift_detected | Human-AI Interaction | MIT-C6.1 |
| charter.missing | Human-AI Interaction | MIT-C6.2 |
| discovery.shadow_ai_found | Human-AI Interaction | MIT-C6.3 |
| drill.control_bypass | Privacy and Security | MIT-C2.3 |

---

## 11. Regulatory Compliance

### 11.1 EU AI Act — Articles 12 and 14

| Requirement | What BlastContain produces | How |
|---|---|---|
| Article 12: Technical Documentation | Signed Audit Packet with MIT AI Risk Repository mapping | Every tool writes to the same Audit Packet format. MIT IDs on every finding. |
| Article 12: Logging | Complete finding timeline across all tools in one Ledger | Immutable retention. Records never deleted. |
| Article 12: Data Minimisation | PII/PHI hashed before persistence. Redaction events logged. | Ledger Evidence Scrubber + `evidence_redaction_log`. |
| Article 12: Control Verification | Signed DrillReport proving controls are functional | BlastContain Drill in staging. Regulators can cite it directly. |
| Article 14: Human Oversight | AGT DID in every session. Cryptographic proof of human authorisation. | Charter captures DID. Unbroken event chain in Ledger. |
| Article 14: Incident Response | Recertification Protocol: new Charter version must address specific FindingType before quarantine lift | Charter Compiler validates remediation. Proof of Remediation artifact in Audit Packet. |
| Article 14: HITL Evidence | HITL quality metrics continuous. Degraded HITL = quantified governance finding. | Ledger `hitl.*` findings in Audit Packet. |

### 11.2 What BlastContain does not solve

| Gap | What BlastContain does | What still requires human action |
|---|---|---|
| Human training | Surfaces rising override rates as governance findings | Cannot fix capability gaps. Tells you training failed. |
| Individual contestation rights | Proves what the agent decided and that a human authorised it | Does not provide a legal challenge path for affected individuals |
| Political will | Routes findings to named owners with MPL values | Cannot compel remediation |
| Demographic bias | Monitors error rates by case category | Does not perform subgroup fairness analysis natively |
| Zero-day agent exploits | Detects known dangerous patterns. Drill covers known scenarios. | Novel exploits against new frameworks will not be covered until patterns are updated. |
| MIT mapping completeness | Maps all findings to MIT AI Risk Repository v4 | MIT taxonomy evolves. Mapping requires periodic review. |

---

*BlastContain — governance that contains the blast radius.*
