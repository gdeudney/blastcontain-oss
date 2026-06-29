# BlastContain Verify — Engineering Specification

**Pre-Deployment Environmental Compliance Scanner**  
Version 1.2 — 2026 | Audience: Engineering, Security, DevOps

```
pip install blastcontain-verify
```

---

## Contents

1. [Purpose](#1-purpose)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [Inputs](#4-inputs)
5. [Check Inventory](#5-check-inventory)
6. [Report Format](#6-report-format)
7. [Signed Audit Packet](#7-signed-audit-packet)
8. [Module Structure](#8-module-structure)
9. [Augmentation APIs](#9-augmentation-apis)
10. [Decisions](#10-decisions)

---

## 1. Purpose

BlastContain Verify runs inside the agent's environment before it is allowed to register. It probes 27 security checks across 14 check groups, produces a cryptographically signed Audit Packet, and writes a Markdown compliance report.

Checks that require external inputs (`--api-spec`, `--mcp-config`, `--context-file`, `--model-dir`, `--skills-dir`) are recorded as **SKIP** when those inputs are not provided. All other checks always run.

| Status | Condition | Exit code |
|---|---|---|
| APPROVED | No findings | 0 |
| REJECTED | HIGH or MEDIUM findings only | 1 |
| QUARANTINED | At least one CRITICAL finding | 2 |
| ERROR | One or more check groups raised an unhandled exception, or a required flag is missing | 3 |

When a check group raises, the orchestrator emits a synthetic finding with `check_id=SCAN-<GROUP>` (e.g. `SCAN-CREDENTIALS`), `finding_type=blastcontain.scanner.check_group_failed`, and `severity=HIGH`, then continues to the next group. The overall status is set to ERROR. The audit packet is always written so the failure is auditable.

Verify is standalone — it works without a BlastContain server (local mode). When `--blastcontain-url` is set it posts findings to the Ledger (server mode). All inputs — skills, API specs, MCP server configs — are provided locally at scan time.

---

## 2. Installation

```
# Core — no augmentation
pip install blastcontain-verify

# Add Presidio PII detection (requires spaCy model)
pip install "blastcontain-verify[pii]"

# Add Cisco AI Skill Scanner — opt-in, CVE-clean as of 2.0.12 (SKILL-02)
pip install "blastcontain-verify[skill]"   # alias: [cisco]

# Add AGT PromptDefenseEvaluator and SupplyChainGuard
pip install "blastcontain-verify[agt]"

# Everything
pip install "blastcontain-verify[full]"
```

### Container (recommended)

The official container image bundles `[full]` with the spaCy `en_core_web_lg` model pre-baked. The image copies both `verify/` and the sibling `core/`, so **the build context is the `blastcontain-oss` repo root** (not `verify/`):

```
# from the blastcontain-oss/ root
podman build -t blastcontain-verify:0.3.0 -f verify/Containerfile .
```

Run with full security isolation:

```
podman run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none --tmpfs /tmp:rw,noexec,nosuid,size=64m -v "C:/path/to/agent:/scan:ro,z" -v "C:/path/to/reports:/reports:rw,z" blastcontain-verify:0.3.0 --agent-id my-agent --env prod --search-path //scan --report //reports/report.md --output //reports/audit.json --acknowledge-risk
```

Note: Use `//scan` and `//reports` (double-slash) on Windows to prevent MSYS2/Git Bash from translating Linux paths.

### Basic invocation

```
blastcontain-verify --agent-id my-agent --env prod
```

### With config file (recommended)

```
blastcontain-verify --config blastcontain-verify.yaml
```

---

## 3. Configuration

All inputs can be provided via a YAML config file, CLI flags, or environment variables. CLI flags override the config file.

### Config file (`blastcontain-verify.yaml`)

```yaml
agent_id: my-agent
environment: prod
search_path: ./src
skills_dir: ./skills
api_spec: ./openapi.yaml
mcp_config: ./mcp-servers.json
model_dir: /models/
context_file: ./context.txt
output: ./audit/packet.json
report: ./reports/latest.md
blastcontain_url: http://blastcontain-server:8080
cisco_api_key: ""
egress_probe_target: "8.8.8.8:53"  # override for air-gapped or firewalled environments
skip_checks: ["CRED-02", "LOCAL-01"]  # checks to record as SKIP instead of FAIL
api_live_probe: false                  # API-01 live OPTIONS probe — opt-in
sarif: ./reports/scan.sarif            # SARIF 2.1.0 output path
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--agent-id` | required | Agent identifier |
| `--config / -c` | `blastcontain-verify.yaml` | Path to config file |
| `--env` | `staging` | `dev` \| `uat` \| `staging` \| `prod` \| `local_developer_workstation` |
| `--search-path` | `.` | Root path walked for source, secret, code, and TLS scanning |
| `--skills-dir` | `--search-path` | Skill code directory for SKILL-01 and SKILL-02. Defaults to `--search-path`. |
| `--api-spec` | None | OpenAPI 3.0 JSON or YAML spec. Required for API-01 and API-02. |
| `--mcp-config` | None | MCP server config JSON. Required for MCP-01, MCP-02, MCP-03. |
| `--model-dir` | `/models/` | Model weights directory. Required for ENV-03 and SUP-01. |
| `--context-file` | None | Session context text file for PII scanning (MEM-01). |
| `--output` | None | Write signed JSON Audit Packet to this path. |
| `--report` | None | Write Markdown compliance report to this path. |
| `--blastcontain-url` | `$BLASTCONTAIN_URL` | BlastContain server base URL. Omit for local mode. |
| `--dry-run` | `False` | Skip server POST even when `--blastcontain-url` is set. |
| `--acknowledge-risk` | `False` | Exit 0 even on CRITICAL. Findings still reported at full severity. |
| `--max-tier` | `0` | Highest TrustTier in delegation chain (0–3). Drives blast radius multiplier. |
| `--egress-probe-target` | `8.8.8.8:53` | `host:port` used by ENV-02 (TCP) and NET-01 (UDP) probes. Override with an internal resolver when 8.8.8.8 is unreachable from the scan environment. |
| `--skip-checks` | None | Comma-separated check IDs to suppress, e.g. `--skip-checks CRED-02,LOCAL-01`. The check still runs (its result may feed composites like MEM-05) but its findings/passes are recorded as SKIP with reason `User-requested skip (--skip-checks)`. |
| `--api-live-probe` | `False` | When set, API-01 performs a live HTTP `OPTIONS` probe to each spec server URL to confirm destructive endpoints are reachable. **OFF by default** — see Decisions for rationale. |
| `--sarif` | None | Write SARIF 2.1.0 output to this path. Consumed by GitHub Code Scanning, GitLab Security Dashboard, and most IDE security extensions. |
| `--require-signing` | `False` | Exit 3 *before scanning* unless a real signing key is configured (`BLASTCONTAIN_SIGNING_KEY_PATH` / `_PEM`, or a non-default `BLASTCONTAIN_SIGNING_KEY`). Stops CI from emitting an advisory (default-HMAC-key) packet. See §7.4. |

### Environment variables

| Variable | Purpose |
|---|---|
| `BLASTCONTAIN_URL` | Server base URL. Overridden by `--blastcontain-url`. |
| `BLASTCONTAIN_SIGNING_KEY_PATH` | Path to a PEM-encoded Ed25519 private key. **Preferred** — produces independently verifiable signatures. |
| `BLASTCONTAIN_SIGNING_KEY_PEM` | PEM contents directly (as an env-injected string). Used when a file path is impractical (e.g. Kubernetes Secret). |
| `BLASTCONTAIN_SIGNING_KEY` | HMAC key — fallback when no Ed25519 source is set. Defaults to `local-verify-default` with a stderr warning on every run. |
| `BLASTCONTAIN_SIGNING_KEY_ID` | Key identifier written into the `signature.key_id` field. Defaults to `local`. Set to a KMS ARN or Vault path in production. |
| `CISCO_AIDEFENSE_API_KEY` | Enables `PROMPT_DEFENSE` analyzer in Cisco MCP Scanner. |

**Signing key priority:** `BLASTCONTAIN_SIGNING_KEY_PATH` > `BLASTCONTAIN_SIGNING_KEY_PEM` > `BLASTCONTAIN_SIGNING_KEY` (HMAC fallback). When the `cryptography` package is not installed, Ed25519 sources silently fall back to HMAC with a stderr warning.

---

## 4. Inputs

### 4.1 Skills Directory (`--skills-dir`)

Defaults to `--search-path` when not explicitly provided. Both SKILL-01 and SKILL-02 are SKIP-ped when the resolved directory is empty or does not exist.

SKILL-01 (pattern matching) always runs when skills files are present. SKILL-02 (Cisco scanner) additionally requires `cisco-ai-skill-scanner` to be installed.

### 4.2 API Specification (`--api-spec`)

Provide an OpenAPI 3.0 JSON or YAML file. Both API-01 and API-02 are SKIP-ped when `--api-spec` is not provided.

```yaml
servers:
  - url: https://api.internal.company.com/v2
paths:
  /customers/{id}:
    delete:
      summary: Delete customer
      security:
        - bearerAuth: []
```

### 4.3 MCP Server Configuration (`--mcp-config`)

Claude-style `mcpServers` JSON. MCP-01, MCP-02, and MCP-03 are all SKIP-ped when not provided.

```json
{
  "mcpServers": {
    "filesystem": {
      "url": "http://localhost:3001"
    },
    "browser": {
      "command": ["python", "browser_mcp.py"]
    }
  }
}
```

Each server would be scanned via the appropriate async `cisco-ai-mcp-scanner` method when `cisco_mcp` augmentation is active. **MCP-01 is currently dormant:** `cisco-ai-mcp-scanner` is no longer packaged (see §2 and §10), so `cisco_mcp` is always inactive and MCP-01 SKIPs until the scanner is re-added under a Charter.

**Analyzer selection:**

| Analyzer | Needs API key | Used in Verify |
|---|---|---|
| `API` | No | Always |
| `YARA` | No | Always |
| `READINESS` | No | Always |
| `PROMPT_DEFENSE` | Cisco key | If `CISCO_AIDEFENSE_API_KEY` set |
| `LLM` | LLM provider key | Excluded — breaks offline guarantee |
| `VIRUSTOTAL` | VT key | Excluded — out of scope |

---

## 5. Check Inventory

### Overview

| Group | Checks | Skip condition |
|---|---|---|
| Environment | ENV-01, ENV-02, ENV-03 | ENV-03 skips when no model dir found |
| Filesystem | DISK-01, DISK-02 | DISK-01 only fires for workstation environments |
| Credentials | CRED-01, CRED-02, CRED-03 | Always run |
| Process | PRIV-01, CAP-01 | Always run |
| Network | NET-01, NET-02 | Always run |
| Persistence | PERM-01 | Always run |
| Memory | MEM-01, MEM-03, MEM-05 | MEM-01 skips without `--context-file`; MEM-03 skips without vector DB env vars; MEM-05 skips unless MEM-01 and ENV-02 both fire |
| Skills | SKILL-01, SKILL-02 | Skip when skills directory empty or missing |
| APIs | API-01, API-02 | Skip without `--api-spec` |
| MCP Servers | MCP-01, MCP-02, MCP-03 | Skip without `--mcp-config` |
| Code | CODE-01 | Always run |
| Supply Chain | SUP-01 | Skips when model dir not found |
| Transport | TLS-01 | Always run |
| Local | LOCAL-01 | Skips when no workstation indicators detected |

---

### 5.1 Environment

#### ENV-01 — Kernel Isolation Missing

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-SYS-02 — Missing Sandbox Isolation |
| **What it checks** | Linux only. First checks `dmesg` output for `gVisor` or `runsc` strings — if found, PASS. Otherwise reads `/proc/sys/kernel/osrelease` and fails if the value contains a known host kernel signature: `ubuntu`, `fedora`, `debian`, `arch`, `centos`, `rhel`, `amazon`, `generic`. Non-Linux platforms: SKIP immediately. |
| **Skip condition** | Non-Linux platform, or `osrelease` is unreadable |
| **Pass condition** | gVisor detected in `dmesg`, or `osrelease` contains none of the host kernel signatures |
| **How to fix** | Deploy inside gVisor (`--runtime=runsc`) or Firecracker microVM. |

---

#### ENV-02 — Network Egress Unrestricted

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-NET-05 — Unrestricted Network Egress |
| **What it checks** | TCP connect probe to the `--egress-probe-target` host:port (default `8.8.8.8:53`) with 3-second timeout. If connection succeeds, default-deny egress policy is absent. |
| **Pass condition** | TCP connect times out or is refused |
| **How to fix** | `--network none` (Docker/Podman). Kubernetes: default-deny egress NetworkPolicy. Use `--egress-probe-target 10.0.0.1:53` if the default probe address is unreachable in your environment. |

---

#### ENV-03 — Model Weight Directory Writable

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-SYS-03 — Mutable Model Artefacts |
| **What it checks** | Attempts to write `.blastcontain_canary.tmp` to `model_dir`. Cleans up on success. |
| **Skip condition** | `model_dir` does not exist |
| **Pass condition** | Write raises `PermissionError` |
| **How to fix** | Mount model volume read-only: `-v /models:/models:ro`. |

---

### 5.2 Filesystem

#### DISK-01 — Filesystem Writable (Workstation)

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-SYS-01 — Insecure Runtime Configuration |
| **What it checks** | Write probe to `~/.blastcontain_root_canary.tmp`. Only runs when `environment` contains `workstation` or `local`. |
| **Pass condition** | Write raises `PermissionError` |

---

#### DISK-02 — Container Root Filesystem Writable

| | |
|---|---|
| **Severity** | MEDIUM |
| **MIT** | MIT-SYS-01 — Insecure Runtime Configuration |
| **What it checks** | Write probe to `/tmp/.blastcontain_disk_canary.tmp`. Runs when environment is not a workstation. |
| **Pass condition** | Write raises `PermissionError` |
| **How to fix** | `--read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m` |

---

### 5.3 Credentials

#### CRED-01 — Hardcoded Secrets on Disk

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-ID-01 — Hardcoded Credentials |
| **What it checks** | Walks `search_path`. Scans files matching these extensions: `.yaml .yml .json .conf .config .cfg .ini .toml .properties .xml .sh .bash .zsh .tf .tfvars`. Also scans these filenames regardless of extension: `.env .env.local .env.production .env.staging .env.development credentials .credentials secrets .netrc .pgpass`. Matches key names from `SECRET_ENV_NAMES` (30+ known credential names) with values longer than 4 characters. Skips directories: `.git __pycache__ node_modules .venv venv env .tox dist build .eggs`. Honours `.blastcontainignore` at `search_path` root. Reports up to 10 hits. |
| **Pass condition** | No secret key-value patterns found |

---

#### CRED-02 — Live Credentials in Process Environment

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-ID-02 — Credentials in Process Environment |
| **What it checks** | Scans `os.environ` for keys in `SECRET_ENV_NAMES` OR values starting with known token prefixes: `ghp_ ghs_ gho_ ghr_` (GitHub), `sk-ant-` (Anthropic), `sk-` (OpenAI), `xoxb- xoxp- xoxa-` (Slack), `AKIA ASIA` (AWS), `AIza` (Google), `hf_` (HuggingFace). |
| **Pass condition** | No matching keys or prefix-matched values in process environment |

---

#### CRED-03 — Wildcard API Capability

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-ID-03 — Overpermissioned API Scope |
| **What it checks** | Walks `search_path` for `.json .yaml .yml .toml` files. Searches for wildcard patterns: `/\*`, `"*"`, `'*'`, `: *\b`. Skips same dirs as CRED-01. |
| **Pass condition** | No wildcard patterns found in any scanned config file |

---

### 5.4 Process

#### PRIV-01 — Elevated Process Privilege

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-SYS-04 — Elevated Process Privilege |
| **What it checks** | Linux/macOS: `os.getuid() == 0`. Windows: `ctypes.windll.shell32.IsUserAnAdmin()`. |
| **Pass condition** | Not running as root / administrator |

---

#### CAP-01 — Dangerous Linux Capabilities

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-SYS-05 — Dangerous Linux Capabilities |
| **What it checks** | Reads `/proc/self/status` `CapEff` field. Tests bitmask for: `CAP_SYS_ADMIN` (21), `CAP_NET_ADMIN` (12), `CAP_SYS_PTRACE` (19), `CAP_SETUID` (7), `CAP_SETGID` (6), `CAP_SYS_MODULE` (16), `CAP_SYS_RAWIO` (3), `CAP_DAC_OVERRIDE` (1), `CAP_NET_RAW` (13). Non-Linux: PASS. |
| **Pass condition** | `CapEff` bitmask contains none of the flagged bits |
| **How to fix** | `--cap-drop ALL` |

---

### 5.5 Network

#### NET-01 — DNS Exfiltration Channel Open

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-NET-01 — DNS Exfiltration Channel |
| **What it checks** | Sends a minimal UDP DNS A-record query for `google.com` to the `--egress-probe-target` host:port (default `8.8.8.8:53`) with a 3-second timeout. If a response is received, UDP DNS egress is open. |
| **Pass condition** | Query times out or raises `OSError` |
| **How to fix** | Block UDP/53 egress. `--network none` blocks both TCP and UDP. Use `--egress-probe-target 10.0.0.1:53` to probe an internal resolver instead. |

---

#### NET-02 — External Network Listeners Detected

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-NET-02 — External Network Exposure |
| **What it checks** | Linux: parses `/proc/net/tcp` and `/proc/net/tcp6` for LISTEN state (state `0A`) sockets bound to `0.0.0.0` or `::`. macOS/Windows: parses `netstat -an` output. |
| **Pass condition** | No LISTEN sockets on external interfaces |

---

### 5.6 Persistence

#### PERM-01 — Persistence Location Write Access

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-SYS-06 — Persistence Location Accessible |
| **What it checks** | Write-probes startup locations by platform. Linux: `~/.bashrc ~/.bash_profile ~/.profile /etc/cron.d /etc/crontab /etc/rc.local`. macOS: `~/Library/LaunchAgents ~/.zshrc ~/.bash_profile`. Windows: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`. Paths computed at import time from `constants.PERSISTENCE_PATHS`. |
| **Pass condition** | All probed paths either do not exist or raise `PermissionError` |

---

### 5.7 Memory

#### MEM-01 — Unmasked PII in Session Context

| | |
|---|---|
| **Severity** | MEDIUM |
| **MIT** | MIT-DATA-07 — PII in Agent Context |
| **What it checks** | Reads `--context-file`. **Presidio** (if active): `AnalyzerEngine` with `en_core_web_lg` model for `CREDIT_CARD`, `US_SSN`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `IBAN_CODE`, `PERSON`, `LOCATION`. **Fallback regex**: runs when Presidio is unavailable **or** returns no matches (e.g. its network/cache-dependent recognisers degrade in the offline hardened container) — email, phone, SSN, credit card patterns. **AGT** `PromptDefenseEvaluator` (if active): runs after Presidio. |
| **Skip condition** | `--context-file` not provided |
| **Pass condition** | No PII detected by any active scanner |
| **How to fix** | Apply Presidio Anonymizer at context ingestion time before passing data to the agent. |

---

#### MEM-03 — Memory Store Lacks Tenant Namespace Isolation

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-DATA-09 — Missing Tenant Namespace Isolation |
| **What it checks** | Scans environment variables for vector DB indicators: `PINECONE_API_KEY PINECONE_ENVIRONMENT QDRANT_URL QDRANT_HOST WEAVIATE_URL WEAVIATE_HOST CHROMA_HOST CHROMADB_HOST REDIS_URL PGVECTOR_URL`. When detected, checks that a namespace/collection value is not in the generic set: `default prod production shared global vectors main common data`. |
| **Skip condition** | None of the vector DB environment variables are set |
| **Pass condition** | No vector DB detected, or namespace is tenant-specific |

---

#### MEM-05 — Viable PII Exfiltration Path

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-DATA-11 — Viable PII Exfiltration Path |
| **What it checks** | Composite finding. Only fires when MEM-01 detected PII **AND** ENV-02 confirmed egress is open. Orchestrated in `scanner.py` via `env02_fired` flag passed to `memory.run()`. |
| **Skip condition** | Either MEM-01 did not fire or ENV-02 did not fire |
| **Pass condition** | Either no PII, or egress blocked |

---

### 5.8 Skills

#### SKILL-01 — Exfiltration-Capable Tool in Skill Spec

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-TOOL-04 — Exfiltration-Capable Tool Present |
| **What it checks** | Walks `skills_dir` for `.json .yaml .yml` files. Matches tool names and descriptions against exfiltration patterns defined in `constants.EXFIL_SKILL_PATTERNS`: `http_post post_request send_email email exec execute shell upload_file upload s3_put put_object data_export export send_message webhook notify publish`. |
| **Skip condition** | Skills directory empty or does not exist |
| **Pass condition** | No tool names or descriptions match exfiltration patterns |

---

#### SKILL-02 — Cisco AI Skill Scanner Findings

| | |
|---|---|
| **Severity** | Mapped from the Cisco Report's highest non-zero severity count |
| **MIT** | MIT-TOOL-03 — Skill Security Finding |
| **What it checks** | Runs `SkillScanner().scan_directory(skills_dir, recursive=True)`, which discovers and scans every Claude Agent Skill (a directory containing a `SKILL.md` manifest plus any bundled scripts) under the path and aggregates per-skill results into one `Report`. Reports findings not caught by SKILL-01. |
| **Skip condition** | Skills directory not provided, `cisco-ai-skill-scanner` not installed, the scanner raises, or the path contains no Claude-format skills (`report.total_skills_scanned == 0`) |
| **Pass condition** | `report` has zero critical/high/medium counts (only LOW/INFO notes, or no findings) |

**Severity mapping** (driven by the Report's per-severity counts):

| Report counts | BlastContain severity | Effect |
|---|---|---|
| `critical_count > 0` | CRITICAL | QUARANTINED |
| `high_count > 0` | HIGH | REJECTED |
| `medium_count > 0` | MEDIUM | REJECTED |
| only `low_count` / `info_count` | — | Note in report only (PASS) |
| no findings | — | PASS |

---

### 5.9 APIs

#### API-01 — Destructive API Permissions

| | |
|---|---|
| **Severity** | HIGH (or CRITICAL when `--api-live-probe` confirms reachability) |
| **MIT** | MIT-TOOL-05 — Destructive API Permission |
| **What it checks** | Parses OpenAPI 3.0 spec for `DELETE`, `PUT`, `PATCH` endpoints and `POST` paths whose `operationId`, `summary`, **or path** contains destructive keywords (`delete remove purge destroy drop truncate wipe reset flush erase`). When `--api-live-probe` is set, additionally sends `OPTIONS` to each spec server URL to confirm reachability — confirmed endpoints escalate to CRITICAL. |
| **Live probe** | OFF by default. When enabled with `--api-live-probe`, sends one HTTP `OPTIONS` request per server URL per destructive path. Off-by-default rationale: preserves the offline guarantee, and a malicious OpenAPI spec could otherwise direct scanner-originated HTTP at attacker-controlled URLs. |
| **Skip condition** | `--api-spec` not provided |
| **Pass condition** | No destructive endpoints found, or all require authentication |

---

#### API-02 — Unauthenticated Endpoints in Spec

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-ID-04 — Unauthenticated Destructive Endpoint |
| **What it checks** | Scans OpenAPI spec for paths without a `security` declaration. |
| **Skip condition** | `--api-spec` not provided |
| **Pass condition** | All endpoints have at least one security requirement |

---

### 5.10 MCP Servers

All three MCP checks are SKIP-ped when `--mcp-config` is not provided.

#### MCP-01 — Unapproved MCP Tool

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-TOOL-01 — Unapproved MCP Tool |
| **What it checks** | Parses `mcpServers` from config. For each server, calls `cisco-ai-mcp-scanner` (`scan_remote_server_tools` for URL servers, `scan_stdio_server_tools` for command servers). Flags tools not in `permitted_tools` allowlist (Phase 3: fetched from Charter; currently passed as `None`). |

---

#### MCP-02 — MCP Server Without Authentication

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-ID-05 — MCP Server Without Authentication |
| **What it checks** | Inspects each `mcpServers` entry. Flags servers with `http://` URLs (plaintext) or no auth configuration. |

---

#### MCP-03 — Dangerous MCP Tool Combination

| | |
|---|---|
| **Severity** | CRITICAL |
| **MIT** | MIT-TOOL-02 — Dangerous MCP Tool Combination |
| **What it checks** | Categorises every tool across all MCP servers into capability classes, then checks for dangerous pairs defined in `constants.MCP_DANGEROUS_PAIRS`. |

**Capability categories** (defined in `constants.MCP_CAPABILITY_CATEGORIES`):

| Category | Example tools |
|---|---|
| **Read** | `read_file`, `query_db`, `list_dir`, `get_object`, `search`, `fetch`, `download` |
| **Execute** | `exec`, `shell_exec`, `run_command`, `eval`, `subprocess`, `bash`, `terminal` |
| **Send** | `http_post`, `send_email`, `upload_file`, `s3_put`, `webhook`, `publish`, `data_export` |
| **Write** | `write_file`, `delete_file`, `insert_db`, `update_db`, `create_file`, `truncate` |
| **Credential** | `get_secret`, `read_env`, `aws_credentials`, `oauth_token`, `fetch_token` |

**Dangerous pairs** (defined in `constants.MCP_DANGEROUS_PAIRS`):

| Combination | Attack pattern | Severity |
|---|---|---|
| Read + Send | Read data, exfiltrate to attacker endpoint | CRITICAL |
| Credential + Send | Steal and exfiltrate credentials | CRITICAL |
| Execute + Write | Execute payload, write persistence | CRITICAL |
| Read + Execute | Read attacker file, execute it | CRITICAL |
| Write + Execute | Drop binary, execute it | CRITICAL |
| Read + Write | Read then corrupt or overwrite data | HIGH |

---

### 5.11 Code

#### CODE-01 — Dangerous Code Execution Patterns

| | |
|---|---|
| **Severity** | CRITICAL (eval/exec/os.system/shell=True), HIGH (pickle/yaml.load/marshal/jsonpickle) |
| **MIT** | MIT-CODE-01 — Dangerous Code Execution Pattern |
| **What it checks** | Walks `search_path` for source files with extensions: `.py .js .ts .mjs .cjs .rb .go .java .cs .php .sh .bash`. Skips directories in `CODE_SKIP_DIRS`: `.git __pycache__ node_modules .venv venv env .tox dist build .eggs tests test __tests__ spec blastcontain_verify blastcontain_drill blastcontain_discovery`. Also honours `.blastcontainignore` at `search_path` root. CRITICAL patterns: `eval(` `exec(` `os.system(` `subprocess(...shell=True` `__import__(`. HIGH patterns: `pickle.load(` `yaml.load(` `marshal.load(` `jsonpickle.decode(`. Reports up to 10 hits total. |
| **Pass condition** | No patterns found in any scanned source file |

---

### 5.12 Supply Chain

#### SUP-01 — Model Weights Without Attestation

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-TOOL-06 — Unattested Model Weights |
| **What it checks** | Walks `model_dir` for weight files: `.bin .pt .pth .ckpt .pkl .gguf .ggml .safetensors .onnx .pb .h5 .keras .tflite .mlmodel`. For each, checks that an attestation file exists alongside it: `.sha256 .sig .asc .minisig`, or `manifest.json checksums.txt sha256sums` in the same directory. |
| **Skip condition** | `model_dir` does not exist |
| **Pass condition** | No weight files present, or all weight files have accompanying attestation |

---

### 5.13 Transport

#### TLS-01 — Plaintext HTTP Endpoints Detected

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-DATA-02 — Plaintext Communication Channel |
| **What it checks** | Walks `search_path` for files with extensions: `.yaml .yml .json .toml .env .conf .config .ini .xml .tf .py .js .ts`. Skips `CODE_SKIP_DIRS` (same as CODE-01). Skips `audit.json` (scanner's own output). Honours `.blastcontainignore` at `search_path` root. Searches for `http://` URLs excluding localhost (`127.`, `0.0.0.0`, `localhost`). Reports up to 15 unique hits. |
| **Pass condition** | No non-localhost `http://` URLs found |
| **How to fix** | Replace all `http://` with `https://` for inter-service communication. |

---

### 5.14 Local

#### LOCAL-01 — Agent Running on Developer Workstation

| | |
|---|---|
| **Severity** | HIGH |
| **MIT** | MIT-SYS-07 — Non-Containerised Agent Deployment |
| **What it checks** | Three detection classes: (1) home path containing `/Users/` (macOS) or `\Users\` (Windows); (2) IDE env vars: `VSCODE_PID`, `VSCODE_IPC_HOOK`, `CURSOR_TRACE_ID`, `JETBRAINS_IDE`, `TERM_PROGRAM=vscode`; (3) IDE config dirs: `~/.vscode`, `~/.cursor`, `~/.idea`, `%APPDATA%\Code`, `%APPDATA%\Cursor`, `%APPDATA%\JetBrains`. |
| **Skip condition** | No workstation indicators detected |
| **Pass condition** | Never passes once indicators are detected — always results in finding |

---

## 6. Report Format

Generated with `--report ./report.md`.

### CLI output

Every check is listed on its own line with result:

```
  Running checks...

  ❌  API-01      SKIP      --api-spec not provided
  ✅  CAP-01      PASS
  ❌  CODE-01     CRITICAL  Dangerous Code Execution Pattern Detected
  ✅  CRED-01     PASS
  ...

  Status:     🔴 QUARANTINED
  Critical:   1
  High:       0
  Medium:     0
  Passed:     13
  Skipped:    14
  Blast rad:  1.0x (TIER_0)
```

### Markdown report structure

```
# BlastContain Verify — Agent Compliance Report

Agent | Environment | Status | Scan ID | Blast Radius Factor

## Summary
Group-level table: CRITICAL / HIGH / MEDIUM / PASS / SKIP counts

## Augmentation
Active and inactive augmentation packages

## 🔴 Critical Findings
Per-finding: check ID, severity, MIT mapping, what happened, how to fix, evidence, references

## 🟠 High Findings
## 🟡 Medium Findings

## ✅ Passed Checks
Table: check ID | group

## ⏭ Skipped Checks
Table: check ID | reason

## MIT AI Risk Repository Coverage
Table: check ID | MIT domain | causal ID | label
```

### SARIF 2.1.0 output

Generated with `--sarif ./scan.sarif`. Conforms to [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) and validates against `https://json.schemastore.org/sarif-2.1.0.json`.

Consumed natively by:

| Consumer | Integration |
|---|---|
| GitHub Code Scanning | `github/codeql-action/upload-sarif@v3` |
| GitLab Security Dashboard | `artifacts.reports.sast` |
| Azure DevOps | SARIF Viewer extension |
| VS Code | SARIF Viewer extension |
| Sonar / Snyk / Semgrep ecosystems | direct upload |

**Mapping conventions:**

| BlastContain | SARIF |
|---|---|
| `Severity.CRITICAL` | `level: error`, `security-severity: 9.5` |
| `Severity.HIGH` | `level: error`, `security-severity: 7.5` |
| `Severity.MEDIUM` | `level: warning`, `security-severity: 5.0` |
| `Severity.LOW` | `level: note`, `security-severity: 2.0` |
| `Severity.INFO` | `level: note`, `security-severity: 0.0` |
| Each unique `check_id` | One `reportingDescriptor` (rule) |
| Each finding | One `result` referencing its rule by index |
| MIT mapping | `properties.mit-domain`, `mit-causal-id`, `mit-label` + tag `mit-risk:<id>` |
| Scan invocation | One `invocations[]` entry with agent_id, environment, status, passed/skipped lists |

Because most findings are environmental rather than line-of-code, each result uses a `logicalLocations` entry (`blastcontain.checks.<CHECK-ID>`) instead of a physical file location. GitHub Code Scanning still displays these correctly under the "Tool" view.

---

## 7. Signed Audit Packet

Generated with `--output ./audit.json`. Two signing algorithms are supported.

### 7.1 Canonical encoding

The payload is canonicalised before signing using:

```
json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

This produces a deterministic byte string that any verifier in any language can reproduce. Different whitespace, key order, or escape conventions would yield different signatures.

### 7.2 Algorithm selection (priority order)

1. **Ed25519 (preferred)** — asymmetric. The public key is embedded in the packet so anyone can verify without sharing secrets. Used when `BLASTCONTAIN_SIGNING_KEY_PATH` or `BLASTCONTAIN_SIGNING_KEY_PEM` is set and the `cryptography` package is installed.
2. **SHA-256 HMAC (fallback)** — symmetric. The verifier needs the same `BLASTCONTAIN_SIGNING_KEY` to verify. Used when no Ed25519 source is configured. Default key `local-verify-default` produces a stderr warning every run.

### 7.3 Ed25519 packet (schema_version 1.1)

```json
{
  "schema_version": "1.1",
  "packet": {
    "agent_id": "my-agent",
    "environment": "prod",
    "scan_id": "<uuid>",
    "scanned_at": "<iso8601>",
    "status": "APPROVED",
    "blast_radius_factor": 1.0,
    "max_tier": 0,
    "findings": [],
    "passed": ["CAP-01", "CRED-01"],
    "skipped": [{"check_id": "MCP-01", "reason": "--mcp-config not provided"}],
    "augmentation": {
      "presidio": true,
      "cisco_mcp": false,
      "cisco_skill": false,
      "agt": true
    },
    "generator": "blastcontain-verify",
    "generator_version": "0.4.0"
  },
  "signature": {
    "algorithm": "ed25519",
    "key_id": "kms://arn:aws:kms:us-east-1:.../key/abc",
    "public_key": "<base64 of 32-byte raw public key>",
    "public_key_encoding": "base64-raw",
    "value": "<base64 of 64-byte Ed25519 signature>",
    "value_encoding": "base64",
    "canonical": "json-sort-keys-tight",
    "signed_at": "<iso8601>"
  }
}
```

### 7.4 HMAC fallback packet

```json
{
  "schema_version": "1.1",
  "packet": { "...": "..." },
  "signature": {
    "algorithm": "sha256-hmac",
    "key_id": "local",
    "value": "<64-char hex>",
    "value_encoding": "hex",
    "canonical": "json-sort-keys-tight",
    "signed_at": "<iso8601>",
    "advisory": true
  }
}
```

`advisory: true` is an **additive** signature-block field present only when the
packet was signed with the built-in default key (`local-verify-default`). The
default key is public knowledge, so such a signature proves *integrity*
(payload unmodified since signing) but **not provenance** — anyone can produce
one. Downstream tooling should treat advisory packets as unattested; CI
pipelines that must never emit one can pass `--require-signing`, which exits 3
before scanning when no real key source is configured. Packets signed with
Ed25519 or a real HMAC key omit the field.

### 7.5 Generating a key

```
openssl genpkey -algorithm Ed25519 -out blastcontain-signing.key
chmod 600 blastcontain-signing.key
export BLASTCONTAIN_SIGNING_KEY_PATH=/etc/blastcontain/signing.key
export BLASTCONTAIN_SIGNING_KEY_ID=ed25519-prod-2026-q2
```

### 7.6 Verifying a packet

`reporter.verify_audit_packet(packet)` returns `bool`. For Ed25519 packets it uses the embedded `public_key`; for HMAC packets it requires `BLASTCONTAIN_SIGNING_KEY` to be set in the environment.

In server mode the packet is `POST`-ed to `/v1/agents/{agent_id}/findings`.

---

## 8. Module Structure

### Package layout

```
blastcontain_verify/
├── __init__.py
├── cli.py              # Click entry point. Builds config, calls run_scan(), writes reports.
├── config.py           # Loads blastcontain-verify.yaml, merges CLI flags → VerifyConfig dataclass.
├── models.py           # InfraFinding, ScanResult, ScanStatus, Severity — zero external deps.
├── constants.py        # MIT_RISK_MAP, SECRET_ENV_NAMES, SECRET_VALUE_PREFIXES,
│                       # SECRET_SCAN_EXTENSIONS, SECRET_SCAN_FILENAMES, SECRET_SKIP_DIRS,
│                       # CODE_CRITICAL_PATTERNS, CODE_HIGH_PATTERNS, CODE_SCAN_EXTENSIONS,
│                       # CODE_SKIP_DIRS, MCP_CAPABILITY_CATEGORIES, MCP_DANGEROUS_PAIRS,
│                       # EXFIL_SKILL_PATTERNS, MODEL_EXTENSIONS, ATTESTATION_EXTENSIONS,
│                       # ATTESTATION_FILENAMES, GENERIC_NAMESPACES, VECTOR_DB_ENV_INDICATORS,
│                       # DANGEROUS_CAPS, PERSISTENCE_PATHS, TIER_BLAST_WEIGHTS
├── augmentation.py     # All try/except imports. Exports:
│                       #   PRESIDIO_AVAILABLE  — presidio-analyzer + en_core_web_lg loaded
│                       #   CISCO_MCP_AVAILABLE — cisco-ai-mcp-scanner (mcpscanner)
│                       #   CISCO_SKILL_AVAILABLE — cisco-ai-skill-scanner (skill_scanner)
│                       #   AGT_AVAILABLE       — agent-governance-toolkit (agent_compliance)
│                       #   AUGMENTATION_FLAGS  — dict of all four flags
│                       #   presidio_analyze()  — safe wrapper, returns [] if unavailable
│                       #   get_mcp_scanner()   — returns Scanner instance or None
│                       #   get_skill_scanner() — returns SkillScanner instance or None
├── ignore.py           # .blastcontainignore support.
│                       #   load_ignore_patterns(search_path) — reads .blastcontainignore,
│                       #     strips comments, returns list of patterns
│                       #   is_ignored(rel_path, patterns) — gitignore-style matching:
│                       #     filename globs (fnmatch), path prefixes, ** globs
│                       # Used by CRED-01, CODE-01, TLS-01.
├── scanner.py          # Thin orchestrator (~100 lines). Runs checks in dependency order.
│                       # ENV-02 result (env02_fired) passed to memory.run().
│                       # egress_probe_target passed to both environment.run() and network.run().
├── reporter.py         # write_markdown_report(), write_audit_packet(),
│                       # verify_audit_packet(), post_to_ledger()
│                       # Ed25519 + HMAC signing with canonical JSON encoding.
├── reporter_sarif.py   # write_sarif() — SARIF 2.1.0 output for GitHub Code
│                       # Scanning, GitLab Security, IDE extensions.
│                       # Maps Severity → SARIF level + security-severity,
│                       # MIT mapping → properties + tags, dedupes rules by
│                       # check_id, embeds invocation metadata.
└── checks/
    ├── __init__.py
    ├── environment.py  # ENV-01, ENV-02, ENV-03
    ├── filesystem.py   # DISK-01, DISK-02
    ├── credentials.py  # CRED-01, CRED-02, CRED-03
    ├── process.py      # PRIV-01, CAP-01
    ├── network.py      # NET-01, NET-02
    ├── persistence.py  # PERM-01
    ├── memory.py       # MEM-01, MEM-03, MEM-05
    ├── skills.py       # SKILL-01, SKILL-02
    ├── api.py          # API-01, API-02
    ├── mcp.py          # MCP-01, MCP-02, MCP-03 (async internally, wrapped in asyncio.run())
    ├── code.py         # CODE-01
    ├── supply_chain.py # SUP-01
    ├── tls.py          # TLS-01
    └── local.py        # LOCAL-01
```

### Test layout

```
tests/
├── unit/
│   ├── checks/
│   │   ├── test_credentials.py   # CRED-01, CRED-02, CRED-03
│   │   ├── test_code.py          # CODE-01
│   │   ├── test_environment.py   # ENV-01, ENV-02, ENV-03
│   │   └── ...
│   └── test_reporter.py          # Markdown report and audit packet
└── integration/                  # Podman-based, exercise the built container
    ├── conftest.py               # run_verify() fixture + compose lifecycle
    ├── compose.yml               # mcp-server + api-server test services
    ├── fixtures/                 # clean/ and dirty/ scan targets
    ├── test_pass.py              # PASS / SKIP expectations
    └── test_fail.py              # FAIL expectations
```

---

## 9. Augmentation APIs

### `presidio-analyzer` + `presidio-anonymizer`

Package: `pip install "blastcontain-verify[pii]"`  
Import: `from presidio_analyzer import AnalyzerEngine`  
Requires: spaCy model `en_core_web_lg` (baked into container image).

```python
from blastcontain_verify.augmentation import presidio_analyze

results = presidio_analyze(text, language="en")
# returns list of RecognizerResult with entity_type, score, start, end
```

### `cisco-ai-mcp-scanner` (not currently packaged)

> **Dormant.** The `[mcp]` extra has been removed — `cisco-ai-mcp-scanner` exact-pins a CVE-bearing `litellm==1.83.7` that conflicts with the now-clean `[skill]` extra, and its only consumer (MCP-01) is dormant without a Charter. The API below is retained for when it is re-added. See §10.

Package: *(removed — was `pip install "blastcontain-verify[mcp]"`)*  
Import module: `mcpscanner`

```python
from mcpscanner import Config, Scanner
from mcpscanner.core.models import AnalyzerEnum
import asyncio, os

config = Config(api_key=os.environ.get("CISCO_AIDEFENSE_API_KEY", ""))
scanner = Scanner(config)

analyzers = [AnalyzerEnum.API, AnalyzerEnum.YARA, AnalyzerEnum.READINESS]
if os.environ.get("CISCO_AIDEFENSE_API_KEY"):
    analyzers.append(AnalyzerEnum.PROMPT_DEFENSE)

# HTTP MCP server
result = asyncio.run(
    scanner.scan_remote_server_tools(url="http://localhost:3001", analyzers=analyzers)
)

# stdio MCP server
result = asyncio.run(
    scanner.scan_stdio_server_tools(command=["python", "server.py"], analyzers=analyzers)
)
```

`LLM` and `VIRUSTOTAL` analyzers are excluded — they break the offline guarantee and are out of scope for a pre-deployment scan.

### `cisco-ai-skill-scanner`

Package: `pip install "blastcontain-verify[skill]"`  
Import module: `skill_scanner`

```python
from skill_scanner import SkillScanner

scanner = SkillScanner()
# scan_directory discovers every Claude Agent Skill (a dir with SKILL.md) under the path
report = scanner.scan_directory("/path/to/skills/dir", recursive=True)

report.total_skills_scanned  # int — 0 means no Claude-format skills were found
report.critical_count        # int
report.high_count            # int
report.medium_count          # int
report.scan_results          # list[ScanResult]; each has .skill_name, .findings, .is_safe, .max_severity
```

`scan_skill(skill_directory)` scans a *single* skill directory and raises `SkillLoadError` when no `SKILL.md` is present. Verify uses `scan_directory` so a path containing many skills — or none — is handled uniformly.

### `agent-governance-toolkit`

Package: `pip install "blastcontain-verify[agt]"`  
Import module: `agent_compliance`

```python
from agent_compliance import PromptDefenseEvaluator, SupplyChainGuard

evaluator = PromptDefenseEvaluator(config)
report = evaluator.evaluate(text)

guard = SupplyChainGuard(config)
result = guard.verify(model_path)
```

---

## 10. Decisions

| Item | Decision |
|---|---|
| Check skip vs always-run | Checks requiring external inputs (api-spec, mcp-config, context-file, model-dir, skills-dir) emit SKIP when inputs not provided. All other checks always run. SKIP does not affect compliance status. |
| `cisco_sdk` removed | There is no `cisco_aidefense` PyPI package. The two Cisco packages are `cisco-ai-mcp-scanner` (import: `mcpscanner`) and `cisco-ai-skill-scanner` (import: `skill_scanner`). AUGMENTATION_FLAGS still has four keys — `presidio`, `cisco_mcp`, `cisco_skill`, `agt` — but only `cisco-ai-skill-scanner` is packaged (opt-in `[skill]`/`[cisco]`); `cisco-ai-mcp-scanner` is unpackaged (CVE-bearing `litellm` pin; MCP-01 dormant), so `cisco_mcp` is always `false`. |
| AGT import name | `agent-governance-toolkit` exposes the module `agent_compliance`, not `agent_governance_toolkit`. Exports used: `PromptDefenseEvaluator`, `SupplyChainGuard`. |
| CODE-01 self-detection | `CODE_SKIP_DIRS` excludes `blastcontain_verify`, `blastcontain_drill`, `blastcontain_discovery` (scanner's own packages) and `tests`, `test`, `__tests__`, `spec` (test fixtures intentionally contain dangerous patterns). |
| TLS-01 scope | Walks `search_path` for config and source files — not limited to spec files. Skips `audit.json` to avoid self-referential hits from previous scan output. |
| Presidio model | Container image downloads `en_core_web_lg` at build time. Fallback to `en_core_web_sm` if lg not available. Without a loaded model, `AnalyzerEngine()` raises and `PRESIDIO_AVAILABLE` is `False`. |
| MEM-05 orchestration | `env02_fired` flag is computed from ENV-02 findings in `scanner.py` and passed to `memory.run()`. MEM-05 is a derived finding, not an independent probe. |
| Async MCP scanning | `asyncio.run()` per server call in `checks/mcp.py`. Safe for a CLI tool with no existing event loop. If Verify is ever embedded in an async server, revisit. |
| LLM analyzer excluded | Breaks the offline guarantee. Adds latency, cost, and an external dependency. Semantic MCP analysis belongs in BlastContain Drill. |
| Charter integration | Not yet implemented. When Charter exists, `permitted_tools` will be fetched from `/v1/agents/{id}/charter`. Currently passed as `None` — all tools treated as unreviewed. |
| Egress probe target | `--egress-probe-target` (default `8.8.8.8:53`) controls the destination for both ENV-02 (TCP) and NET-01 (UDP) probes. A single flag covers both checks. Override with an internal resolver (`10.0.0.1:53`) when 8.8.8.8 is blocked by the environment's own egress policy but the scan must still check for unrestricted egress to other destinations. |
| Signing key default | Default HMAC key changed from a per-scan UUID to the static string `local-verify-default`. Per-scan UUIDs made it impossible for a verifier to re-derive or validate the signature without the original key. The static default is still insecure — production deployments must set `BLASTCONTAIN_SIGNING_KEY` to a real secret and `BLASTCONTAIN_SIGNING_KEY_ID` to a resolvable key reference. |
| `.blastcontainignore` | CRED-01, CODE-01, and TLS-01 all load `ignore.py::load_ignore_patterns()` before walking `search_path`. Create `.blastcontainignore` at the repo root to suppress known-safe paths (vendored fixtures, generated certs, test data). Syntax: `#` comments, directory suffixes (`vendor/`), filename globs (`*.pem`), path globs (`tests/**`). |
| ENV-01 non-Linux | `check_env01_kernel_isolation()` returns SKIP immediately on any non-Linux platform. The previous behaviour (probe gVisor on non-Linux) was never implemented. Kernel isolation checks that read `/proc` are Linux-specific; the SKIP on other platforms is intentional. |
| Charter schema | The Charter schema lives in `blastcontain_core.charter` (the OSS `blastcontain-core` package) and exposes `CharterSchema`, `DelegationRules` (max chain depth, allowed tiers, parent approval), `HitlConfig` (HITL triggers, timeout, escalation contact), `RemediationProof` (finding type, evidence URI, verifier), and `EnvironmentConstraints`. `CharterSchema` includes `signing_key_id`, `delegation_rules`, `hitl_config`, `remediation_proofs`, and `transparency_label` (EU AI Act Art. 15). These fields are schema-only — enforcement lives in the closed-source platform. |
| Per-group try/except | Each check group is wrapped in `try/except BaseException` in `scanner.py`. A raised exception produces a synthetic `SCAN-<GROUP>` finding (`blastcontain.scanner.check_group_failed`, severity HIGH) and the orchestrator continues. Overall status flips to ERROR. Rationale: prior behaviour crashed the whole scan with no audit packet — operators had no record of what had run before the failure. |
| `--skip-checks` semantics | The flag does **not** prevent the check from executing. It runs, its result is collected, then any finding/pass matching the skip list is rewritten to SKIP with reason `User-requested skip (--skip-checks)`. Necessary because some check results feed composite checks (e.g. ENV-02 → MEM-05); skipping the probe would silently break the composite. Use sparingly — every skip is a signed exception in the audit trail. |
| API-01 live probe opt-in | `--api-live-probe` (default OFF) gates the `httpx.options()` call. Off-by-default rationale: (1) preserves the offline guarantee the rest of the tool advertises; (2) a malicious OpenAPI spec listing `http://attacker.com/...` as a server URL would otherwise coax the scanner into sending outbound HTTP — a confused-deputy primitive. Severity escalates HIGH → CRITICAL when the live probe confirms reachability. |
| API-01 destructive POST detection | Destructive keyword match was extended from operationId + summary to also include the path itself (`/admin/destroy` now fires even when operationId is bland). Keyword list extended with `wipe`, `reset`, `flush`, `erase`. |
| SARIF output | New `--sarif <path>` flag and `reporter_sarif.py` module. SARIF 2.1.0 with `security-severity` properties so GitHub Code Scanning ranks findings correctly. Each unique check_id becomes one `reportingDescriptor` (rule); each finding becomes one `result` referencing its rule by index. MIT mapping serialised as properties and tags so downstream tooling can filter by MIT-AI risk taxonomy. Findings use `logicalLocations` (not physical) since most are environmental. |
| Ed25519 signing | `reporter.py` now selects between Ed25519 (preferred) and SHA-256 HMAC (fallback). Ed25519 keys come from `BLASTCONTAIN_SIGNING_KEY_PATH` (PEM file) or `BLASTCONTAIN_SIGNING_KEY_PEM` (PEM string). The 32-byte raw public key is embedded in `signature.public_key` (base64) so verification needs nothing else. `cryptography` is now a core dependency. HMAC remains for offline development and CI artifact integrity, but the default key `local-verify-default` now emits a stderr warning on every use. Schema bumped to 1.1 (additive — algorithm field tells the verifier which path to take). |
| Canonical signing encoding | Changed from `sort_keys=True` only to `sort_keys=True, separators=(",", ":")`. The old format left default Python json whitespace, producing different bytes than what a Go/Rust/JS verifier would generate from the same logical payload. Tightening the separators makes the canonical form trivially reproducible in any language. The `signature.canonical` field records `"json-sort-keys-tight"` so verifiers know exactly which encoding to apply. |
| Lazy Presidio init | `augmentation.py` no longer calls `AnalyzerEngine()` at import time. Initialisation is deferred to the first call to `presidio_analyze()`. Scans that never run MEM-01 (the common case for CI smoke tests) save the multi-second spaCy model load. `PRESIDIO_AVAILABLE` is optimistic before first use (`True` if the package imports) and flips to `False` if the lazy init fails. |
| NET-02 false-pass bug fixed | `checks/network.py` previously had `if "0.0.0.0:" in line or ":::":` — the literal `":::"` is truthy so every LISTEN line passed the gate. The regex on the next line was the real filter, so detection worked, but the intended fast-path was a no-op. One-line fix to `or ":::" in line`. No spec-level behaviour change, but worth recording as the kind of bug that hides in plain sight. |
| Hardened-container offline hardening | The optional `[full]` deps (presidio→`tldextract`, `litellm` via the Cisco scanners, Hugging Face/`onnxruntime`) attempt `~/.cache` writes and remote fetches on first use. In the hardened run profile (`--read-only`, no writable `$HOME` at `/home/verify`, `--network none`) those raise (`OSError: Read-only file system` / `socket.gaierror`); with some unpinned version combinations the failure escapes a check and aborts the scan (traceback, no audit packet). `blastcontain_verify/__init__.py::_harden_runtime_env()` — mirrored by `Containerfile` `ENV` — runs *before any optional dep is imported* and redirects every cache to the writable `/tmp` tmpfs (`TLDEXTRACT_CACHE`, `XDG_CACHE_HOME`, `HF_HOME`, `MPLCONFIGDIR`; base is writability-probed) and forces offline (`HF_HUB_OFFLINE`, `TRANSFORMERS_OFFLINE`, `LITELLM_LOCAL_MODEL_COST_MAP`). `$HOME` is deliberately **not** redirected — a writable home would make PERM-01 (persistence-locations-writable) fire on the hardened container. The four optional-dep import guards in `augmentation.py` also catch `SystemExit` (not just `Exception`), so an ML library that aborts its own import downgrades the augmentation instead of killing Verify. |
| MEM-01 offline regex fallback | When Presidio is installed but its analysis returns nothing — e.g. its network/cache-dependent recognisers degrade offline — `_scan_text_for_pii` falls back to the built-in regex patterns. Previously the regex ran only when Presidio was entirely absent, so a present-but-degraded Presidio could PASS PII-laden context (a false negative). The finding's scanner label records which path produced the hit. |
| Malformed config degrades | A present-but-unparseable `--config` file (invalid YAML, or a path that resolves to a directory) logs a stderr warning and falls back to defaults instead of raising out of `load_config()` → `main()`. Matches how `api.py` / `skills.py` treat unparseable inputs and keeps Verify fail-safe. A *non-existent* `--config` path was already a no-op via the `.exists()` guard. |
| Typed check contract + plugin registry | Since 0.4.0 the scanner↔checks boundary is typed: `contract.py` (a leaf module) defines `CheckContext` (typed config + `ScanState.fired`), `CheckGroupResult`, and the `CheckGroup` protocol; `registry.py` holds the ordered `BUILTIN_GROUPS` inventory (order is load-bearing — environment before memory for MEM-05) and discovers third-party groups via the `blastcontain_verify.checks` entry point. Replaces the `**kwargs` dispatch (a renamed config field is now a type/attribute error at the read site, not a silently-defaulted kwarg). Plugin failures degrade to `SCAN-PLUGIN` findings and check-ID collisions are rejected — a broken plugin can never kill the scan or shadow a built-in check. Plugins are trusted in-process code; the hardened container is the blast-radius control (docs/plugins.md). |
| Advisory signatures are machine-readable | Packets signed with the default HMAC key carry `signature.advisory: true` (additive field, no schema bump — three packages share the 1.1 writer) so the Ledger and CI gates can refuse unattested packets mechanically instead of parsing a stderr warning. `--require-signing` fails fast (exit 3, before scanning) when no real key is configured. See §7.4. |
| Augmentation acceptance checklist | Every candidate augmentation must pass the checklist in [CONTRIBUTING.md](../CONTRIBUTING.md#adding-an-augmentation) (pip-audit-clean tree, no exact-pins of shared libs, offline/read-only import safety, tree-size budget, graceful degradation) before landing in any extra. CVE-bearing packages that clear the other gates go in opt-in extras only, with accepted CVEs documented in SECURITY.md; the Security workflow audits opt-in trees weekly, non-gating. Codifies the litellm/tldextract lessons. |
| Doc-drift tests | `tests/unit/test_doc_consistency.py` pins prose facts to code: spec.md §5 sections ↔ `constants.ALL_CHECK_IDS` (the canonical inventory), the README check/category counts, pyproject ↔ `__version__` ↔ CHANGELOG, and the generator_version regression. Duplicated facts rot silently otherwise — the hardcoded generator_version bug was this failure mode. |
| Cisco scanners are opt-in | The Cisco AI Skill Scanner (`cisco-ai-skill-scanner` → SKILL-02) is **excluded from `[full]`** and installed via `[skill]` / `[cisco]`. It was CVE-bearing until 2.0.12 raised its `litellm` floor to `>=1.84` (current `litellm` relaxed its `aiohttp`/`python-dotenv` pins to ranges), so this tree is **now CVE-clean** — both `[full]` and the opt-in are clean (the former gated by `pip-audit`, the latter watched weekly, both in the Security workflow). The Cisco **MCP** scanner (`cisco-ai-mcp-scanner` → the MCP-01 backend) is **deliberately not packaged**: every release still exact-pins the vulnerable `litellm==1.83.7` (CVE-2026-34993/-47265/-40217/-28684), it now conflicts with `skill>=2.0.12`'s `litellm`, and MCP-01 is dormant (SKIPs without a Charter). Re-add when upstream relaxes the pin AND Charter activates MCP-01. See SECURITY.md. |
| Output write is fail-safe | The `--report` / `--output` / `--sarif` writes in `cli.py` are wrapped: a non-writable output path prints a clear, actionable error and exits 3 (ERROR) rather than raising an uncaught `OSError`. This was the actual cause of the red "Verify hardened-container integration" job — the non-root scan UID (10001) could not write the host-mounted `/reports` volume in CI's rootless podman, so every output-writing scan crashed on the audit-packet write (after the scan and signing had succeeded). The integration conftest now `chmod`s the mounted `/reports` (and writable `/models`) so uid 10001 can write them. |
