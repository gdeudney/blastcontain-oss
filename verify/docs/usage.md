# BlastContain Verify — Usage Guide

Task-oriented, copy-pasteable examples for running `blastcontain-verify`.

- New here? Start with the [README](../README.md) for the overview.
- Need the precise definition of a check, flag, or output field? See [`spec.md`](spec.md).
- Want to know *why* it's built this way? See [`architecture.md`](architecture.md).

This guide is the **how-do-I** layer: the common scenarios, end to end.

## Contents

1. [Install](#1-install)
2. [Two ways to run (and when to use each)](#2-two-ways-to-run)
3. [Quickstart](#3-quickstart)
4. [Reading the output](#4-reading-the-output)
5. [Exit codes & gating CI](#5-exit-codes--gating-ci)
6. [Cookbook](#6-cookbook)
7. [Optional augmentation](#7-optional-augmentation)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Install

```bash
# Core scanner (pattern-based checks, no ML deps)
pip install blastcontain-verify

# With optional augmentation (see §7)
pip install "blastcontain-verify[full]"
```

Or use the hardened container image (bundles `[full]` + the spaCy model):

```bash
# build context is the blastcontain-oss repo ROOT (the image needs core/ too)
podman build -t blastcontain-verify:latest -f verify/Containerfile .
```

---

## 2. Two ways to run

| | `pip` install | Hardened container |
|---|---|---|
| **Use when** | Scanning **your own** repo in dev or CI | Scanning **untrusted / third-party** agent code |
| **Isolation** | Runs in your shell | Read-only rootfs, no network, dropped caps, non-root UID |
| **Setup** | `pip install` | `podman build` once |

Rule of thumb: **if you didn't write the code you're scanning, run it in the container.** The container is the same environment the checks are designed for (`--network none`, read-only fs), so results are deterministic.

---

## 3. Quickstart

Scan a local project with the pip install:

```bash
blastcontain-verify --agent-id my-agent --env prod --search-path ./src
```

The same scan, hardened, in the container:

```bash
mkdir -p reports
podman run --rm \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --network none --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "$PWD:/scan:ro,z" -v "$PWD/reports:/reports:rw,z" \
  blastcontain-verify:latest \
  --agent-id my-agent --env prod \
  --search-path /scan --output /reports/audit.json
```

> **Windows (Git Bash / MSYS2):** write the *container-side* paths with a leading double slash — `//scan`, `//reports/audit.json` — so MSYS doesn't rewrite them into Windows paths. The `-v` host paths stay normal.

---

## 4. Reading the output

Every run prints a per-check table and a summary to the console:

```
============================================================
  BlastContain Verify  |  Agent: my-agent  |  Env: prod
============================================================
  Augmentation active:   presidio, cisco_mcp, cisco_skill, agt

  Running checks...

  ❌  CRED-01     CRITICAL  Hardcoded Secrets Found in Source Files
  ✅  CRED-02     PASS
  ⏭   MEM-01      SKIP      No --context-file provided
  ...
  Status:     🔴 QUARANTINED
  Critical:   3   High: 3   Medium: 0   Passed: 9   Skipped: 12
```

Three optional machine-readable artifacts (write any combination):

| Flag | Output | Consumer |
|---|---|---|
| `--report PATH` | Markdown compliance report | humans, PR comments |
| `--output PATH` | Signed JSON **audit packet** | the audit trail / BlastContain Ledger |
| `--sarif PATH` | SARIF 2.1.0 | GitHub Code Scanning, GitLab, IDEs |

`⏭ SKIP` is meaningful: it means the check **could not run** (its input wasn't provided), *not* that it passed. Provide the matching `--flag` (see §6) to turn a SKIP into a real PASS/FAIL.

---

## 5. Exit codes & gating CI

| Code | Status | Meaning |
|---|---|---|
| `0` | APPROVED | no findings |
| `1` | REJECTED | HIGH or MEDIUM findings |
| `2` | QUARANTINED | at least one CRITICAL |
| `3` | ERROR | a check group crashed, **or an output file couldn't be written** |

Two ways to use this in CI:

```bash
# (a) Hard gate — fail the pipeline on any finding
blastcontain-verify --agent-id my-agent --env prod --search-path ./src

# (b) Report-only — never fail the build; surface findings via SARIF instead
blastcontain-verify --agent-id my-agent --env prod --search-path ./src \
  --sarif scan.sarif --acknowledge-risk     # forces exit 0
```

`--acknowledge-risk` forces exit `0` even on CRITICAL (findings are still reported at full severity in the report/packet/SARIF). It does **not** suppress a code-3 *write* error.

---

## 6. Cookbook

### 6.1 Scan a local agent repo (dev)

```bash
blastcontain-verify --agent-id support-bot --env dev \
  --search-path ./src --report report.md
```

### 6.2 Hardened scan of untrusted code, all outputs

```bash
mkdir -p reports && chmod 0777 reports      # writable by the container's scan UID — see §8
podman run --rm \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --network none --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "/path/to/agent:/scan:ro,z" -v "$PWD/reports:/reports:rw,z" \
  blastcontain-verify:latest \
  --agent-id third-party-agent --env prod \
  --search-path /scan \
  --report /reports/report.md \
  --output /reports/audit.json \
  --sarif  /reports/scan.sarif \
  --acknowledge-risk
```

### 6.3 GitHub Actions + Code Scanning

`--agent-id` should be a **stable logical name** for the agent (e.g. `support-bot-prod`), not the repo slug — it's the key your audit packets are attributed to over time. Store it as an Actions **variable**.

```yaml
# .github/workflows/security.yml
jobs:
  verify:
    runs-on: ubuntu-latest
    permissions: { security-events: write, contents: read }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install "blastcontain-verify[full]"
      - name: Scan
        run: |
          blastcontain-verify --agent-id "${{ vars.AGENT_ID }}" --env prod \
            --search-path . --sarif scan.sarif --acknowledge-risk
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: scan.sarif }
```

Drop `--acknowledge-risk` if you want findings to **fail** the job instead of only appearing in the Security tab.

### 6.4 Config-file-driven scan

Put a `blastcontain-verify.yaml` next to your project (CLI flags override it):

```yaml
agent_id: support-bot
environment: prod
search_path: ./src
skills_dir: ./skills
api_spec: ./openapi.yaml
mcp_config: ./mcp-servers.json
context_file: ./session-context.txt
output: ./audit/packet.json
report: ./reports/latest.md
skip_checks: ["CRED-02"]
```

```bash
blastcontain-verify --config blastcontain-verify.yaml
```

### 6.5 Scan specific inputs

Each input flag unlocks the checks that need it (otherwise they SKIP):

```bash
# PII in session/conversation context  -> MEM-01
blastcontain-verify --agent-id a --context-file ./context.txt

# MCP server config  -> MCP-02 (no auth), MCP-03 (dangerous tool combos)
blastcontain-verify --agent-id a --mcp-config ./mcp-servers.json

# OpenAPI spec  -> API-01 (destructive endpoints), API-02 (unauthenticated)
blastcontain-verify --agent-id a --api-spec ./openapi.yaml

# Claude-format skills dir  -> SKILL-01 (exfil tools), SKILL-02 (Cisco scanner)
blastcontain-verify --agent-id a --skills-dir ./skills

# Model weights dir  -> SUP-01 (unattested weights), ENV-03 (writable model dir)
blastcontain-verify --agent-id a --model-dir ./models
```

### 6.6 Network egress checks (ENV-02 / NET-01)

These check whether the agent's runtime can reach the outside world. Under the recommended `--network none`, egress is blocked, so **ENV-02 and NET-01 PASS** — that's the desired prod posture. To assert that a *less* restricted environment still blocks egress, run with network access and point the probe somewhere reachable:

```bash
# verify egress IS restricted in an environment that has a network
blastcontain-verify --agent-id a --env staging \
  --egress-probe-target 10.0.0.1:53      # an internal resolver you expect to be blocked
```

`--egress-probe-target host:port` (default `8.8.8.8:53`) is the destination for both the ENV-02 (TCP) and NET-01 (UDP) probes. Override it when `8.8.8.8` is itself blocked by policy but you still want to test reachability of other hosts.

### 6.7 Production signing & verifying the packet

By default the audit packet is HMAC-signed with a built-in key (advisory only, prints a warning). For a packet anyone can verify with just its embedded public key, sign with Ed25519:

```bash
# one-time: generate a key
openssl genpkey -algorithm ed25519 -out verify-signing.pem

BLASTCONTAIN_SIGNING_KEY_PATH=./verify-signing.pem \
BLASTCONTAIN_SIGNING_KEY_ID="kms://prod/verify-2026" \
blastcontain-verify --agent-id a --search-path ./src --output audit.json
```

Verify a packet later (Ed25519 packets need nothing but the file):

```python
import json
from blastcontain_core.signing import verify_packet
assert verify_packet(json.load(open("audit.json")))
```

### 6.8 Suppress known-safe paths and checks

`.blastcontainignore` at the root of `--search-path` (honoured by CRED-01, CODE-01, TLS-01):

```
tests/fixtures/      # whole tree
*.mock.json          # filename glob
**/snapshots/**      # path glob
```

`--skip-checks` records specific checks as SKIP (still runs them so composites like MEM-05 work; logs a signed exception in the packet):

```bash
blastcontain-verify --agent-id a --search-path ./src --skip-checks CRED-02,LOCAL-01
```

### 6.9 Post results to a BlastContain server (Ledger)

```bash
blastcontain-verify --agent-id a --search-path ./src \
  --blastcontain-url https://blastcontain.internal:8080
# add --dry-run to compute everything but skip the POST
```

---

## 7. Optional augmentation

Verify runs standalone; extras unlock deeper checks. Missing extras degrade gracefully (the dependent check falls back or SKIPs — it never crashes).

Every augmentation — default and opt-in — is **CVE-clean** (as of 2026-06).

| Extra | Unlocks | CVE-clean |
|---|---|---|
| `[pii]`   | Microsoft Presidio NER for MEM-01 (falls back to regex without it) | ✅ |
| `[agt]`   | Agent Governance Toolkit | ✅ |
| `[full]`  | `[pii]` + `[agt]` — the default set, shipped in the image | ✅ |
| `[skill]` / `[cisco]` | Cisco AI Skill Scanner (SKILL-02) | ✅ |

```bash
pip install "blastcontain-verify[full]"          # CVE-clean default
pip install "blastcontain-verify[full,cisco]"     # + SKILL-02 (Cisco skill scanner)
```

The startup banner prints which augmentations are active, and SKILL-02 SKIPs with an enable hint when the `[cisco]` extra is absent. The Cisco **MCP** scanner is not currently packaged (still CVE-bearing; MCP-01 is dormant without a Charter) — see [SECURITY.md](../SECURITY.md).

---

## 8. Troubleshooting

**`Error: could not write output file: ... Permission denied` (exit 3).**
The official image runs as the non-root `verify` user (UID 10001), so the host directory you mount at `/reports` must be writable by that UID. Make it writable before mounting:

```bash
chmod 0777 reports
# or, with podman, let it chown the volume to the container user:
-v "$PWD/reports:/reports:rw,z,U"
# or run the container as yourself (least-isolated):
--user "$(id -u):$(id -g)"
```

(Verify now reports this clearly and exits 3 instead of crashing — but you still need a writable output dir to get the packet.)

**`Error: unable to find network ...` / `exit code 125`.**
That's the container runtime failing before Verify starts — usually the image tag isn't built locally (podman tries to pull it) or a `--network` name doesn't exist. Build/tag the image and reference that exact tag.

**MEM-01 says "pattern matching (Presidio not installed)".**
You're on the core install. `pip install "blastcontain-verify[pii]"` (or use the container) for full NER. Offline, Presidio's network/cache-dependent recognisers degrade and Verify automatically falls back to the built-in regex patterns, so obvious PII (SSN, card, email) is still caught.

**A whole check group shows `SCAN-<GROUP>` CRITICAL/HIGH.**
That's the orchestrator's safety net: a check crashed, so it emitted a synthetic finding and kept going (overall status → ERROR). Re-run and check the `evidence` field for the exception; file an issue if it's a scanner bug.

**Network checks (ENV-02/NET-01) "didn't fire" when I expected them to.**
Under `--network none` they correctly PASS (no egress). They only FAIL when the scan environment actually *has* reachable egress to `--egress-probe-target`. See §6.6.

**Everything SKIPs.**
Most checks need an input. A bare `--search-path` scan covers code/secrets/TLS/process/filesystem; add `--context-file`, `--mcp-config`, `--api-spec`, `--skills-dir`, `--model-dir` to light up the rest (§6.5).
