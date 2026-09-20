# Assess an MCP server with Verify

MCP assessment is the first step of the agreed sequence: **Verify assessment →
control validation → Drill → governance with Charter**, for both agents and tools.
This release inspects configuration and optionally the invoking runtime. It does
not connect to a server, discover its live tools, launch its configured command,
invoke tools or validate live authentication. Installed check plugins do not run
in this profile.

For the separate opt-in synthetic control-validation adapter, see
[control validation](control-validation.md). The passive profile below remains
the default; live requests require both explicit flags.

## Quickstart

From the repository root, after installing `./core` and `./verify` into your Python
environment:

```bash
blastcontain-verify --target-type mcp --target-id billing-mcp \
  --mcp-config verify/examples/mcp/server.json \
  --policy verify/examples/mcp/policy.json \
  --output mcp-audit.json --report mcp-report.md --sarif mcp-scan.sarif
```

These examples refer to a nonexistent demonstration endpoint; no connection is
made. The example should exit 0 with complete coverage of the **configuration
profile**, not a claim that the service is secure. Existing `--agent-id` commands
retain the agent profile and packet schema.

Use a stable deployment identifier in `--target-id`. With more than one server in
the input, select it explicitly using `--mcp-server billing`. Results and policy
comparison apply only to that server. Run separate assessments for other servers.

## Configuration and expected access

Accepted input is a JSON object containing `mcpServers` (or `mcp_servers`), mapping
server names to objects. Exactly one of `command` (stdio) and `url`/`baseUrl`
(HTTP) must be present on the selected server. `args` is a string list; `env` and
`headers` are string mappings. Files are limited to 2 MiB.

```json
{
  "mcpServers": {
    "billing": {
      "command": "python",
      "args": ["billing_server.py"],
      "env": {"API_TOKEN": "${MCP_TOKEN}"},
      "tools": [{"name": "get_invoice", "inputSchema": {"type": "object"}}]
    }
  }
}
```

`tools` is Verify's supplemental declared inventory: MCP launch configurations do
not normally contain the server's full tool list. Export or provide it separately
in this assessment file. Names and optional input-schema hashes are recorded;
descriptions, raw schemas, arguments, URLs and credential values are not copied
into the inventory. An explicit empty list declares no tools; omitting the list
means inventory is unavailable. This declaration is not live discovery.

The local policy is JSON with exactly these fields:

```json
{"target_id": "billing-mcp", "permitted_tools": ["get_invoice"]}
```

Names match exactly and are case-sensitive. Target/server/tool identifiers accept
1–128 letters, digits and `_ . : / -`; wildcard permissions are not supported.
The policy's target ID must match the assessment. No Charter connection is needed.
Missing policy still yields inventory and findings, but expected-access coverage
is incomplete and the scan exits 3.

The same options can be supplied in `blastcontain-verify.yaml`:

```yaml
target_type: mcp
target_id: billing-mcp
mcp_config: ./mcp.json
mcp_server: billing
policy: ./tool-policy.json
scan_scope: config
output: ./mcp-audit.json
```

CLI values override YAML. MCP targets use `--target-id`, not `--agent-id`.
MCP Ledger posting is rejected until the server supports target-aware ingestion;
use local artifacts. `--api-live-probe` is also rejected in this profile.

## Configuration checks

| Check | Evidence and limit |
|---|---|
| MCP-01 | Declared tools compared with a local allowlist; does not prove exposed tools or authorization |
| MCP-02 | Network TLS/auth configuration hints; stdio relies on local identity, not HTTP authentication |
| MCP-03 | Dangerous capability combinations inferred from names; actual tool behavior remains unvalidated |
| MCP-04 | Declared tool inventory present and parseable; does not confirm completeness against the server |
| MCP-05 | Inline secret-like environment values, auth credentials or URL credentials/query; values omitted from findings |
| MCP-06 | Known broad privileges in stdio launch arguments, such as privileged containers and runtime sockets; HTTP is not applicable |

PASS means that check found no issue within this limited evidence. In particular,
MCP-02 PASS never means tokens or access decisions were validated. Environment
references such as `${MCP_TOKEN}` are not expanded by the scanner. Unknown secret
formats and indirect launch scripts can evade these configuration heuristics.

## Inspect the actual runtime

Add `--scan-scope runtime` **only while running Verify with the MCP server's actual
execution identity, mounts, credentials and restrictions**, and set `--search-path`
to its source/configuration root. This adds existing process/capability, filesystem,
persistence, workstation, source/credential and plaintext-URL checks. Some checks
write and remove canary files. This is opt-in local runtime inspection, not a
remote-service scan. No outbound reachability probes run in this profile.

A separate hardened scanner container can review configuration, but its runtime
results do not describe the server. Verify does not impersonate a configured
command or remotely inspect a process. The report labels runtime attribution as
operator-supplied context. Do not use `--env` alone to claim runtime equivalence.

## Coverage across the ten feature areas

| Feature | Current evidence | Still requires later work |
|---|---|---|
| Capabilities and connections | Declared tools and name-based capability hints | Actual read/write/execute/contact access and adjacency graph |
| Runtime containment | Optional local observations and launch-argument hints | Complete deployment containment and network policy validation |
| Scoped authorization | Declared tool allowlist | Caller, tenant, record and field enforcement |
| Identity and credentials | Configuration credential hints | Token validation, delegation and downstream separation |
| Egress restrictions | Explicitly not assessed | Redirects, proxies, internal destinations and upload bypasses |
| Exact-action approval | Explicitly not assessed | Argument/recipient/record binding and expiry |
| Replay and cumulative limits | Explicitly not assessed | Retry, concurrency and delegated budget enforcement |
| Untrusted inputs and outputs | Explicitly not assessed | Poisoned metadata/results and privileged downstream effects |
| Dependencies and changes | Configuration and input-schema hashes | Dependency audit, version provenance and baseline comparison |
| Audit and independent stopping | Signed scanner evidence | Target trace reconstruction and independent revocation |

JSON, Markdown and SARIF include the same target, inventory and coverage metadata.
MCP audit packets use schema `1.2` with `target` instead of `agent_id`; agent packets
remain `1.1`. The signature covers target metadata and coverage as well as findings.
Signer trust requirements remain unchanged; see [usage](usage.md#67-production-signing--verifying-the-packet).

Required checks missing, malformed or suppressed make profile coverage incomplete
and status ERROR (exit 3). Applicable configuration checks are required; runtime
mode additionally requires its selected checks, excluding the filesystem check
for the other environment type and workstation detection when no indicators exist. Findings still appear when coverage is incomplete.
`--acknowledge-risk` retains the existing report-only exit override; inspect packet
status and coverage rather than treating its exit 0 as approval. Complete profile
coverage does not imply coverage of all ten security areas.
