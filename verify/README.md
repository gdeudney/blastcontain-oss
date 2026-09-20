# blastcontain-verify

Pre-deployment technical security scanner for AI agents and MCP servers. The agent profile has 27 security checks across 14 categories. Outputs Markdown reports, signed JSON audit packets, and SARIF for GitHub Code Scanning.

```
pip install blastcontain-verify
blastcontain-verify --agent-id my-agent --env prod --search-path ./src
```

## What a scan establishes

Run Verify **inside the environment being tested**, with the agent's effective
identity, filesystem access, credentials and network restrictions. `--env` labels
the deployment context; it does not enter or recreate that environment.

A separate hardened scanner container can inspect mounted source and configuration,
but its runtime checks describe **the scanner container**, not the agent's host or
production deployment. A PASS is evidence for an individual probe, not proof of
complete containment or organizational compliance. Review SKIPs and suppressed
checks alongside findings.

Today `--mcp-config` checks MCP configuration and declared tool combinations;
it does not certify a remote server's runtime or authorization. MCP-01 currently
SKIPs without a Charter allowlist. Use `--target-type mcp --target-id NAME` for the new passive MCP assessment
with a local policy; see [MCP usage](docs/mcp.md).
See the [technical checklist](../docs/technical-security-checklist.md).

## MCP server assessment

```bash
blastcontain-verify --target-type mcp --target-id billing-mcp \
  --mcp-config verify/examples/mcp/server.json \
  --policy verify/examples/mcp/policy.json --output mcp-audit.json
```

Run this example from the repository root. Configuration-only assessment is the
MCP default; add `--scan-scope runtime` inside the actual server environment for
local runtime checks. No MCP commands or tools are executed. Missing inventory or
policy produces incomplete coverage, not approval. See [the MCP guide](docs/mcp.md)
for evidence limits across all ten planned security areas.

## What the agent profile checks

| Group | Checks |
|---|---|
| Environment | kernel isolation, egress restriction, model weight mutability |
| Filesystem | workstation rootfs, container rootfs |
| Credentials | secrets on disk, secrets in process env, wildcard API capability |
| Process | running as root, dangerous Linux capabilities |
| Network | DNS exfiltration channel, external listeners |
| Persistence | writable startup/cron paths |
| Memory | unmasked PII in context, vector store tenant isolation, viable PII exfil path |
| Skills | exfiltration-capable tools, Cisco AI Skill Scanner findings |
| APIs | destructive endpoints, unauthenticated endpoints |
| MCP | unapproved tools, missing auth, dangerous tool combinations |
| Code | dangerous execution patterns (eval/exec/pickle/yaml.load) |
| Supply chain | unattested model weights |
| Transport | plaintext HTTP endpoints |
| Local | developer workstation indicators |

Every check is mapped to the [MIT AI Risk Repository](https://airisk.mit.edu/) taxonomy.

> **Two checks are conditional:** SKILL-02 (Cisco AI Skill Scanner) needs the opt-in `[cisco]` extra — see [Augmentation](#augmentation); MCP-01 (unapproved tools) is not yet implemented and currently SKIPs. The rest run out of the box.

## Isolated source/configuration scan

The official image bundles `[full]` with the spaCy `en_core_web_lg` model. The image copies both `verify/` and the sibling `core/`, so the build context is the `blastcontain-oss` repo root:

```
# from the blastcontain-oss/ root
mkdir -p reports
podman build -t blastcontain-verify:latest -f verify/Containerfile .
podman run --rm --userns=keep-id:uid=10001,gid=10001 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --network none --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -v "$PWD:/scan:ro,z" -v "$PWD/reports:/reports:rw,z" \
  blastcontain-verify:latest \
  --agent-id my-agent --env prod \
  --search-path /scan --report /reports/report.md \
  --output /reports/audit.json --sarif /reports/scan.sarif \
  --acknowledge-risk
```

## CLI flags (most common)

```
--agent-id              Agent identifier (required)
--env                   dev | uat | staging | prod | local_developer_workstation
--search-path           Root walked for source/secret/code/TLS scanning
--skills-dir            Skill code directory (SKILL-01/02)
--api-spec              OpenAPI 3.0 YAML/JSON path (API-01/02)
--mcp-config            MCP server config JSON (MCP-01/02/03)
--model-dir             Model weights directory (ENV-03, SUP-01)
--context-file          Session context text for PII scanning (MEM-01)
--output PATH           Write signed JSON audit packet
--report PATH           Write Markdown report
--sarif PATH            Write SARIF 2.1.0 for GitHub Code Scanning
--skip-checks IDs       Comma-separated check IDs to suppress
--api-live-probe        Enable live OPTIONS probe in API-01 (off by default)
--egress-probe-target   host:port for ENV-02/NET-01 probes
--acknowledge-risk      Exit 0 even on CRITICAL
--require-signing       Exit 3 unless a real signing key is set (no advisory packet)
```

Usage guide & examples: [docs/usage.md](docs/usage.md) · Full spec: [docs/spec.md](docs/spec.md) · Design notes: [docs/architecture.md](docs/architecture.md) · Custom checks: [docs/plugins.md](docs/plugins.md)

## GitHub Code Scanning integration

`--agent-id` should be a **stable logical identifier for the agent being scanned** (e.g. `support-bot-prod`), not the repository slug — it is the key your audit packets are attributed to over time, so it must stay constant even if the repo is renamed or forked. Store it as a repository or org Actions **variable** (Settings → Secrets and variables → Actions → Variables):

```yaml
# .github/workflows/security.yml
- name: BlastContain Verify
  run: blastcontain-verify --sarif scan.sarif --agent-id "${{ vars.AGENT_ID }}"
- uses: github/codeql-action/upload-sarif@v4
  if: always() && hashFiles('scan.sarif') != ''
  with:
    sarif_file: scan.sarif
```

## Augmentation

Verify works standalone; optional packages unlock deeper checks. Dependency audits are point-in-time checks. The pinned sets and resolved opt-in
extras passed the [2026-09-19 Security run](https://github.com/gdeudney/blastcontain-oss/actions/runs/35465109852).
Unpinned installs can resolve differently; audit the environment you deploy.

| Extra | Adds | Audited 2026-09-19 |
|---|---|---|
| `[pii]`   | Microsoft Presidio NER for MEM-01 | ✅ |
| `[agt]`   | Agent Governance Toolkit | ✅ |
| `[full]`  | `[pii]` + `[agt]` — the default supported set | ✅ |
| `[skill]` / `[cisco]` | Cisco AI Skill Scanner (SKILL-02) | ✅ |

```
pip install "blastcontain-verify[full]"          # default: Presidio + AGT
pip install "blastcontain-verify[full,cisco]"     # + SKILL-02 (Cisco skill scanner)
```

> The Cisco **MCP** scanner (the MCP-01 backend) is not currently packaged — it
> was excluded following dependency findings; MCP-01 is dormant without a Charter. See
> [SECURITY.md](SECURITY.md).

Without the relevant extra, the dependent check SKIPs with a hint on how to enable it.

## Suppressing findings — `.blastcontainignore`

Drop a `.blastcontainignore` at the root of `--search-path`:

```
tests/fixtures/      # entire directory tree
*.mock.json          # filename glob
**/snapshots/**      # path glob
```

Honoured by CRED-01, CODE-01, TLS-01.

## Verifying audit packets

```python
import json
from blastcontain_core.signing import verify_packet

packet = json.load(open("audit.json"))
assert verify_packet(packet)
```

Ed25519 packets carry their public key inline, sufficient for checking signature
consistency. To trust the signer, compare that key with a separately trusted key;
an embedded key alone does not establish identity. HMAC packets require `BLASTCONTAIN_SIGNING_KEY` in the environment.

**Be clear about what the default signature means:** with no key configured,
packets are signed with a built-in key and marked `"advisory": true` — that
detects accidental changes, **not malicious tampering or attestation** (anyone
can modify and re-sign one). Attestation requires an Ed25519 key you manage. CI pipelines
that must never emit an advisory packet should pass `--require-signing`, which
exits 3 before scanning if no real key is configured.

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off (`git commit -s`).
