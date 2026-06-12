# blastcontain-verify

Pre-deployment compliance scanner for AI agents. 27 security checks across 14 categories. Outputs Markdown reports, signed JSON audit packets, and SARIF for GitHub Code Scanning.

```
pip install blastcontain-verify
blastcontain-verify --agent-id my-agent --env prod --search-path ./src
```

## What it checks

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

## Container (recommended)

The official image bundles `[full]` with the spaCy `en_core_web_lg` model. The image copies both `verify/` and the sibling `core/`, so the build context is the `blastcontain-oss` repo root:

```
# from the blastcontain-oss/ root
podman build -t blastcontain-verify:latest -f verify/Containerfile .
podman run --rm \
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
```

Usage guide & examples: [docs/usage.md](docs/usage.md) · Full spec: [docs/spec.md](docs/spec.md) · Design notes: [docs/architecture.md](docs/architecture.md)

## GitHub Code Scanning integration

`--agent-id` should be a **stable logical identifier for the agent being scanned** (e.g. `support-bot-prod`), not the repository slug — it is the key your audit packets are attributed to over time, so it must stay constant even if the repo is renamed or forked. Store it as a repository or org Actions **variable** (Settings → Secrets and variables → Actions → Variables):

```yaml
# .github/workflows/security.yml
- name: BlastContain Verify
  run: blastcontain-verify --sarif scan.sarif --agent-id "${{ vars.AGENT_ID }}"
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
```

## Augmentation

Verify works standalone; optional packages unlock deeper checks. **Secure by
default:** `[full]` and the official image are CVE-clean. The Cisco AI Defense
scanners are **opt-in** — they transitively pull `litellm`, which carries known
CVEs with no upstream fix (see [SECURITY.md](SECURITY.md)).

| Extra | Adds | Clean |
|---|---|---|
| `[pii]`   | Microsoft Presidio NER for MEM-01 | ✅ |
| `[agt]`   | Agent Governance Toolkit | ✅ |
| `[full]`  | `[pii]` + `[agt]` — the default supported set | ✅ |
| `[mcp]`   | Cisco AI MCP Scanner (MCP-01 backend) | ⚠️ pulls litellm |
| `[skill]` | Cisco AI Skill Scanner (SKILL-02) | ⚠️ pulls litellm |
| `[cisco]` | `[mcp]` + `[skill]` | ⚠️ pulls litellm |

```
pip install "blastcontain-verify[full]"          # CVE-clean: Presidio + AGT
pip install "blastcontain-verify[full,cisco]"     # + SKILL-02 & Cisco MCP (opt-in; see SECURITY.md)
```

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

Ed25519 packets carry their public key inline — verification needs nothing else. HMAC packets require `BLASTCONTAIN_SIGNING_KEY` in the environment.

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off (`git commit -s`).
