# blastcontain-core

Shared types, Charter schema, audit-packet signing, and SARIF emit for the BlastContain tool family.

```
pip install blastcontain-core
```

## What's in here

| Module | Purpose |
|---|---|
| `blastcontain_core.models` | `Severity`, `ScanStatus`, `InfraFinding`, `ScanResult` |
| `blastcontain_core.constants` | `MIT_RISK_MAP` — finding_type → MIT AI Risk taxonomy |
| `blastcontain_core.charter` | `CharterSchema`, `DelegationRules`, `HitlConfig`, `RemediationProof` |
| `blastcontain_core.signing` | Ed25519 + HMAC packet signing and verification |
| `blastcontain_core.sarif` | SARIF 2.1.0 output for GitHub/GitLab/IDEs |
| `blastcontain_core.ignore` | `.blastcontainignore` pattern loader |

## Who uses this

- [`blastcontain-verify`](https://github.com/blastcontain/verify) — pre-deployment compliance scanner
- [`blastcontain-drill`](https://github.com/blastcontain/drill) — runtime probing / red-team simulation
- [`blastcontain-discovery`](https://github.com/blastcontain/discovery) — shadow AI / agent discovery
- BlastContain Platform (closed source)

> **Pre-release note:** these repositories and PyPI packages are not published yet. The links above are the planned canonical locations and will 404 until the first public release; `blastcontain-verify` ships first, with `drill` and `discovery` following once they have implementations. Until then, build from the local `blastcontain-oss/` working tree.

If you're writing a third-party BlastContain tool, depend on this package and your output will be wire-compatible with the rest of the ecosystem.

## Signing an audit packet

```python
from blastcontain_core.signing import sign_packet, verify_packet
from datetime import datetime, timezone

payload = {"agent_id": "my-agent", "environment": "prod", "findings": []}
signed_at = datetime.now(timezone.utc).isoformat()

signature = sign_packet(payload, signed_at=signed_at)
packet = {"schema_version": "1.1", "packet": payload, "signature": signature}

# Anyone with the public key (or the HMAC secret) can verify
assert verify_packet(packet) is True
```

Signing key sources, in priority order:

1. `BLASTCONTAIN_SIGNING_KEY_PATH` — path to a PEM-encoded Ed25519 private key (preferred)
2. `BLASTCONTAIN_SIGNING_KEY_PEM` — PEM contents as a string
3. `BLASTCONTAIN_SIGNING_KEY` — arbitrary HMAC secret (fallback)
4. None — defaults to `local-verify-default` HMAC with a stderr warning

Generate a real Ed25519 key:

```
openssl genpkey -algorithm Ed25519 -out blastcontain-signing.key
chmod 600 blastcontain-signing.key
export BLASTCONTAIN_SIGNING_KEY_PATH=$PWD/blastcontain-signing.key
export BLASTCONTAIN_SIGNING_KEY_ID=ed25519-prod-2026-q2
```

## Writing a local Charter

```yaml
# charter.yaml
agent_id: my-agent
environment: prod
version: "1.0"
trust_tier: 1
permitted_tools:
  - search_knowledge_base
  - get_ticket_status
delegation_rules:
  max_chain_depth: 0
  require_parent_approval: true
hitl_config:
  required_for: ["destructive_apis"]
  timeout_sec: 600
```

```python
from blastcontain_core.charter import load_charter

charter = load_charter("./charter.yaml")
assert "search_knowledge_base" in charter.permitted_tools
```

## SARIF output

```python
from blastcontain_core.sarif import write_sarif
write_sarif(scan_result, "scan.sarif", tool_name="my-tool", tool_version="1.0.0")
```

Upload to GitHub Code Scanning in your CI:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: scan.sarif
```

## License

[Apache 2.0](LICENSE) — see also [NOTICE](NOTICE) for third-party attribution.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off (`git commit -s`).
