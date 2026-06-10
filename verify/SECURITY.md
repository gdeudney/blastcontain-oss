# Security Policy

## Reporting a vulnerability

Email **security@blastcontain.io** with:

1. A description of the vulnerability
2. Steps to reproduce or a proof-of-concept
3. The affected version(s) of `blastcontain-verify`
4. Your name and how you'd like to be credited

**Please do not open public GitHub issues for security vulnerabilities.**

## What counts as a vulnerability

We treat the following as security-relevant:

- A check that can be tricked into a false PASS by a malicious scan target
- A check that exfiltrates data to attacker-controlled infrastructure (e.g. API-01 live probe pointed at attacker URL)
- A way to forge or replay a valid audit packet signature
- Privilege escalation via the verify container
- An issue in `cryptography`-backed signing logic that we vendor or wrap

We treat the following as bugs (open a public issue):

- False positives on legitimate code/config
- Missed detections of dangerous patterns where the pattern is documented in spec.md
- Performance issues

## Response timeline

| Day | Response |
|---|---|
| Within 2 business days | Acknowledgement |
| Within 7 days | Initial triage and severity assessment |
| Within 90 days | Fix released or detailed mitigation plan |
| At time of fix | CVE assignment if applicable, public advisory, credit |

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | yes |
| 0.2.x | security fixes only until 2026-12-31 |
| < 0.2 | not supported |

## Audit packet signing — what the default actually proves

Without a configured key, packets are HMAC-signed with the built-in
`local-verify-default` key and carry `signature.advisory: true`. Because that
key is public knowledge, an advisory signature proves **integrity only** — the
payload hasn't changed since signing — and provides **no attestation of who
produced it**. Treat advisory packets as unattested. For attestation, configure
an Ed25519 key (`BLASTCONTAIN_SIGNING_KEY_PATH`) and manage it like any other
production secret; use `--require-signing` in pipelines that must never emit an
advisory packet. Key management is deliberately out of scope for the OSS tool —
the signature is only as trustworthy as your key handling.

## Optional Cisco scanners — known dependency CVEs

`blastcontain-verify` is **secure-by-default**: the standard install
(`pip install blastcontain-verify` or `[full]`) and the official container image
carry **no known-vulnerable dependencies** — verified in CI by `pip-audit`
against [`constraints-full.txt`](constraints-full.txt).

The two Cisco AI Defense scanners are **opt-in only** (`[cisco]` / `[mcp]` /
`[skill]`) because they transitively require `litellm`, which exact-pins
vulnerable `aiohttp` and `python-dotenv` with **no fixed combination available
upstream**:

| Dependency | CVE | Pulled via |
|---|---|---|
| `aiohttp` 3.13.x | CVE-2026-34993, CVE-2026-47265 | litellm |
| `litellm` 1.83.7 | CVE-2026-40217 | cisco-ai-mcp-scanner / -skill-scanner |
| `python-dotenv` 1.0.1 | CVE-2026-28684 | litellm |

`cisco-ai-mcp-scanner` exact-pins `litellm==1.83.7`, and `litellm` exact-pins the
vulnerable `aiohttp`/`python-dotenv` even in its own patched release — so no
version bump resolves these.

**If you opt in** (`pip install "blastcontain-verify[cisco]"`) to enable SKILL-02
and the Cisco MCP-01 backend, you accept these CVEs. They are largely mitigated
in the recommended hardened container profile (`--network none`): `litellm` and
`aiohttp` make no outbound calls during a scan, so the network-path CVEs are not
reachable. Residual exposure exists only when running via `pip` with network
access and an `http://` `--mcp-config`. The pins will be dropped as soon as
upstream ships a fixed combination.

## Out of scope

- Vulnerabilities in optional augmentation packages (Cisco, AGT, Presidio) — report upstream
- Issues that require physical access or a pre-authenticated administrator
- Findings in the closed-source BlastContain Platform — report to security@blastcontain.io with `[platform]` in the subject
