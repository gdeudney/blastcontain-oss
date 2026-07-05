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
| 0.4.x | yes |
| 0.3.x | security fixes only until 2026-12-31 |
| < 0.3 | not supported |

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

## Optional Cisco scanner — dependency posture

`blastcontain-verify` is **secure-by-default**: the standard install
(`pip install blastcontain-verify` or `[full]`) and the official container image
carry **no known-vulnerable dependencies** — verified in CI by `pip-audit`
against [`constraints-full.txt`](constraints-full.txt).

As of 2026-06 the **opt-in Cisco AI Skill Scanner is also CVE-clean.**
`cisco-ai-skill-scanner>=2.0.12` (installed via `[skill]` / `[cisco]`) raised its
`litellm` floor to `>=1.84`, and current `litellm` relaxed its transitive pins to
ranges (`aiohttp>=3.10`, `python-dotenv>=1.0`), so the fixed versions now resolve
and the four earlier CVEs (CVE-2026-34993 / -47265 / -40217 / -28684) clear. The
weekly opt-in audit job in `security.yml` watches this (unpinned) tree for new
CVEs.

**`cisco-ai-mcp-scanner` (the MCP-01 backend) is deliberately NOT packaged.**
Every release still exact-pins `litellm==1.83.7`, which drags in the vulnerable
`aiohttp`/`python-dotenv` above; it also conflicts with `skill>=2.0.12`'s newer
`litellm`, so the two cannot coexist. And MCP-01 is dormant — it SKIPs without a
Charter (not yet wired). It will be re-added the day upstream relaxes that pin
**and** Charter activates MCP-01; until then it would add CVEs for zero active
coverage.

## Out of scope

- Vulnerabilities in optional augmentation packages (Cisco, AGT, Presidio) — report upstream
- Issues that require physical access or a pre-authenticated administrator
- Findings in the closed-source BlastContain Platform — report to security@blastcontain.io with `[platform]` in the subject
