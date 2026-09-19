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
key is public knowledge, an advisory signature can detect accidental corruption
but cannot protect against an attacker modifying and re-signing the payload. It
provides **no attestation of who produced it**. Treat advisory packets as unattested. For attestation, configure
an Ed25519 key (`BLASTCONTAIN_SIGNING_KEY_PATH`) and manage it like any other
production secret; use `--require-signing` in pipelines that must never emit an
advisory packet. Key management is deliberately out of scope for the OSS tool —
the signature is only as trustworthy as your key handling. Consumers must match
an embedded public key against a separately trusted signer; signature consistency
alone is not signer authentication.

## Presidio Anonymizer compatibility hold (2026-09-07)

Analyzer is updated to 2.2.364, but Anonymizer is deliberately pinned to
2.2.362 in both `[full]` and `[pii]`. Anonymizer 2.2.364 requires
`cryptography>=48.0.1,<49.0.0`; resolving it selected cryptography 48.0.1.
`pip-audit` reported PYSEC-2026-3553 and PYSEC-2026-3554 (fixed in 49.0.0),
and PYSEC-2026-3552 (fixed in 50.0.0). Duplicate advisory rows were also
reported; these represent three distinct advisory identifiers.

The upgrade candidate passed unit tests but failed the security audit. Keep
Anonymizer 2.2.362 with the audited cryptography 50.0.1 container pin. Revisit
when an upstream Anonymizer release supports patched cryptography; regenerate
constraints, run the tests and audit, and validate the container before updating.
Do not override upstream metadata with `--no-deps` to force this upgrade.

## Optional Cisco scanner — dependency posture

The [2026-09-19 Security run](https://github.com/gdeudney/blastcontain-oss/actions/runs/35465109852)
passed the four pinned dependency audits and the separately resolved optional
extras audit. The gating job audits `constraints-full.txt`; it does not establish
that every unconstrained pip installation or every container OS package is clean.
Audit the resolved deployment environment as well.

The `[skill]` / `[cisco]` extras install Cisco AI Skill Scanner. Their unpinned
transitive dependencies are checked by a weekly, non-gating audit that records
failures. An earlier clean run is not a continuing security guarantee.

`cisco-ai-mcp-scanner` is not packaged. It was excluded after dependency findings
and conflicts with the skill scanner. Re-evaluate current upstream metadata and
security advisories before adding it. MCP-01 currently SKIPs without the Charter
allowlist integration; MCP-02/03 provide configuration checks only.

## Out of scope

- Vulnerabilities in optional augmentation packages (Cisco, AGT, Presidio) — report upstream
- Issues that require physical access or a pre-authenticated administrator
- Findings in the closed-source BlastContain Platform — report to security@blastcontain.io with `[platform]` in the subject
