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

## Out of scope

- Vulnerabilities in optional augmentation packages (Cisco, AGT, Presidio) — report upstream
- Issues that require physical access or a pre-authenticated administrator
- Findings in the closed-source BlastContain Platform — report to security@blastcontain.io with `[platform]` in the subject
