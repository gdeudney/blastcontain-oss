# Security Policy

## Reporting a vulnerability

Email **security@blastcontain.io** with:

1. A description of the vulnerability
2. Steps to reproduce or a proof-of-concept
3. The affected version(s)
4. Your name and how you'd like to be credited (or "anonymous")

**Please do not open public GitHub issues for security vulnerabilities.**

## What to expect

| Day | Response |
|---|---|
| Within 2 business days | Acknowledgement of receipt |
| Within 7 days | Initial triage and severity assessment |
| Within 90 days | Fix released or detailed mitigation plan |
| At time of fix | CVE assignment if applicable, public advisory, credit |

We follow [coordinated disclosure](https://www.first.org/cvss/). If you'd like to publish your finding, please coordinate timing with us.

## Supported versions

| Version | Supported |
|---|---|
| 0.x | yes |

Once we hit 1.0, the most recent two minor versions will receive security fixes for at least 12 months.

## Out of scope

- Issues in downstream packages (`blastcontain-verify`, `blastcontain-drill`, `blastcontain-discovery`) — please report to their respective repos
- Issues in `cryptography` or `pyyaml` upstream — report to those projects directly
- Findings that require physical access to a system or a pre-authenticated administrator

Thanks for helping keep the BlastContain ecosystem safe.
