# Security Policy

## Reporting a vulnerability

Email **security@blastcontain.io** with:

1. A description of the vulnerability
2. Steps to reproduce or a proof-of-concept
3. The affected version(s) of `blastcontain-drill`
4. Your name and how you'd like to be credited

**Please do not open public GitHub issues for security vulnerabilities.**

## Drill is an offensive tool — handle it accordingly

Drill emits live adversarial payloads and, in its generative layer, runs an
attacker model with no refusals. The product's own design tenet applies to
itself (*govern your own*):

- **Run attacks in the cage.** The attacker model and the corpus execution are
  air-gapped, egress-controlled, and logged. Treat their output as untrusted.
- **The generated-jailbreak corpus is sensitive.** Store it like a secret; do
  not commit it; do not leak it to disk unencrypted.
- **Check dataset licenses.** Some HF jailbreak sets are gated or restricted —
  record provenance before redistributing.

## What counts as a vulnerability

- A scenario that can be tricked into a false **HELD** by a malicious target
  (reports a control works when it does not)
- A way to forge or replay a valid DrillReport signature
- A cage escape — an in-cage agent reaching the host or the network past the
  egress allowlist
- An attacker-model or corpus output path that exfiltrates payloads off the box

## What we treat as bugs (open a public issue)

- A scenario that reports BYPASS on a control that actually held (false positive)
- Detection-latency inaccuracy
- A scorer that crashes on unusual model output

## Response timeline

| Day | Response |
|---|---|
| Within 2 business days | Acknowledgement |
| Within 7 days | Initial triage and severity assessment |
| Within 90 days | Fix released or detailed mitigation plan |

## Out of scope

- Vulnerabilities in optional augmentation (AI-Infra-Guard, DeepEval, guardrail
  models) — report upstream
- Findings in the closed-source BlastContain Platform — email with `[platform]`
  in the subject
