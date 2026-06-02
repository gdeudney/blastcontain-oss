"""
blastcontain-core — shared types and primitives for BlastContain tools.

Used by:
  - blastcontain-verify  (pre-deployment compliance scanner)
  - blastcontain-drill   (runtime probing / red-team simulation)
  - blastcontain-discovery (shadow AI / agent discovery)
  - BlastContain Platform (closed source; depends on this package)

Stable public API:
  models       — Severity, ScanStatus, InfraFinding, ScanResult;
                 DrillOutcome, DrillStatus, DrillFinding, DrillReport
  constants    — MIT_RISK_MAP, ATLAS_TECHNIQUES, OWASP_AGENTIC_MAP,
                 DRILL_CATEGORY_TAXONOMY (the shared taxonomy maps)
  charter      — CharterSchema, DelegationRules, HitlConfig, RemediationProof
  signing      — sign_packet(), verify_packet() — Ed25519 + HMAC fallback
  sarif        — write_sarif(), parse_sarif()
  ignore       — load_ignore_patterns(), is_ignored() (.blastcontainignore)
"""
from __future__ import annotations

__version__ = "0.2.0"
