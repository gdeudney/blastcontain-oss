"""
blastcontain_core.constants — MIT AI Risk Repository taxonomy mapping.

This file maps internal BlastContain finding_type strings to the public
MIT AI Risk Repository v4 taxonomy. Both the tools and the platform
read from this single source of truth.

The MIT AI Risk Repository is a public taxonomy maintained at:
  https://airisk.mit.edu/

Tier weights are also shared here because every tool that surfaces
compliance status needs to compute a blast radius factor consistently.
"""
from __future__ import annotations

from typing import Optional


# ── Blast radius tier weights ──────────────────────────────────────────────────
TIER_BLAST_WEIGHTS: dict[int, float] = {0: 1.0, 1: 1.5, 2: 2.5, 3: 4.0}


# ── MIT AI Risk Repository v4 mapping ─────────────────────────────────────────
# finding_type -> (domain, causal_id, causal_label)
MIT_RISK_MAP: dict[str, tuple[str, str, str]] = {
    "blastcontain.env.kernel_isolation_missing":    ("System Deficiencies",    "MIT-SYS-02", "Missing Sandbox Isolation"),
    "blastcontain.env.egress_unrestricted":         ("Exfiltration Vectors",   "MIT-NET-05", "Unrestricted Network Egress"),
    "blastcontain.env.model_weights_writable":      ("System Deficiencies",    "MIT-SYS-03", "Mutable Model Artefacts"),
    "blastcontain.disk.rootfs_writable":            ("System Deficiencies",    "MIT-SYS-01", "Insecure Runtime Configuration"),
    "blastcontain.cred.secrets_on_disk":            ("Identity Abuse",         "MIT-ID-01",  "Hardcoded Credentials"),
    "blastcontain.cred.live_env_credentials":       ("Identity Abuse",         "MIT-ID-02",  "Credentials in Process Environment"),
    "blastcontain.cred.wildcard_api_capability":    ("Identity Abuse",         "MIT-ID-03",  "Overpermissioned API Scope"),
    "blastcontain.priv.elevated_privilege":         ("System Deficiencies",    "MIT-SYS-04", "Elevated Process Privilege"),
    "blastcontain.priv.dangerous_capabilities":     ("System Deficiencies",    "MIT-SYS-05", "Dangerous Linux Capabilities"),
    "blastcontain.net.dns_exfil_open":              ("Exfiltration Vectors",   "MIT-NET-01", "DNS Exfiltration Channel"),
    "blastcontain.net.external_listeners":          ("Exfiltration Vectors",   "MIT-NET-02", "External Network Exposure"),
    "blastcontain.perm.persistence_writable":       ("System Deficiencies",    "MIT-SYS-06", "Persistence Location Accessible"),
    "blastcontain.mem.pii_in_context":              ("Data Security Failures", "MIT-DATA-07", "PII in Agent Context"),
    "blastcontain.mem.pii_exfil_path":              ("Data Security Failures", "MIT-DATA-11", "Viable PII Exfiltration Path"),
    "blastcontain.mem.namespace_isolation_missing": ("Data Security Failures", "MIT-DATA-09", "Missing Tenant Namespace Isolation"),
    "blastcontain.skill.exfil_capable":             ("Tool Vetting Lack",      "MIT-TOOL-04", "Exfiltration-Capable Tool Present"),
    "blastcontain.skill.cisco_finding":             ("Tool Vetting Lack",      "MIT-TOOL-03", "Skill Security Finding"),
    "blastcontain.api.destructive_permission":      ("Tool Vetting Lack",      "MIT-TOOL-05", "Destructive API Permission"),
    "blastcontain.api.unauthenticated_endpoint":    ("Identity Abuse",         "MIT-ID-04",  "Unauthenticated Destructive Endpoint"),
    "blastcontain.mcp.unapproved_tool":             ("Tool Vetting Lack",      "MIT-TOOL-01", "Unapproved MCP Tool"),
    "blastcontain.mcp.missing_auth":                ("Identity Abuse",         "MIT-ID-05",  "MCP Server Without Authentication"),
    "blastcontain.mcp.dangerous_combination":       ("Tool Vetting Lack",      "MIT-TOOL-02", "Dangerous MCP Tool Combination"),
    "blastcontain.code.dangerous_pattern":          ("Unsafe Code Execution",  "MIT-CODE-01", "Dangerous Code Execution Pattern"),
    "blastcontain.supply_chain.unsigned_weights":   ("Tool Vetting Lack",      "MIT-TOOL-06", "Unattested Model Weights"),
    "blastcontain.tls.plaintext_endpoint":          ("Data Security Failures", "MIT-DATA-02", "Plaintext Communication Channel"),
    "blastcontain.local.workstation_detected":     ("System Deficiencies",    "MIT-SYS-07", "Non-Containerised Agent Deployment"),
    "blastcontain.scanner.check_group_failed":      ("System Deficiencies",    "MIT-SYS-08", "Scanner Internal Failure"),
}


def mit_for(finding_type: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Look up the MIT (domain, causal_id, label) for a finding_type."""
    return MIT_RISK_MAP.get(finding_type, (None, None, None))


# ── MITRE ATLAS technique registry ────────────────────────────────────────────
# Verified against atlas.mitre.org (June 2026). ATLAS is the AI-native ATT&CK
# and the *primary* taxonomy for Drill findings (drill-spec §6). The two agent
# techniques (T0086, T0110) cover the action plane — what the agent *did*, not
# just what the model said.
ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0051":     "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054":     "LLM Jailbreak",
    "AML.T0057":     "LLM Data Leakage",
    "AML.T0024":     "Exfiltration via AI Inference API",
    "AML.T0086":     "Exfiltration via AI Agent Tool Invocation",
    "AML.T0110":     "AI Agent Tool Poisoning",
}


# ── OWASP Agentic Security (ASI) threat catalog — T1–T15 ───────────────────────
# OWASP Agentic AI "Threats and Mitigations" v1.0 — the secondary taxonomy,
# consistent with charter-spec §4.
OWASP_AGENTIC_MAP: dict[str, str] = {
    "T1":  "Memory Poisoning",
    "T2":  "Tool Misuse",
    "T3":  "Privilege Compromise",
    "T4":  "Resource Overload",
    "T5":  "Cascading Hallucination Attacks",
    "T6":  "Intent Breaking & Goal Manipulation",
    "T7":  "Misaligned & Deceptive Behaviors",
    "T8":  "Repudiation & Untraceability",
    "T9":  "Identity Spoofing & Impersonation",
    "T10": "Overwhelming Human-in-the-Loop",
    "T11": "Unexpected RCE and Code Attacks",
    "T12": "Agent Communication Poisoning",
    "T13": "Rogue Agents in Multi-Agent Systems",
    "T14": "Human Attacks on Multi-Agent Systems",
    "T15": "Human Manipulation",
}


# ── Drill attack-category taxonomy ─────────────────────────────────────────────
# Maps each Drill attack category to its taxonomy tags as
# (atlas_id, atlas_name, mit_domain, owasp_id, owasp_label).
#
# ATLAS ids are verified and primary; OWASP uses the project-standard T1–T15.
# The MIT field carries only the real high-level *domain* name (a MIT AI Risk
# Repository "Causal" top-level domain) — the numeric subdomain ids are
# intentionally omitted rather than invented; validate against airisk.mit.edu
# before adding them (cf. platform-spec §6's note on purging non-real MIT ids).
DRILL_CATEGORY_TAXONOMY: dict[str, tuple[str, str, Optional[str], str, str]] = {
    "prompt_injection_direct": (
        "AML.T0051.000", "LLM Prompt Injection: Direct",
        "Malicious Actors & Misuse", "T6", "Intent Breaking & Goal Manipulation",
    ),
    "prompt_injection_indirect": (
        "AML.T0051.001", "LLM Prompt Injection: Indirect",
        "Malicious Actors & Misuse", "T6", "Intent Breaking & Goal Manipulation",
    ),
    "jailbreak": (
        "AML.T0054", "LLM Jailbreak",
        "Malicious Actors & Misuse", "T6", "Intent Breaking & Goal Manipulation",
    ),
    "data_exfiltration": (
        "AML.T0086", "Exfiltration via AI Agent Tool Invocation",
        "Privacy & Security", "T2", "Tool Misuse",
    ),
    "tool_misuse": (
        "AML.T0086", "Exfiltration via AI Agent Tool Invocation",
        "Malicious Actors & Misuse", "T2", "Tool Misuse",
    ),
    "mcp_hijack": (
        "AML.T0110", "AI Agent Tool Poisoning",
        "Privacy & Security", "T2", "Tool Misuse",
    ),
}


def atlas_for(category: str) -> tuple[Optional[str], Optional[str]]:
    """Return (atlas_id, atlas_name) for a Drill attack category."""
    entry = DRILL_CATEGORY_TAXONOMY.get(category)
    return (entry[0], entry[1]) if entry else (None, None)


def owasp_for(category: str) -> tuple[Optional[str], Optional[str]]:
    """Return (owasp_id, owasp_label) for a Drill attack category."""
    entry = DRILL_CATEGORY_TAXONOMY.get(category)
    return (entry[3], entry[4]) if entry else (None, None)


def taxonomy_for(category: str) -> dict:
    """
    Return the full taxonomy dict for a Drill attack category:
    {atlas_id, atlas_name, mit_domain, owasp_id, owasp_label}.
    An unknown category yields all-None (the finding is still recorded).
    """
    entry = DRILL_CATEGORY_TAXONOMY.get(category)
    if not entry:
        return {
            "atlas_id": None, "atlas_name": None, "mit_domain": None,
            "owasp_id": None, "owasp_label": None,
        }
    return {
        "atlas_id": entry[0], "atlas_name": entry[1], "mit_domain": entry[2],
        "owasp_id": entry[3], "owasp_label": entry[4],
    }
