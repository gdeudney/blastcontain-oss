"""
BlastContain Drill — report writer.

Produces a human-readable Markdown report and a cryptographically signed JSON
DrillReport packet, in the same Audit-Packet envelope Verify uses. Signing is
delegated to blastcontain_core.signing (Ed25519 or HMAC fallback).
"""
from __future__ import annotations

import datetime
import json
import os
from collections import defaultdict

from blastcontain_core.models import DrillOutcome, DrillReport, DrillStatus, Severity
from blastcontain_core.signing import sign_packet

from . import __version__

_STATUS_EMOJI = {
    DrillStatus.PASSED: "✅",
    DrillStatus.PARTIAL: "🟠",
    DrillStatus.FAILED: "🔴",
    DrillStatus.ERROR: "⚠️",
}

_SEV_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    None: "",
}


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _outcome_mark(f) -> str:
    if f.outcome == DrillOutcome.HELD:
        return "✅ HELD"
    if f.outcome == DrillOutcome.BYPASS:
        return f"{_SEV_EMOJI.get(f.severity, '🟠')} BYPASS"
    if f.outcome == DrillOutcome.OVER_REFUSAL:
        return "🟡 OVER-REFUSAL"
    return "⚠️ ERROR"


def write_markdown_report(report: DrillReport, path: str) -> None:
    lines: list[str] = []
    emoji = _STATUS_EMOJI.get(report.status, "⚠️")

    lines += [
        "# BlastContain Drill — Adversarial Red-Team Report",
        "",
        f"**Agent:** `{report.agent_id}` | **Environment:** `{report.environment}` | "
        f"**Status:** {emoji} {report.status.value}",
        f"**Corpus:** `{report.corpus_version}` "
        f"(sources: {', '.join(report.corpus_sources) or '—'}) | "
        f"**Drilled:** {report.drilled_at} | **Drill ID:** `{report.drill_id}`",
        "",
        "**Bench** — "
        f"target: `{report.target_model or '—'}` · cage: `{report.cage or '—'}` · "
        f"judge: `{report.judge_model or '—'}` · guard: `{report.guard_model or '—'}`",
        "",
    ]

    # Summary counts
    summary_lines = [
        "## Summary",
        "",
        f"- Scenarios run: **{len(report.findings)}**",
        f"- ✅ Held: **{len(report.held)}**",
        f"- BYPASS: **{len(report.bypasses)}** "
        f"(🔴 critical: **{len(report.critical_bypasses)}**)",
    ]
    if report.over_refusals:
        summary_lines.append(
            "- 🟡 Over-refusals (benign requests wrongly refused): "
            f"**{len(report.over_refusals)}**"
        )
    summary_lines += [
        f"- ⚠️ Errors: **{len(report.errors)}**",
        "",
    ]
    lines += summary_lines
    if report.warnings:
        lines += ["## ⚠ Warnings", ""]
        lines += [f"- {w}" for w in report.warnings]
        lines += [""]
    if report.judge_reliability:
        jr = report.judge_reliability
        lines += [
            "## Judge reliability",
            "",
            f"- Judged findings: **{jr['judged_findings']}** · judge↔guard compared: "
            f"**{jr['judge_guard_compared']}** · disagreements: **{jr['judge_guard_disagreements']}**",
            f"- Mean judge confidence: **{jr['mean_judge_confidence']}** · low-confidence "
            f"(<0.5): **{jr['low_confidence_findings']}**",
        ]
        if report.judge_target_same_family:
            lines.append(
                "- ⚠️ Judge and target are the **same model family** — possible self-bias; "
                "treat judge-only bypasses with caution."
            )
        lines += [""]
    if report.critical_bypasses:
        lines += [
            "> 🔴 **CRITICAL bypasses present — this drill blocks prod promotion.**",
            "",
        ]

    # Per-scenario results table
    lines += [
        "## Results",
        "",
        "| Scenario | Category | Result | Latency | Held/blocked by |",
        "|---|---|---|---|---|",
    ]
    for f in report.findings:
        latency = f"{f.detection_latency_ms:.0f}ms" if f.detection_latency_ms is not None else "—"
        lines.append(
            f"| `{f.scenario_id}` | {f.scenario_name} | {_outcome_mark(f)} | "
            f"{latency} | {f.blocked_by or '—'} |"
        )
    lines.append("")

    # Bypass detail
    if report.bypasses:
        lines += ["## 🔴 Bypasses", ""]
        for f in sorted(report.bypasses, key=lambda x: 0 if x.severity == Severity.CRITICAL else 1):
            lines += [
                f"### {f.scenario_id} — {f.scenario_name}",
                "",
                f"**Severity:** {_SEV_EMOJI.get(f.severity, '')} "
                f"{f.severity.value if f.severity else '—'} | "
                f"**Technique:** `{f.technique}` | **Vector:** {f.vector or '—'} | "
                f"**Layer:** {f.layer}",
                f"**ATLAS:** {f.atlas_id} — {f.atlas_name} | "
                f"**OWASP:** {f.owasp_id} ({f.owasp_label}) | **MIT:** {f.mit_domain or '—'}",
                "",
                f"{f.bypass_description or ''}",
                "",
            ]
            if f.evidence:
                lines += [f"**Evidence:** `{f.evidence}`", ""]
            if f.blocked_by:
                lines += [f"**Note:** {f.blocked_by}", ""]

    # Over-refusal detail — benign requests the agent wrongly refused (false positives)
    if report.over_refusals:
        lines += ["## 🟡 Over-refusals (false positives on benign requests)", ""]
        for f in report.over_refusals:
            extra = f" — {f.bypass_description}" if f.bypass_description else ""
            lines.append(f"- `{f.scenario_id}` {f.scenario_name}{extra}")
        lines.append("")

    # ATLAS coverage
    cov: dict[str, dict] = defaultdict(lambda: {"name": "", "run": 0, "bypass": 0})
    for f in report.findings:
        if not f.atlas_id:
            continue
        cov[f.atlas_id]["name"] = f.atlas_name or ""
        cov[f.atlas_id]["run"] += 1
        if f.outcome == DrillOutcome.BYPASS:
            cov[f.atlas_id]["bypass"] += 1
    if cov:
        lines += [
            "## MITRE ATLAS Coverage",
            "",
            "| Technique | Name | Scenarios | Bypasses |",
            "|---|---|---|---|",
        ]
        for tid in sorted(cov):
            c = cov[tid]
            lines.append(f"| {tid} | {c['name']} | {c['run']} | {c['bypass']} |")
        lines.append("")

    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def write_drill_packet(report: DrillReport, path: str) -> dict:
    """Write and return a signed JSON DrillReport packet."""
    payload = report.as_dict()
    payload["generator"] = "blastcontain-drill"
    payload["generator_version"] = __version__

    signed_at = _utc_now_iso()
    signature = sign_packet(payload, signed_at=signed_at)
    packet = {"schema_version": "1.1", "packet": payload, "signature": signature}

    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(packet, f, indent=2)
    return packet


def write_generative_corpus(results, path: str) -> dict:
    """
    Write discovered jailbreaks + transcripts to a SENSITIVE corpus file.

    These are working attacks against the target — store them like secrets
    (drill-spec §8): separate from the signed report, never committed, never
    shared. The signed DrillReport carries only an excerpt of each.
    """
    payload = {
        "_warning": "SENSITIVE — working jailbreak prompts. Treat as secrets; do not commit or share.",
        "generator": "blastcontain-drill",
        "generator_version": __version__,
        "results": [
            {
                "goal_id": r.goal_id,
                "category": r.category,
                "success": r.success,
                "iterations": r.iterations,
                "discovered_prompt": r.discovered_prompt,
                "transcript": r.transcript,
            }
            for r in results
        ],
    }
    _ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return payload


def post_to_ledger(report: DrillReport, blastcontain_url: str) -> bool:
    """POST the DrillReport to the BlastContain Ledger. Returns True on success."""
    try:
        import httpx

        url = f"{blastcontain_url.rstrip('/')}/v1/agents/{report.agent_id}/findings"
        resp = httpx.post(url, json=report.as_dict(), timeout=10)
        return resp.status_code in (200, 201, 202)
    except Exception:
        return False


def _ensure_parent(path: str) -> None:
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except OSError:
        pass
