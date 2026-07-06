"""
BlastContain Verify — CLI entry point.

blastcontain-verify [OPTIONS]
"""
from __future__ import annotations

import os
import sys

import click

from .augmentation import AUGMENTATION_FLAGS
from .config import load_config
from .models import ScanStatus
from .reporter import post_to_ledger, write_audit_packet, write_markdown_report
from .reporter_sarif import write_sarif
from .scanner import run_scan

_STATUS_EMOJI = {
    ScanStatus.APPROVED:    "✅",
    ScanStatus.REJECTED:    "🟠",
    ScanStatus.QUARANTINED: "🔴",
    ScanStatus.ERROR:       "⚠️",
}

_EXIT_CODES = {
    ScanStatus.APPROVED:    0,
    ScanStatus.REJECTED:    1,
    ScanStatus.QUARANTINED: 2,
    ScanStatus.ERROR:       3,
}


def _force_utf8_output() -> None:
    """Keep the emoji-bearing console output from ever aborting the scan.

    The results table and summary print status glyphs (✅ ❌ ⏭ ⚠️). On Windows a
    non-UTF-8 stdout — a redirect to a file, a pipe, or a legacy cp1252 console —
    cannot encode them, so ``click.echo`` raises ``UnicodeEncodeError`` mid-run
    and, because the table prints *before* the packet is written, the audit
    packet is lost. Reconfigure both streams to UTF-8 (replacing any glyph a
    target still can't render rather than crashing). No-op on streams that don't
    support ``reconfigure``.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


@click.command("blastcontain-verify")
@click.option("--agent-id",          default=None,      help="Agent identifier (required)")
@click.option("--config", "-c",      default=None,      help="Config file path (default: blastcontain-verify.yaml)")
@click.option("--env",               default=None,      help="Environment: dev | uat | staging | prod | local_developer_workstation")
@click.option("--search-path",       default=None,      help="Root path for source and secret scanning")
@click.option("--skills-dir",        default=None,      help="Skill code directory for SKILL-01/02")
@click.option("--api-spec",          default=None,      help="OpenAPI 3.0 JSON/YAML spec path")
@click.option("--mcp-config",        default=None,      help="MCP server config JSON path")
@click.option("--model-dir",         default=None,      help="Model weights directory")
@click.option("--context-file",      default=None,      help="Session context text for PII scanning")
@click.option("--output",            default=None,      help="Signed JSON Audit Packet output path")
@click.option("--report",            default=None,      help="Markdown report output path")
@click.option("--blastcontain-url",  default=None,      help="BlastContain server URL (or $BLASTCONTAIN_URL)")
@click.option("--dry-run",           is_flag=True,      help="Skip server POST")
@click.option("--acknowledge-risk",  is_flag=True,      help="Exit 0 even on CRITICAL (not recommended)")
@click.option("--max-tier",          default=None, type=int, help="Highest TrustTier in delegation chain (0-3)")
@click.option("--egress-probe-target", default=None, help="host:port for ENV-02/NET-01 probes (default: 8.8.8.8:53)")
@click.option("--skip-checks",       default=None,            help="Comma-separated check IDs to skip, e.g. 'CRED-02,LOCAL-01'")
@click.option("--api-live-probe",    is_flag=True, default=False, help="API-01: send live OPTIONS requests to spec server URLs (off by default — opt-in for offline scans)")
@click.option("--sarif",             default=None,            help="Write SARIF 2.1.0 output to this path (for GitHub Code Scanning, GitLab, IDEs)")
@click.option("--require-signing",   is_flag=True, default=False, help="Exit 3 before scanning unless a real signing key is configured — never emit an advisory (default-HMAC-key) packet")
def main(
    agent_id, config, env, search_path, skills_dir, api_spec, mcp_config,
    model_dir, context_file, output, report, blastcontain_url,
    dry_run, acknowledge_risk, max_tier, egress_probe_target,
    skip_checks, api_live_probe, sarif, require_signing,
):
    """
    BlastContain Verify — pre-deployment environmental compliance scanner.

    Runs 27 security checks against the agent's runtime environment and
    produces a Markdown report and signed JSON Audit Packet.

    Exit codes: 0=APPROVED  1=REJECTED  2=QUARANTINED  3=ERROR
    """
    # Make console output encoding-safe before anything is printed — a Windows
    # cp1252 or redirected stdout otherwise raises UnicodeEncodeError on the
    # status emoji and aborts the scan before the audit packet is written.
    _force_utf8_output()

    # ── Build config ───────────────────────────────────────────────────────────
    cfg = load_config(
        config_file=config,
        cli_overrides={
            "agent_id":         agent_id,
            "environment":      env,
            "search_path":      search_path,
            "skills_dir":       skills_dir,
            "api_spec":         api_spec,
            "mcp_config":       mcp_config,
            "model_dir":        model_dir,
            "context_file":     context_file,
            "output":           output,
            "report":           report,
            "blastcontain_url": blastcontain_url,
            "dry_run":             dry_run,
            "acknowledge_risk":    acknowledge_risk,
            "max_tier":            max_tier,
            "egress_probe_target": egress_probe_target,
            "skip_checks":         skip_checks,
            "api_live_probe":      api_live_probe if api_live_probe else None,
            "sarif":               sarif,
        },
    )

    if not cfg.agent_id:
        click.echo("Error: --agent-id is required (or set agent_id in config file)", err=True)
        sys.exit(3)

    # ── Signing gate ───────────────────────────────────────────────────────────
    # With --require-signing, refuse to scan unless a real key source is set.
    # The default HMAC key produces an *advisory* packet (integrity-only, not
    # attestation) — CI attestation pipelines use this flag to fail fast rather
    # than ship one. Mirrors blastcontain_core.signing's key priority.
    if require_signing:
        has_real_key = bool(
            os.environ.get("BLASTCONTAIN_SIGNING_KEY_PATH")
            or os.environ.get("BLASTCONTAIN_SIGNING_KEY_PEM")
            or os.environ.get("BLASTCONTAIN_SIGNING_KEY", "local-verify-default")
            != "local-verify-default"
        )
        if not has_real_key:
            click.echo(
                "Error: --require-signing is set but no signing key is configured. "
                "Set BLASTCONTAIN_SIGNING_KEY_PATH (PEM Ed25519, preferred), "
                "BLASTCONTAIN_SIGNING_KEY_PEM, or a non-default BLASTCONTAIN_SIGNING_KEY.",
                err=True,
            )
            sys.exit(3)

    # ── Augmentation banner ────────────────────────────────────────────────────
    active = [k for k, v in AUGMENTATION_FLAGS.items() if v]
    inactive = [k for k, v in AUGMENTATION_FLAGS.items() if not v]

    click.echo(f"\n{'='*60}")
    click.echo(f"  BlastContain Verify  |  Agent: {cfg.agent_id}  |  Env: {cfg.environment}")
    click.echo(f"{'='*60}")
    if active:
        click.echo(f"  Augmentation active:   {', '.join(active)}")
    if inactive:
        click.echo(f"  Not installed:         {', '.join(inactive)}")
        if any(k in inactive for k in ("presidio", "agt")):
            click.echo('  Enable PII / AGT:      pip install "blastcontain-verify[full]"')
        if "cisco_skill" in inactive:
            click.echo('  Enable SKILL-02:       pip install "blastcontain-verify[cisco]"')
    click.echo()

    # ── Run scan ───────────────────────────────────────────────────────────────
    click.echo("  Running checks...\n")
    result = run_scan(cfg)

    # ── Per-check results table ────────────────────────────────────────────────
    # Build lookup maps
    failed_map = {f.check_id: f for f in result.findings}
    passed_set = set(result.passed)
    skipped_map = {s["check_id"]: s.get("reason", "") for s in result.skipped}

    # Collect all check IDs across all three buckets and sort them
    all_ids = sorted(
        set(failed_map) | passed_set | set(skipped_map),
        key=lambda c: (c.split("-")[0], int(c.split("-")[1]) if c.split("-")[1].isdigit() else 0),
    )

    _SEV_TAG = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "HIGH    ",
        "MEDIUM":   "MEDIUM  ",
        "LOW":      "LOW     ",
        "INFO":     "INFO    ",
    }

    for check_id in all_ids:
        if check_id in failed_map:
            f = failed_map[check_id]
            tag = _SEV_TAG.get(f.severity.value, f.severity.value)
            click.echo(f"  ❌  {check_id:<10}  {tag}  {f.title}")
        elif check_id in passed_set:
            click.echo(f"  ✅  {check_id:<10}  PASS      ")
        elif check_id in skipped_map:
            reason = skipped_map[check_id]
            click.echo(f"  ⏭   {check_id:<10}  SKIP      {reason}")
    click.echo()

    # ── Summary ────────────────────────────────────────────────────────────────
    emoji = _STATUS_EMOJI[result.status]
    click.echo(f"  Status:     {emoji} {result.status.value}")
    click.echo(f"  Critical:   {len(result.criticals)}")
    click.echo(f"  High:       {len(result.highs)}")
    click.echo(f"  Medium:     {len(result.mediums)}")
    click.echo(f"  Passed:     {len(result.passed)}")
    click.echo(f"  Skipped:    {len(result.skipped)}")
    click.echo(f"  Blast rad:  {result.blast_radius_factor:.1f}x (TIER_{result.max_tier})")
    click.echo()

    # ── Write report / audit / SARIF ───────────────────────────────────────────
    # A non-writable output path (e.g. an output volume the hardened scan UID
    # cannot write to) must fail with a clear, actionable message and an ERROR
    # exit — never an uncaught traceback.
    try:
        if cfg.report:
            write_markdown_report(result, cfg.report)
            click.echo(f"  Report:     {cfg.report}")

        if cfg.output:
            write_audit_packet(result, cfg.output)
            click.echo(f"  Audit:      {cfg.output}")

        if cfg.sarif:
            write_sarif(result, cfg.sarif)
            click.echo(f"  SARIF:      {cfg.sarif}")
    except OSError as exc:
        click.echo(
            f"Error: could not write output file: {exc}. "
            "Ensure the output directory exists and is writable by the scan user "
            "(mount it writable, e.g. -v <host-dir>:/reports:rw, and make sure the "
            "container UID can write to it).",
            err=True,
        )
        sys.exit(3)

    # ── Post to Ledger ─────────────────────────────────────────────────────────
    if cfg.blastcontain_url and not cfg.dry_run:
        click.echo(f"  Posting to: {cfg.blastcontain_url}")
        ok = post_to_ledger(result, cfg.blastcontain_url)
        if not ok:
            click.echo("  Warning: Ledger POST failed", err=True)
            sys.exit(3)

    click.echo(f"{'='*60}\n")

    # ── Exit code ──────────────────────────────────────────────────────────────
    if cfg.acknowledge_risk:
        sys.exit(0)

    sys.exit(_EXIT_CODES.get(result.status, 3))
