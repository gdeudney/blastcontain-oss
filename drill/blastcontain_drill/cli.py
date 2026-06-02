"""
BlastContain Drill — CLI entry point.

blastcontain-drill [OPTIONS]

Exit codes: 0=PASSED  1=PARTIAL  2=FAILED  3=ERROR
"""
from __future__ import annotations

import sys

import click

from blastcontain_core.models import DrillOutcome, DrillStatus

from .config import load_config
from .reporter import post_to_ledger, write_drill_packet, write_markdown_report
from .runner import run_drill

_STATUS_EMOJI = {
    DrillStatus.PASSED: "✅",
    DrillStatus.PARTIAL: "🟠",
    DrillStatus.FAILED: "🔴",
    DrillStatus.ERROR: "⚠️",
}
_EXIT = {
    DrillStatus.PASSED: 0,
    DrillStatus.PARTIAL: 1,
    DrillStatus.FAILED: 2,
    DrillStatus.ERROR: 3,
}


@click.command("blastcontain-drill")
@click.option("--agent-id", default=None, help="Target agent identifier (required)")
@click.option("--config", "-c", default=None, help="Config file (default: blastcontain-drill.yaml)")
@click.option("--env", default=None, help="Environment: dev | uat | staging | prod")
@click.option("--cage", "cage_kind", default=None, help="inprocess | podman")
@click.option("--target-base-url", default=None, help="OpenAI-compatible endpoint for the in-cage agent")
@click.option("--target-model", default=None, help="Model id to drive as the agent (e.g. qwen/qwen3.6-27b)")
@click.option("--judge-base-url", default=None, help="Endpoint for the judge (defaults to target)")
@click.option("--judge-model", default=None, help="Model id for the content-plane judge")
@click.option("--guard-model", default=None, help="Guardrail classifier id (auto-detects Qwen3Guard / Granite Guardian)")
@click.option("--agent-url", default=None, help="Attack a running agent over HTTP (black-box mode)")
@click.option("--corpus", default=None, help="Corpus version to pin (default: built-in latest)")
@click.option("--scenarios", default=None, help="Comma-separated attack categories (default: all)")
@click.option("--limit", default=None, type=int, help="Cap attacks per category")
@click.option("--charter", default=None, help="Local charter.yaml — permitted_tools define 'forbidden'")
@click.option("--enable-aig", is_flag=True, default=False, help="Add AI-Infra-Guard source if its service is up")
@click.option("--operators", "enable_operators", is_flag=True, default=False, help="Add the model-free Operators layer (technique transforms)")
@click.option("--generative", is_flag=True, default=False, help="Run the generative layer (attacker model crafts/refines jailbreaks)")
@click.option("--generative-only", is_flag=True, default=False, help="Skip the static corpus; run only the generative loop")
@click.option("--attacker-model", default=None, help="Abliterated/Heretic attacker model id for the generative layer")
@click.option("--attacker-base-url", default=None, help="Endpoint for the attacker model (defaults to target)")
@click.option("--generative-iters", default=None, type=int, help="Max refinement iterations per goal (default 4)")
@click.option("--generative-corpus", default=None, help="Write discovered jailbreaks here (SENSITIVE — gitignore it)")
@click.option("--max-steps", default=None, type=int, help="Max tool steps per attack (default 4)")
@click.option("--output", default=None, help="Signed DrillReport JSON output path")
@click.option("--report", default=None, help="Markdown report output path")
@click.option("--blastcontain-url", default=None, help="BlastContain Ledger URL (or $BLASTCONTAIN_URL)")
@click.option("--dry-run", is_flag=True, default=False, help="Skip the Ledger POST")
def main(
    agent_id, config, env, cage_kind, target_base_url, target_model,
    judge_base_url, judge_model, guard_model, agent_url, corpus, scenarios,
    limit, charter, enable_aig, enable_operators,
    generative, generative_only, attacker_model, attacker_base_url,
    generative_iters, generative_corpus,
    max_steps, output, report,
    blastcontain_url, dry_run,
):
    """BlastContain Drill — adversarial red-team scanner with cage action ground truth."""
    # Windows consoles default to cp1252 and choke on the status emoji; force UTF-8.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass

    cfg = load_config(
        config_file=config,
        cli_overrides={
            "agent_id": agent_id, "environment": env, "cage": cage_kind,
            "target_base_url": target_base_url, "target_model": target_model,
            "judge_base_url": judge_base_url, "judge_model": judge_model,
            "guard_model": guard_model, "agent_url": agent_url, "corpus": corpus,
            "scenarios": scenarios, "limit": limit, "charter": charter,
            "enable_aig": enable_aig if enable_aig else None,
            "enable_operators": enable_operators if enable_operators else None,
            "generative": generative if generative else None,
            "generative_only": generative_only if generative_only else None,
            "attacker_model": attacker_model, "attacker_base_url": attacker_base_url,
            "generative_iters": generative_iters, "generative_corpus": generative_corpus,
            "max_steps": max_steps, "output": output, "report": report,
            "blastcontain_url": blastcontain_url, "dry_run": dry_run if dry_run else None,
        },
    )

    if not cfg.agent_id:
        click.echo("Error: --agent-id is required (or set agent_id in config file)", err=True)
        sys.exit(3)
    if cfg.cage == "inprocess" and not cfg.target_model:
        click.echo("Error: --target-model is required for the inprocess cage", err=True)
        sys.exit(3)

    click.echo(f"\n{'='*60}")
    click.echo(f"  BlastContain Drill  |  Agent: {cfg.agent_id}  |  Env: {cfg.environment}")
    click.echo(f"{'='*60}")

    # Availability banner — declare the bench honestly, like Verify augmentation.
    if cfg.cage == "inprocess":
        from .llm import ChatClient

        up = ChatClient(cfg.target_base_url, cfg.target_model).is_available()
        click.echo(f"  Cage:        inprocess  |  target: {cfg.target_model}  "
                   f"({'reachable' if up else 'UNREACHABLE'} at {cfg.target_base_url})")
        if not up:
            click.echo("  Warning: target model server is not reachable — scenarios will ERROR.", err=True)
    else:
        click.echo(f"  Cage:        {cfg.cage}")

    if cfg.generative:
        if cfg.attacker_model:
            click.echo(f"  Generative:  attacker = {cfg.attacker_model}  (iters: {cfg.generative_iters})")
        else:
            click.echo("  Warning: --generative set but no --attacker-model; the generative layer will be skipped.", err=True)

    click.echo("  Running drill...\n")
    drill = run_drill(cfg)

    # Per-scenario results
    for f in drill.findings:
        if f.outcome == DrillOutcome.HELD:
            mark = "✅ HELD  "
        elif f.outcome == DrillOutcome.BYPASS:
            sev = f.severity.value if f.severity else ""
            mark = f"❌ BYPASS {sev:<8}"
        else:
            mark = "⚠️  ERROR "
        latency = f"{f.detection_latency_ms:.0f}ms" if f.detection_latency_ms is not None else "—"
        click.echo(f"  {mark}  {f.scenario_id:<18}  {f.scenario_name:<28}  {latency:>7}")
    click.echo()

    scorers_on = [k for k, v in drill.scorers.items() if v]
    emoji = _STATUS_EMOJI.get(drill.status, "⚠️")
    click.echo(f"  Status:      {emoji} {drill.status.value}")
    click.echo(f"  Corpus:      {drill.corpus_version}  (sources: {', '.join(drill.corpus_sources) or '—'})")
    click.echo(f"  Scorers:     {', '.join(scorers_on)}")
    click.echo(f"  Scenarios:   {len(drill.findings)}")
    click.echo(f"  Held:        {len(drill.held)}")
    click.echo(f"  Bypasses:    {len(drill.bypasses)}  (critical: {len(drill.critical_bypasses)})")
    click.echo(f"  Errors:      {len(drill.errors)}")
    click.echo()

    if cfg.report:
        write_markdown_report(drill, cfg.report)
        click.echo(f"  Report:      {cfg.report}")
    if cfg.output:
        write_drill_packet(drill, cfg.output)
        click.echo(f"  DrillReport: {cfg.output}")

    if cfg.blastcontain_url and not cfg.dry_run:
        ok = post_to_ledger(drill, cfg.blastcontain_url)
        click.echo(f"  Posted to:   {cfg.blastcontain_url}" if ok else "  Warning: Ledger POST failed")

    click.echo(f"{'='*60}\n")
    sys.exit(_EXIT.get(drill.status, 3))
