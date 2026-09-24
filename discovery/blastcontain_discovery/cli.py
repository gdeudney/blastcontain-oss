"""blastcontain-discovery — CLI entry point."""
from __future__ import annotations

import sys

import click

from .report import write_report
from .scanner import run_discovery


@click.command("blastcontain-discovery")
@click.option("--env", default="prod", help="Environment to classify against.")
@click.option("--search-path", default=".", help="Filesystem path to walk for agents/MCP configs.")
@click.option("--process-scan/--no-process-scan", default=True, help="Scan running processes.")
@click.option("--copilot-scan/--no-copilot-scan", default=True,
              help="Scan for IDE/desktop copilots + MCP wirings.")
@click.option("--blastcontain-url", default=None, envvar="BLASTCONTAIN_URL",
              help="Platform URL for registry cross-reference + Charter derive.")
@click.option("--token", default=None, envvar="BLASTCONTAIN_TOKEN", help="Platform bearer token.")
@click.option("--bootstrap-charter", is_flag=True,
              help="Draft a Charter for each shadow find (derive-then-ratify).")
@click.option("--charter-output-dir", default="./charters", help="Where local draft Charters go.")
@click.option("--report", "report_path", default=None, help="Write a signed report to this path.")
@click.option("--fail-on-shadow/--no-fail-on-shadow", default=True,
              help="Exit 2 when shadow AI is found (CI gate).")
def main(env, search_path, process_scan, copilot_scan, blastcontain_url, token,
         bootstrap_charter, charter_output_dir, report_path, fail_on_shadow):
    """BlastContain Discovery — find the agents you didn't register."""
    click.echo(f"\nBlastContain Discovery  |  env: {env}\n")

    report = run_discovery(
        environment=env,
        search_path=search_path,
        process_scan=process_scan,
        copilot_scan=copilot_scan,
        blastcontain_url=blastcontain_url or "",
        token=token,
        bootstrap_charter=bootstrap_charter,
        charter_output_dir=charter_output_dir,
    )

    s = report.summary()
    click.echo(f"  assets found:     {s['total']}")
    click.echo(f"  registered:       {s['registered']}")
    click.echo(f"  known-unverified: {s['known_unverified']}")
    click.echo(f"  shadow AI:        {s['shadow_ai']}")

    for asset in report.shadow_ai:
        click.echo(f"\n  ⚠ SHADOW: {asset.asset_id}  [{asset.asset_type}]")
        click.echo(f"     location: {asset.location}")
        if asset.mcp_servers:
            click.echo(f"     mcp:      {', '.join(asset.mcp_servers)}")
        if asset.draft_charter_ref:
            click.echo(f"     draft:    {asset.draft_charter_ref}")

    if report_path:
        write_report(report, report_path, sign=True)
        click.echo(f"\n  signed report -> {report_path}")

    click.echo()
    sys.exit(2 if (fail_on_shadow and report.shadow_ai) else 0)


if __name__ == "__main__":  # pragma: no cover
    main()
