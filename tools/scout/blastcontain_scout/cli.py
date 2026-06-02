"""BlastContain Scout — CLI. Default run is a safe dry-run preview."""
from __future__ import annotations

import datetime
import sys
from pathlib import Path

import click

from .pipeline import ScoutConfig, build_plan
from .repo import preview, publish


def _default_root() -> str:
    """Repo root: prefer git toplevel (robust to where the package lives), else walk up."""
    import subprocess

    here = Path(__file__).resolve().parent
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=str(here), capture_output=True, text=True,
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return str(here.parents[2])   # blastcontain_scout -> scout -> tools -> <root>


@click.command()
@click.option("--repo-root", default=None, help="Repo root to open the PR against (default: the monorepo)")
@click.option("--base-branch", default="main", help="Base branch for the PR (default: main)")
@click.option("--max", "max_results", default=50, type=int, help="Max arXiv results to scan (newest first)")
@click.option("--model", default=None, help="LM Studio model id for classification (omit = keyword heuristic)")
@click.option("--base-url", default="http://localhost:1234/v1", help="OpenAI-compatible base URL")
@click.option("--threshold", default=0.5, type=float, help="Relevance threshold 0..1 (default 0.5)")
@click.option("--ledger", default=None, help="Path to the seen-ledger JSON (relative to repo root)")
@click.option("--apply", is_flag=True, default=False, help="Write files + commit on a new branch (default: dry-run)")
@click.option("--open-pr", is_flag=True, default=False, help="Also push and open the PR via gh (implies --apply)")
def main(repo_root, base_branch, max_results, model, base_url, threshold, ledger, apply, open_pr):
    """Scan arXiv for new jailbreak/agent-attack papers and draft a PR to feed the Drill corpus."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass

    root = repo_root or _default_root()
    today = datetime.date.today().isoformat()
    cfg = ScoutConfig(
        repo_root=root, base_branch=base_branch, max_results=max_results,
        threshold=threshold, base_url=base_url, model=model,
        ledger_path=ledger or ScoutConfig.ledger_path,
    )

    click.echo("=" * 60)
    click.echo(f"  BlastContain Scout  |  arXiv jailbreak watch  |  {today}")
    click.echo("=" * 60)
    click.echo(f"  Classifier:  {model or 'keyword heuristic (no model)'}")

    result = build_plan(cfg, today)
    click.echo(f"  Scanned:     {result.scanned}   New: {result.new}   Relevant: {result.relevant}")
    click.echo()

    for a in sorted([x for x in result.analyses if x.relevant], key=lambda x: -x.relevance):
        click.echo(f"  [{a.kind:9}] {a.relevance:.2f}  arXiv:{a.paper.arxiv_id}  {a.paper.title[:70]}")
    click.echo()

    if result.plan is None:
        click.echo(f"  {result.note}. Nothing to propose.")
        return

    if not apply and not open_pr:
        click.echo(preview(result.plan, root))
        return

    res = publish(result.plan, root, open_pr=open_pr)
    if not res.get("ok"):
        click.echo(f"  ✗ failed at {res.get('step')}: {res.get('error')}")
        raise SystemExit(1)
    click.echo(f"  ✓ branch {res['branch']} — committed {len(res['committed'])} file(s)")
    if res.get("pr"):
        click.echo(f"  ✓ PR: {res['pr']}")
    elif res.get("pr_error"):
        click.echo(f"  ⚠ PR not opened: {res['pr_error']}")
    elif open_pr:
        click.echo("  ⚠ PR step skipped.")


if __name__ == "__main__":
    main()
