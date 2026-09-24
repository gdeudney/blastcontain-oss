"""Research tracker commands, separate from Scout's backward-compatible scan CLI."""
import json
import sqlite3
from collections import Counter
from pathlib import Path

import click

from .analyze import Analysis
from .arxiv import Paper
from .cli import _default_root
from .tracker import IMPLEMENTATION_STATES, REVIEW_STATES, Tracker


@click.group()
@click.option('--database', type=click.Path(path_type=Path), default=None)
@click.pass_context
def main(ctx, database):
    """Track paper processing, review decisions and Drill implementation evidence."""
    ctx.obj = database or Path(_default_root()) / 'tools/scout/state/scout.sqlite3'


@main.command('import')
@click.argument('papers_file', type=click.Path(exists=True, path_type=Path))
@click.option('--analyses', type=click.Path(exists=True, path_type=Path))
@click.pass_obj
def ingest(database, papers_file, analyses):
    """Import saved Scout paper metadata and optional classifier results."""
    papers = [Paper(**p) for p in json.loads(papers_file.read_text())]
    results = []
    if analyses:
        for raw in json.loads(analyses.read_text()):
            raw['paper'] = Paper(**raw['paper'])
            results.append(Analysis(**raw))
    with Tracker(database) as tracker:
        tracker.ingest(papers, results)
    click.echo(f'Imported {len(papers)} papers and {len(results)} classifications; review states preserved.')


@main.command('import-ledger')
@click.argument('ledger_file', type=click.Path(exists=True, path_type=Path))
@click.pass_obj
def import_ledger(database, ledger_file):
    """Preserve legacy seen dates without claiming papers were reviewed."""
    raw = json.loads(ledger_file.read_text())
    seen = raw.get('seen', raw)
    if not isinstance(seen, dict) or not all(isinstance(v, str) for v in seen.values()):
        raise click.ClickException('Expected an ID-to-date ledger mapping')
    with Tracker(database) as tracker:
        for pid, date in seen.items():
            if tracker.db.execute('SELECT 1 FROM papers WHERE id=?', (pid,)).fetchone():
                continue
            tracker.ingest([Paper(pid, '', '', '', '')])
            with tracker._write():
                tracker.db.execute('UPDATE papers SET first_seen=? WHERE id=?', (date, pid))
                tracker._event(pid, 'legacy_seen', {'date': date})
    click.echo(f'Imported legacy ledger ({len(seen)} entries); metadata-only records still need processing.')


@main.command()
@click.argument('paper_id')
@click.option('--status', type=click.Choice(REVIEW_STATES), required=True)
@click.option('--note', required=True)
@click.option('--actor', default='legacy-unattributed')
@click.option('--expected-revision', type=int)
@click.pass_obj
def review(database, paper_id, status, note, actor, expected_revision):
    """Record a human review decision."""
    try:
        with Tracker(database) as tracker:
            tracker.review(paper_id, status, note, actor=actor, expected_revision=expected_revision)
    except (ValueError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error
    click.echo('Review recorded.')


@main.command()
@click.argument('paper_id')
@click.option('--source', required=True, help='Drill source/module path or feature identifier')
@click.option('--status', type=click.Choice(IMPLEMENTATION_STATES), required=True)
@click.option('--reference', default='', help='Commit or PR reference; required for implemented/validated')
@click.option('--tests', default='', help='Test evidence; required for validated')
@click.option('--note', default='')
@click.option('--actor', default='legacy-unattributed')
@click.option('--expected-revision', type=int)
@click.pass_obj
def link(database, paper_id, source, status, reference, tests, note, actor, expected_revision):
    """Link research to an implementation. Evidence is recorded, not auto-verified."""
    try:
        with Tracker(database) as tracker:
            tracker.link(paper_id, source, status, reference, tests, note, actor=actor, expected_revision=expected_revision)
    except (ValueError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error
    click.echo('Implementation link recorded.')


@main.command()
@click.option('--paper-id', default=None)
@click.option('--json-output', is_flag=True)
@click.pass_obj
def report(database, paper_id, json_output):
    """Show processing/review totals, or a paper's evidence and history."""
    if not database.exists():
        raise click.ClickException('Database does not exist; import a digest or run Scout with --record.')
    with Tracker(database, readonly=True) as tracker:
        data = tracker.snapshot()
    if paper_id:
        data['papers'] = [p for p in data['papers'] if p['id'] == paper_id]
        for table in ('analyses', 'implementations', 'events'):
            data[table] = [r for r in data[table] if r['paper_id'] == paper_id]
        if not data['papers']:
            raise click.ClickException('Unknown paper')
    if json_output or paper_id:
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(f"Database revision: {data['revision']}")
        click.echo(f"Papers: {len(data['papers'])}")
        click.echo(f"Need processing: {sum(p['needs_processing'] for p in data['papers'])}")
        click.echo(f"Stale reviews: {sum(p['review_stale'] for p in data['papers'])}")
        click.echo('Review states: ' + json.dumps(Counter(p['review_status'] for p in data['papers'])))
        click.echo('Recorded implementation states: ' + json.dumps(Counter(p['status'] for p in data['implementations'])))
        click.echo(f"Stale/unbound implementation records: {sum(p['implementation_stale'] for p in data['implementations'])}")


@main.command()
@click.option('--registry', type=click.Path(exists=True, path_type=Path), default=None)
@click.option('--paper-id', default=None)
@click.option('--json-output', is_flag=True)
@click.pass_obj
def coverage(database, registry, paper_id, json_output):
    """Join Drill's paper coverage registry to Scout's local records (read-only)."""
    from .coverage import read_coverage

    registry = registry or Path(_default_root()) / 'drill/blastcontain_drill/corpus/arxiv/registry.json'
    try:
        data = read_coverage(registry, database, paper_id)
    except (OSError, ValueError, KeyError) as error:
        raise click.ClickException(str(error)) from error
    if json_output:
        click.echo(json.dumps(data, indent=2))
        return
    click.echo(f"Drill coverage audit: {data['audited_at']} at {data['main_commit'][:12]}")
    for row in data['entries']:
        click.echo(f"{row['paper_id']}  {row['coverage']}  {row['status'] or 'no implementation claim'}  {row['title']}")
    if data.get('note'):
        click.echo(data['note'])


@main.command()
@click.argument('output', type=click.Path(path_type=Path))
@click.pass_obj
def backup(database, output):
    """Write a consistent private backup to a new path; never overwrite a database."""
    from .storage import copy_database
    try:
        copy_database(database, output)
    except (OSError, ValueError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error
    click.echo('Backup created.')


@main.command()
@click.argument('backup_file', type=click.Path(exists=True, path_type=Path))
@click.argument('output', type=click.Path(path_type=Path))
def restore(backup_file, output):
    """Restore to a NEW database; select it explicitly with --database afterward."""
    from .storage import copy_database
    try:
        copy_database(backup_file, output)
    except (OSError, ValueError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error
    click.echo('Restored to a new database; select it explicitly with --database.')


@main.command('export-audit')
@click.argument('output', type=click.Path(path_type=Path))
@click.pass_obj
def export_audit(database, output):
    """Export complete recorded history; this does not grant execution acceptance."""
    from .storage import export_audit as write_export
    try:
        write_export(database, output)
    except (OSError, ValueError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error
    click.echo('Audit history exported.')


def provenance_api():
    try:
        from . import provenance
    except ImportError as error:
        raise click.ClickException('Provenance commands require Core and Drill from the same supported checkout.') from error
    return provenance


@main.command('inspect-mapping')
@click.option('--repo', type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--commit', required=True, help='Full commit containing the mapping file')
@click.option('--manifest', required=True, help='Repository-relative committed JSON mapping')
@click.option('--main-ref', default='origin/main')
@click.pass_obj
def inspect_mapping(database, repo, commit, manifest, main_ref):
    """Inspect committed identities against current local Git and Scout state; no writes."""
    api = provenance_api()
    try:
        with Tracker(database, readonly=True) as tracker:
            report = api.inspect_mapping(repo, commit, manifest, tracker, main_ref=main_ref)
        click.echo(json.dumps(report, indent=2))
    except (ValueError, OSError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error


@main.command('refresh-mapping')
@click.option('--repo', type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--commit', required=True)
@click.option('--manifest', required=True)
@click.option('--main-ref', default='origin/main')
@click.option('--actor', required=True)
@click.option('--expected-revision', required=True, type=int)
@click.pass_obj
def refresh_mapping(database, repo, commit, manifest, main_ref, actor, expected_revision):
    """Explicitly append a Git-bound workflow snapshot; never accept or enable attacks."""
    api = provenance_api()
    try:
        with Tracker(database) as tracker:
            report = api.inspect_mapping(repo, commit, manifest, tracker, main_ref=main_ref)
            changed = api.refresh_mapping(tracker, report, actor=actor, expected_revision=expected_revision)
            click.echo(json.dumps({'changed': changed, 'revision': tracker.revision, 'report': report}, indent=2))
    except (ValueError, OSError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error


@main.command('trace')
@click.option('--repo', type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--main-ref', default='origin/main')
@click.option('--lock', 'lock_path', type=click.Path(exists=True, path_type=Path), required=True)
@click.option('--run', 'run_path', type=click.Path(exists=True, path_type=Path))
@click.option('--trusted-key', type=click.Path(exists=True, path_type=Path))
@click.option('--allow-advisory', is_flag=True)
@click.option('--scenarios', type=click.Path(exists=True, path_type=Path))
@click.option('--states', type=click.Path(exists=True, path_type=Path))
@click.option('--paper-id')
@click.pass_obj
def trace(database, repo, main_ref, lock_path, run_path, trusted_key, allow_advisory, scenarios, states, paper_id):
    """Trace a lock/run to papers, exact revisions, reviews and committed test records."""
    api = provenance_api()
    from blastcontain_drill.suites.commands import verification_kwargs
    from blastcontain_drill.suites.durable import verify_run
    try:
        options = verification_kwargs(trusted_key, allow_advisory, lock_path, scenarios, states)
        lock = options['lock']
        verification = verify_run(run_path, **options) if run_path else None
        with Tracker(database, readonly=True) as tracker:
            tracker.db.execute('BEGIN')
            try:
                git = api.GitObjects(repo)
                checked_main = git.commit(main_ref)
                checked_revision = tracker.revision
                snapshots = api.latest_mappings(tracker, repo_key=git.key)
                reports = [api.inspect_mapping(repo, r['mapping_commit'], r['manifest_path'], tracker, main_ref=checked_main) for r in snapshots.values()]
            finally:
                tracker.db.rollback()
        result = api.trace_lock(lock, reports, verification=verification, paper_id=paper_id)
        result['checked_database_revision'] = checked_revision
        result['checked_main_commit'] = checked_main
        # Read-only tracing surfaces divergence; refresh is an explicit separate action.
        result['database_divergence'] = [r['mapping_id'] for r in reports if
            {k: v for k, v in r.items() if k != 'main_commit'} !=
            {k: v for k, v in snapshots[r['mapping_id']].items() if k != 'main_commit'}]
        click.echo(json.dumps(result, indent=2))
    except (ValueError, OSError, sqlite3.Error) as error:
        raise click.ClickException(str(error)) from error


if __name__ == '__main__':
    main()
