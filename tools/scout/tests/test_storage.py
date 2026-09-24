"""Real SQLite migrations, concurrent reviews and restore round trips."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import threading

from click.testing import CliRunner
import pytest

from blastcontain_scout.analyze import classify
from blastcontain_scout.arxiv import Paper
from blastcontain_scout.storage import BASE_TABLES, copy_database, exclusive_output, export_audit, migrate
from blastcontain_scout.tracker import Tracker
from blastcontain_scout.tracking_cli import main


def paper():
    return Paper('2601.12345', '<script>hostile title</script>', 'text as data', '2026-01-01', '2026-01-01')


def seeded(path):
    with Tracker(path) as tracker:
        tracker.ingest([paper()], [classify(paper(), ())])
        tracker.review(paper().arxiv_id, 'selected', 'read method', actor='Gordon')
        tracker.link(paper().arxiv_id, 'source.one', 'validated', 'commit:claimed', 'recorded test', actor='Gordon')
        tracker.save_publication(path.parent, {'branch': 'pending', 'note': 'preserve retry'})
        return tracker.snapshot()


def legacy(path, version):
    with sqlite3.connect(path) as db:
        for sql in BASE_TABLES:
            db.execute(sql)
        if version == 2:
            db.execute('ALTER TABLE papers ADD COLUMN proposed_fingerprint TEXT')
            db.execute('CREATE TABLE pending_publications(repo_root TEXT PRIMARY KEY,data TEXT NOT NULL)')
        db.execute('PRAGMA user_version=' + str(version))
        db.execute('INSERT INTO papers(id,metadata,fingerprint,first_seen,last_seen) VALUES(?,?,?,?,?)', ('2601.12345', '{}', 'old', 'then', 'then'))
        db.execute('INSERT INTO implementations VALUES(?,?,?,?,?,?,?)', ('2601.12345', 'source.old', 'validated', 'PR 1', 'claimed test', 'note', 'then'))


@pytest.mark.parametrize('version', [1, 2])
def test_atomic_migration_preserves_legacy_without_inventing_actor_or_revision(tmp_path, version):
    path = tmp_path / 'legacy.sqlite3'
    legacy(path, version)
    before = path.read_bytes()
    with Tracker(path, readonly=True) as tracker:
        assert tracker.version == version
        assert tracker.snapshot()['implementations'][0]['implementation_stale']
    assert path.read_bytes() == before
    with Tracker(path) as tracker:
        assert tracker.version == 3 and tracker.revision == 0
        row = tracker.snapshot()['implementations'][0]
        assert row['actor'] is None and row['paper_fingerprint'] is None
        assert row['evidence_status'] == 'recorded_only' and row['implementation_stale']
        assert row['status'] == 'validated'


def test_migration_failure_rolls_back_all_ddl_and_version(tmp_path):
    path = tmp_path / 'legacy.sqlite3'
    legacy(path, 1)

    class FailedVersion(sqlite3.Connection):
        def execute(self, statement, *args):
            if statement == 'PRAGMA user_version=3':
                raise sqlite3.OperationalError('injected migration failure')
            return super().execute(statement, *args)

    db = sqlite3.connect(path, factory=FailedVersion)
    with pytest.raises(sqlite3.OperationalError):
        migrate(db)
    db.close()
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA user_version').fetchone()[0] == 1
        assert 'proposed_fingerprint' not in {r[1] for r in db.execute('PRAGMA table_info(papers)')}
        assert not db.execute("SELECT name FROM sqlite_master WHERE name='tracking_meta'").fetchone()
        assert db.execute('SELECT count(*) FROM implementations').fetchone()[0] == 1
    with Tracker(path) as tracker:
        assert tracker.version == 3


def test_concurrent_reviews_have_one_winner_and_preserve_the_winning_event(tmp_path):
    path = tmp_path / 'research.sqlite3'
    seeded(path)
    with Tracker(path, readonly=True) as tracker:
        revision = tracker.revision
    barrier = threading.Barrier(2)

    def edit(actor):
        with Tracker(path) as tracker:
            barrier.wait(timeout=5)
            try:
                tracker.review(paper().arxiv_id, 'reviewed', actor, actor=actor, expected_revision=revision)
            except ValueError as error:
                assert 'reload' in str(error)
                return False
            return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(edit, ['first', 'second'])) == [False, True]
    with Tracker(path, readonly=True) as tracker:
        snapshot = tracker.snapshot()
        assert tracker.revision == revision + 1
        reviews = [json.loads(e['data']) for e in snapshot['events'] if e['action'] == 'review']
        assert len(reviews) == 2 and reviews[-1]['actor'] == snapshot['papers'][0]['note']
        assert reviews[-1]['fingerprint'] == snapshot['papers'][0]['fingerprint']


def test_metadata_revision_marks_implementation_annotation_stale(tmp_path):
    path = tmp_path / 'research.sqlite3'
    seeded(path)
    with Tracker(path) as tracker:
        assert not tracker.snapshot()['implementations'][0]['implementation_stale']
        tracker.ingest([replace(paper(), summary='new method')])
        snapshot = tracker.snapshot()
        assert snapshot['papers'][0]['review_stale']
        assert snapshot['implementations'][0]['implementation_stale']
        assert snapshot['implementations'][0]['evidence_status'] == 'recorded_only'
        assert snapshot['implementations'][0]['actor'] == 'Gordon'


def test_backup_and_restore_preserve_history_pending_work_and_wal_commits(tmp_path):
    path, backup, restored = (tmp_path / name for name in ('research.sqlite3', 'backup.sqlite3', 'restored.sqlite3'))
    seeded(path)
    with Tracker(path) as writer:
        writer.db.execute('PRAGMA journal_mode=WAL')
        writer.review(paper().arxiv_id, 'deferred', 'Latest committed WAL review', actor='Gordon')
        snapshot = writer.snapshot()
        assert Path(str(path) + '-wal').exists()
        copy_database(path, backup)
    copy_database(backup, restored)
    with Tracker(restored, readonly=True) as tracker:
        assert tracker.snapshot() == snapshot
    exported = tmp_path / 'audit.json'
    export_audit(restored, exported)
    assert json.loads(exported.read_text()) == snapshot
    if os.name != 'nt':
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in (path, backup, restored, exported))


def test_restore_never_overwrites_running_database_or_follows_destination_links(tmp_path):
    path, backup = tmp_path / 'live.sqlite3', tmp_path / 'backup.sqlite3'
    seeded(path)
    copy_database(path, backup)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        copy_database(backup, path)
    assert path.read_bytes() == before
    link = tmp_path / 'link.sqlite3'
    try:
        link.symlink_to(tmp_path / 'absent.sqlite3')
    except OSError:
        pytest.skip('Host does not permit symlink creation')
    with pytest.raises(FileExistsError):
        copy_database(backup, link)
    assert not (tmp_path / 'absent.sqlite3').exists()


def test_unknown_corrupt_or_failed_backup_never_leaves_a_restore_candidate(tmp_path, monkeypatch):
    future = tmp_path / 'future.sqlite3'
    with sqlite3.connect(future) as db:
        db.execute('PRAGMA user_version=99')
    output = tmp_path / 'output.sqlite3'
    with pytest.raises(ValueError):
        copy_database(future, output)
    assert not output.exists()
    corrupt = tmp_path / 'corrupt.sqlite3'
    corrupt.write_text('not SQLite')
    with pytest.raises(sqlite3.DatabaseError):
        copy_database(corrupt, output)
    assert not output.exists()
    path = tmp_path / 'live.sqlite3'
    seeded(path)

    def fail_fsync(*args):
        raise OSError('simulated disk failure')

    monkeypatch.setattr(os, 'fsync', fail_fsync)
    with pytest.raises(OSError):
        copy_database(path, output)
    assert not output.exists()
    with Tracker(path, readonly=True) as tracker:
        assert tracker.snapshot()['papers']


def test_cli_backup_restore_export_and_conflict_message(tmp_path):
    path = tmp_path / 'live.sqlite3'
    seeded(path)
    runner = CliRunner()
    args = ['--database', str(path)]
    backup, restored, exported = (tmp_path / name for name in ('backup.sqlite3', 'restored.sqlite3', 'history.json'))
    assert runner.invoke(main, args + ['backup', str(backup)]).exit_code == 0
    assert runner.invoke(main, args + ['restore', str(backup), str(restored)]).exit_code == 0
    assert runner.invoke(main, args + ['export-audit', str(exported)]).exit_code == 0
    assert json.loads(exported.read_text())['pending_publications']
    result = runner.invoke(main, args + ['review', paper().arxiv_id, '--status', 'reviewed', '--note', 'stale', '--actor', 'Gordon', '--expected-revision', '0'])
    assert result.exit_code != 0
    assert 'reload' in result.output
    assert runner.invoke(main, args + ['restore', str(backup), str(path)]).exit_code != 0


def test_output_publication_rejects_racing_file_without_overwriting_it(tmp_path):
    output = tmp_path / 'history.json'
    with pytest.raises(FileExistsError):
        with exclusive_output(output) as (stream, _):
            stream.write('draft snapshot')
            assert not output.exists()
            output.write_text('concurrent owner')
    assert output.read_text() == 'concurrent owner'
    assert not tuple(tmp_path.glob('.scout-*'))
