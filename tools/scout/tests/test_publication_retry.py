from dataclasses import asdict, replace
import json
from pathlib import Path
import subprocess
from unittest.mock import Mock

from click.testing import CliRunner

from blastcontain_scout.analyze import classify
from blastcontain_scout.arxiv import Paper
from blastcontain_scout.cli import main
from blastcontain_scout.pipeline import ScoutConfig, build_plan
from blastcontain_scout.tracker import Tracker
from blastcontain_scout import repo


def paper():
    return Paper('2601.12345', 'Tool poisoning attack', 'A tool poisoning attack', '2026-01-01', '2026-01-01')


def git(root, *args):
    return subprocess.run(['git', *args], cwd=root, text=True, encoding='utf-8', capture_output=True, check=True).stdout.strip()


def repository(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    git(root, 'init', '-b', 'main')
    git(root, 'config', 'user.email', 'fixture@example.invalid')
    git(root, 'config', 'user.name', 'Fixture')
    (root / 'README.md').write_text('fixture\n')
    git(root, 'add', 'README.md')
    git(root, 'commit', '-m', 'fixture')
    return root


def test_recorded_preview_then_apply_reuses_classification_and_deduplicates(tmp_path, monkeypatch):
    root = repository(tmp_path)
    database = tmp_path / 'research.sqlite3'
    monkeypatch.setattr('blastcontain_scout.pipeline.arxiv_mod.fetch', lambda **kw: [paper()])
    classifier = Mock(wraps=classify)
    monkeypatch.setattr('blastcontain_scout.pipeline.classify', classifier)
    args = ['--repo-root', str(root), '--database', str(database)]
    runner = CliRunner()
    assert runner.invoke(main, args + ['--record']).exit_code == 0
    assert not (root / 'drill/docs/scout').exists()
    before = database.read_bytes()
    assert runner.invoke(main, args).exit_code == 0
    assert database.read_bytes() == before
    result = runner.invoke(main, args + ['--apply'])
    assert result.exit_code == 0, result.output
    assert classifier.call_count == 1
    assert len(list((root / 'drill/docs/scout').glob('digest-*'))) == 1
    with Tracker(database, readonly=True) as tracker:
        assert not tracker.needs_proposal(paper())
        assert tracker.snapshot()['papers'][0]['review_status'] == 'unreviewed'
        assert tracker.pending_publication(root) is None
    head = git(root, 'rev-parse', 'HEAD')
    assert runner.invoke(main, args + ['--apply']).exit_code == 0
    assert git(root, 'rev-parse', 'HEAD') == head


def test_imported_analysis_can_be_proposed_without_reclassification(tmp_path, monkeypatch):
    database = tmp_path / 'research.sqlite3'
    with Tracker(database) as tracker:
        tracker.ingest([paper()], [classify(paper(), ('tool poisoning',))])
    monkeypatch.setattr('blastcontain_scout.pipeline.arxiv_mod.fetch', lambda **kw: [paper()])
    classifier = Mock(side_effect=AssertionError('must reuse saved analysis'))
    monkeypatch.setattr('blastcontain_scout.pipeline.classify', classifier)
    result = build_plan(ScoutConfig(repo_root=str(tmp_path), database=str(database)), '2026-09-20')
    assert result.new == 0 and result.relevant == 1 and result.plan is not None
    classifier.assert_not_called()


def test_failed_commit_retries_exact_draft_without_refetching(tmp_path, monkeypatch):
    root = repository(tmp_path)
    database = tmp_path / 'research.sqlite3'
    fetch = Mock(return_value=[paper()])
    monkeypatch.setattr('blastcontain_scout.pipeline.arxiv_mod.fetch', fetch)
    real_run = repo._run
    fail = True

    def command(args, cwd):
        nonlocal fail
        if args[:2] == ['git', 'commit'] and fail:
            fail = False
            return subprocess.CompletedProcess(args, 1, '', 'controlled commit failure')
        return real_run(args, cwd)

    monkeypatch.setattr(repo, '_run', command)
    args = ['--repo-root', str(root), '--database', str(database), '--apply']
    runner = CliRunner()
    assert runner.invoke(main, args).exit_code == 1
    with Tracker(database, readonly=True) as tracker:
        pending = tracker.pending_publication(root)
        assert pending and tracker.needs_proposal(paper())
    fetch.side_effect = AssertionError('retry must use saved plan, even if feed is unavailable')
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert git(root, 'branch', '--show-current') == pending['plan']['branch']
    assert git(root, 'rev-list', '--count', 'HEAD') == '2'
    assert fetch.call_count == 1


def test_failed_push_reuses_commit_and_retries_pr(tmp_path, monkeypatch):
    root = repository(tmp_path)
    database = tmp_path / 'research.sqlite3'
    monkeypatch.setattr('blastcontain_scout.pipeline.arxiv_mod.fetch', lambda **kw: [paper()])
    real_run = repo._run
    pushes = 0

    def command(args, cwd):
        nonlocal pushes
        if args[:2] == ['git', 'push']:
            pushes += 1
            return subprocess.CompletedProcess(args, 1 if pushes == 1 else 0, '', 'controlled push failure')
        if args[:3] == ['gh', 'pr', 'list']:
            return subprocess.CompletedProcess(args, 0, '[]', '')
        if args[:3] == ['gh', 'pr', 'create']:
            assert '--draft' in args and '--body-file' in args
            assert Path(args[args.index('--body-file') + 1]).read_text(encoding='utf-8')
            return subprocess.CompletedProcess(args, 0, 'https://example.invalid/pr/1\n', '')
        return real_run(args, cwd)

    monkeypatch.setattr(repo, '_run', command)
    args = ['--repo-root', str(root), '--database', str(database), '--open-pr']
    runner = CliRunner()
    first = runner.invoke(main, args)
    assert first.exit_code == 1
    assert 'push failed' in first.output
    head = git(root, 'rev-parse', 'HEAD')
    second = runner.invoke(main, args)
    assert second.exit_code == 0, second.output
    assert git(root, 'rev-parse', 'HEAD') == head
    assert pushes == 2
    with Tracker(database, readonly=True) as tracker:
        assert tracker.pending_publication(root) is None
        assert not tracker.needs_proposal(paper())


def test_retry_refuses_to_overwrite_user_edits(tmp_path, monkeypatch):
    root = repository(tmp_path)
    monkeypatch.setattr('blastcontain_scout.pipeline.arxiv_mod.fetch', lambda **kw: [paper()])
    plan = build_plan(ScoutConfig(repo_root=str(root)), '2026-09-20').plan
    real_run = repo._run
    monkeypatch.setattr(repo, '_run', lambda args, cwd: subprocess.CompletedProcess(args, 1, '', 'failed')
                        if args[:2] == ['git', 'commit'] else real_run(args, cwd))
    assert not repo.publish(plan, str(root), False)['ok']
    changed = Path(plan.files[0].path)
    changed.write_text('user edit')
    monkeypatch.setattr(repo, '_run', real_run)
    assert repo.publish(plan, str(root), False)['step'] == 'resume'
    assert changed.read_text() == 'user edit'


def test_v1_readonly_and_migration_preserve_history(tmp_path):
    database = tmp_path / 'research.sqlite3'
    with Tracker(database) as tracker:
        tracker.ingest([paper()], [classify(paper(), ())])
        tracker.review(paper().arxiv_id, 'selected', 'reviewed methods')
        with tracker.db:
            tracker.db.execute('ALTER TABLE papers DROP COLUMN proposed_fingerprint')
            tracker.db.execute('DROP TABLE pending_publications')
            tracker.db.execute('PRAGMA user_version=1')
    before = database.read_bytes()
    with Tracker(database, readonly=True) as tracker:
        assert tracker.needs_proposal(paper())
        assert tracker.saved_analysis(paper())
    assert database.read_bytes() == before
    with Tracker(database) as tracker:
        assert tracker.version == 3
        assert tracker.snapshot()['papers'][0]['review_status'] == 'selected'
        assert len(tracker.snapshot()['analyses']) == 1


def test_old_pending_proposal_does_not_mark_new_revision_published(tmp_path):
    with Tracker(tmp_path / 'research.sqlite3') as tracker:
        analysis = classify(paper(), ())
        tracker.ingest([paper()], [analysis])
        tracker.save_publication(tmp_path, {'analyses': [asdict(analysis)]})
        newer = replace(paper(), updated='2026-02-01')
        tracker.ingest([newer])
        tracker.finish_publication(tmp_path, [analysis], 'commit:fixture')
        assert tracker.needs_proposal(newer)
        assert json.loads(tracker.db.execute('SELECT metadata FROM papers').fetchone()[0])['updated'] == newer.updated
