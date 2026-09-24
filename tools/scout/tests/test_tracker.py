from dataclasses import replace
import json

import pytest
from click.testing import CliRunner

from blastcontain_scout.analyze import classify
from blastcontain_scout.arxiv import Paper
from blastcontain_scout.pipeline import ScoutConfig, build_plan
from blastcontain_scout.tracker import Tracker
from blastcontain_scout.tracking_cli import main


def paper():
    return Paper('2601.12345', 'Tool poisoning', 'A tool poisoning attack', '2026-01-01', '2026-01-01')


def test_revision_keeps_review_and_implementation_but_requires_reprocessing(tmp_path):
    p = paper()
    with Tracker(tmp_path / 'research.sqlite3') as db:
        db.ingest([p], [classify(p, ('tool poisoning',))])
        db.review(p.arxiv_id, 'selected', 'Review complete; reproduce first')
        db.link(p.arxiv_id, 'drill/source.py', 'validated', 'commit:abc', 'test run 12 passed')
        assert not db.needs_processing(p)
        revised = replace(p, updated='2026-02-01', summary='Changed method')
        db.ingest([revised])
        snapshot = db.snapshot()
        assert db.needs_processing(revised)
        assert snapshot['papers'][0]['review_stale']
        assert snapshot['papers'][0]['review_status'] == 'selected'
        assert snapshot['implementations'][0]['status'] == 'validated'
        assert len(snapshot['analyses']) == 1
        db.ingest([revised], [classify(revised, ('tool poisoning',))])
        assert len(db.snapshot()['analyses']) == 2
        assert not db.needs_processing(revised)
        assert db.snapshot()['papers'][0]['review_stale']


def test_import_idempotence_and_atomic_failure(tmp_path):
    p = paper()
    a = classify(p, ('tool poisoning',))
    with Tracker(tmp_path / 'research.sqlite3') as db:
        db.ingest([p], [a])
        before = db.snapshot()
        db.ingest([p], [a])
        assert len(db.snapshot()['events']) == len(before['events'])
        assert len(db.snapshot()['analyses']) == 1
        other = replace(p, arxiv_id='2601.99999')
        with pytest.raises(ValueError):
            db.ingest([other], [classify(replace(other, summary='wrong revision'), ())])
        assert len(db.snapshot()['papers']) == 1


def test_evidence_and_unknown_paper_validation(tmp_path):
    with Tracker(tmp_path / 'research.sqlite3') as db:
        db.ingest([paper()])
        for status, reference, tests in [('implemented', '', ''), ('validated', 'PR 1', '')]:
            with pytest.raises(ValueError):
                db.link(paper().arxiv_id, 'drill/x.py', status, reference, tests)
        with pytest.raises(ValueError):
            db.review('missing', 'selected', 'note')
        with pytest.raises(ValueError):
            db.link('missing', 'drill/x.py', 'planned')
        assert db.snapshot()['implementations'] == []


def test_pipeline_preview_no_writes_and_record_deduplication(tmp_path, monkeypatch):
    p = paper()
    monkeypatch.setattr('blastcontain_scout.pipeline.arxiv_mod.fetch', lambda **kw: [p])
    path = tmp_path / 'db.sqlite3'
    cfg = ScoutConfig(repo_root=str(tmp_path), database=str(path))
    assert build_plan(cfg, '2026-09-20').new == 1
    assert not path.exists()
    cfg.record = True
    assert build_plan(cfg, '2026-09-20').new == 1
    cfg.record = False
    before = path.read_bytes()
    repeated = build_plan(cfg, '2026-09-20')
    assert repeated.new == 0 and repeated.plan is not None
    assert path.read_bytes() == before
    with Tracker(path, readonly=True) as db:
        assert db.snapshot()['papers'][0]['review_status'] == 'unreviewed'


def test_discovery_alone_does_not_skip_classification(tmp_path):
    with Tracker(tmp_path / 'db.sqlite3') as db:
        db.ingest([paper()])
        assert db.needs_processing(paper())


def test_cli_legacy_and_readonly_report(tmp_path):
    runner = CliRunner()
    path = tmp_path / 'db.sqlite3'
    args = ['--database', str(path)]
    assert runner.invoke(main, args + ['report']).exit_code != 0
    assert not path.exists()
    ledger = tmp_path / 'ledger.json'
    ledger.write_text(json.dumps({'seen': {'2601.12345': '2026-01-02'}}))
    assert runner.invoke(main, args + ['import-ledger', str(ledger)]).exit_code == 0
    result = runner.invoke(main, args + ['report', '--json-output'])
    row = json.loads(result.output)['papers'][0]
    assert row['first_seen'] == '2026-01-02'
    assert row['review_status'] == 'unreviewed'
    assert row['needs_processing']
    assert runner.invoke(main, args + ['import-ledger', str(ledger)]).exit_code == 0
    assert len(json.loads(runner.invoke(main, args + ['report', '--json-output']).output)['papers']) == 1


def test_cli_import_review_link_export(tmp_path):
    from dataclasses import asdict

    runner = CliRunner()
    p = paper()
    papers = tmp_path / 'papers.json'
    analyses = tmp_path / 'analyses.json'
    papers.write_text(json.dumps([asdict(p)]))
    analyses.write_text(json.dumps([asdict(classify(p, ('tool poisoning',)))]))
    args = ['--database', str(tmp_path / 'tracker.sqlite3')]
    assert runner.invoke(main, args + ['import', str(papers), '--analyses', str(analyses)]).exit_code == 0
    assert runner.invoke(main, args + ['review', p.arxiv_id, '--status', 'selected', '--note', 'Read methods']).exit_code == 0
    assert runner.invoke(main, args + ['link', p.arxiv_id, '--source', 'drill/source.py', '--status', 'validated', '--reference', 'commit:123', '--tests', 'test run 1']).exit_code == 0
    assert runner.invoke(main, args + ['import', str(papers), '--analyses', str(analyses)]).exit_code == 0
    result = runner.invoke(main, args + ['report', '--paper-id', p.arxiv_id])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data['analyses']) == 1
    assert data['papers'][0]['review_status'] == 'selected'
    assert data['implementations'][0]['tests'] == 'test run 1'


def test_future_schema_rejected_without_changes(tmp_path):
    import sqlite3

    path = tmp_path / 'future.sqlite3'
    with sqlite3.connect(path) as conn:
        conn.execute('PRAGMA user_version=99')
    before = path.read_bytes()
    with pytest.raises(ValueError, match='Unsupported'):
        Tracker(path)
    assert path.read_bytes() == before


def test_implementation_many_to_many_and_event_history(tmp_path):
    p = paper()
    other = replace(p, arxiv_id='2601.22222')
    with Tracker(tmp_path / 'tracker.sqlite3') as db:
        db.ingest([p, other])
        db.link(p.arxiv_id, 'drill/a.py', 'planned')
        db.link(other.arxiv_id, 'drill/a.py', 'planned')
        db.link(p.arxiv_id, 'drill/b.py', 'planned')
        db.link(p.arxiv_id, 'drill/a.py', 'implemented', 'commit:abc')
        snapshot = db.snapshot()
        assert len(snapshot['implementations']) == 3
        assert len([e for e in snapshot['events'] if e['action'] == 'implementation']) == 4
