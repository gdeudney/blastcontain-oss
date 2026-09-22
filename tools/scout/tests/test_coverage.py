import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from blastcontain_scout.arxiv import Paper
from blastcontain_scout.coverage import read_coverage
from blastcontain_scout.tracker import Tracker
from blastcontain_scout.tracking_cli import main

REGISTRY = Path(__file__).resolve().parents[3] / 'drill/blastcontain_drill/corpus/arxiv/registry.json'


def test_registry_covers_audit_without_enabling_attacks(tmp_path):
    missing_db = tmp_path / 'absent.sqlite3'
    data = read_coverage(REGISTRY, missing_db)
    assert len(data['entries']) == 21
    entries = {r['paper_id']: r for r in data['entries']}
    assert entries['2404.01318']['coverage'] == 'dataset_only'
    assert entries['2312.02119']['status'] is None
    assert entries['2508.14925']['status'] == 'validated'
    assert entries['2406.13352']['coverage'] == 'partial_method'
    assert entries['2406.13352']['status'] == 'validated'
    assert all(r['scout'] is None for r in data['entries'])
    assert not missing_db.exists()


def test_join_is_readonly_and_keeps_registry_and_local_status_distinct(tmp_path):
    path = tmp_path / 'db.sqlite3'
    with Tracker(path) as db:
        db.ingest([Paper('2404.01318', 'JBB', '', '', '')])
        db.link('2404.01318', 'local/source.py', 'planned')
    before = path.read_bytes()
    row = read_coverage(REGISTRY, path, '2404.01318')['entries'][0]
    assert row['status'] == 'validated'
    assert row['scout']['implementation_records'][0]['status'] == 'planned'
    assert row['scout']['needs_processing']
    assert before == path.read_bytes()


def test_unknown_is_unaudited_not_unimplemented():
    data = read_coverage(REGISTRY, paper_id='2601.99999')
    assert data['entries'] == []
    assert 'unknown' in data['note']


@pytest.mark.parametrize('change', ['duplicate', 'missing_evidence', 'contradiction'])
def test_registry_rejects_invalid_evidence(tmp_path, change):
    data = json.loads(REGISTRY.read_text())
    if change == 'duplicate':
        data['entries'].append(data['entries'][0])
    elif change == 'missing_evidence':
        data['entries'][0]['tests'] = ''
    else:
        data['entries'][0]['coverage'] = 'not_implemented'
    path = tmp_path / 'registry.json'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        read_coverage(path)


def test_coverage_cli_without_database(tmp_path):
    result = CliRunner().invoke(main, ['--database', str(tmp_path/'missing.sqlite3'),
        'coverage', '--registry', str(REGISTRY), '--paper-id', '2312.02119', '--json-output'])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)['entries'][0]['coverage'] == 'not_implemented'
