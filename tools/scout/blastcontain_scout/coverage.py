"""Join a data-only Drill registry to local Scout records; never load attack code."""
import json
import re
from pathlib import Path

from .tracker import Tracker

COVERAGE = {
    'dataset_only', 'partial_method', 'research_informed_examples',
    'not_implemented', 'no_paper_specific_implementation_identified',
}


def read_coverage(registry, database=None, paper_id=None):
    data = json.loads(Path(registry).read_text(encoding='utf-8'))
    if data.get('schema_version') != 1 or not isinstance(data.get('entries'), list):
        raise ValueError('Unsupported Drill registry schema')
    seen = set()
    for entry in data['entries']:
        pid = entry.get('paper_id', '')
        if not re.fullmatch(r'\d{4}\.\d{4,5}', pid) or pid in seen:
            raise ValueError('Invalid or duplicate paper ID in Drill registry')
        seen.add(pid)
        if entry.get('coverage') not in COVERAGE:
            raise ValueError('Invalid coverage classification')
        if not all(isinstance(entry.get(k), str) and entry[k].strip()
                   for k in ('title', 'source', 'reference', 'tests', 'relationship', 'details')):
            raise ValueError('Registry entry lacks audit evidence')
        if entry.get('status') not in (None, 'implemented', 'validated', 'in_progress'):
            raise ValueError('Invalid implementation status')
        if entry['coverage'] in ('not_implemented', 'no_paper_specific_implementation_identified') and entry['status'] is not None:
            raise ValueError('Negative coverage cannot claim an implementation status')
    snapshot = {'papers': [], 'implementations': []}
    if database and Path(database).exists():
        with Tracker(database, readonly=True) as tracker:
            snapshot = tracker.snapshot()
    papers = {p['id']: p for p in snapshot['papers']}
    result = {k: data[k] for k in ('schema_version', 'audited_at', 'main_commit', 'draft_pr_head')}
    result['entries'] = []
    for entry in data['entries']:
        if paper_id and entry['paper_id'] != paper_id:
            continue
        paper = papers.get(entry['paper_id'])
        result['entries'].append({**entry, 'scout': None if paper is None else {
            'needs_processing': paper['needs_processing'], 'review_status': paper['review_status'],
            'review_stale': paper['review_stale'],
            'implementation_records': [r for r in snapshot['implementations'] if r['paper_id'] == entry['paper_id']],
        }})
    if paper_id and not result['entries']:
        result['note'] = 'Paper has not been audited in this registry; implementation status is unknown.'
    return result
