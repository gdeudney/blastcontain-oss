"""Local research provenance. Discovery and classification never imply ratification."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .storage import VERSION, migrate

REVIEW_STATES = ('unreviewed', 'reviewed', 'selected', 'deferred', 'rejected')
IMPLEMENTATION_STATES = ('planned', 'in_progress', 'implemented', 'validated', 'retired')


def fingerprint(paper):
    return hashlib.sha256(json.dumps(asdict(paper), sort_keys=True).encode()).hexdigest()


class Tracker:
    def __init__(self, path, readonly=False):
        path = Path(path).resolve()
        if readonly:
            self.db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
            self.db = sqlite3.connect(path)
        self.readonly = readonly
        self.db.row_factory = sqlite3.Row
        try:
            self.db.execute('PRAGMA foreign_keys=ON')
            self.db.execute('PRAGMA trusted_schema=OFF')
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in range(VERSION + 1) or (readonly and version == 0):
                raise ValueError(f'Unsupported Scout database version: {version}')
            self.version = version if readonly else migrate(self.db)
        except BaseException:
            self.db.close()
            raise

    @property
    def revision(self):
        if self.version < 3:
            return None
        return self.db.execute('SELECT revision FROM tracking_meta WHERE id=1').fetchone()[0]

    @contextmanager
    def _write(self, expected_revision=None):
        if self.readonly:
            raise ValueError('Tracker is read-only')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if expected_revision is not None and (
                type(expected_revision) is not int or expected_revision != self.revision
            ):
                raise ValueError('Scout history changed; reload before applying this edit')
            before = self.db.total_changes
            yield
            if self.db.total_changes != before:
                self.db.execute('UPDATE tracking_meta SET revision=revision+1 WHERE id=1')
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _event(self, pid, action, data):
        self.db.execute('INSERT INTO events(paper_id,recorded_at,action,data) VALUES(?,?,?,?)',
                        (pid, self.now(), action, json.dumps(data, sort_keys=True)))

    @staticmethod
    def now():
        return datetime.now(timezone.utc).isoformat()

    def needs_processing(self, paper):
        row = self.db.execute('SELECT processed_fingerprint FROM papers WHERE id=?',
                              (paper.arxiv_id,)).fetchone()
        return row is None or row[0] != fingerprint(paper)

    def needs_proposal(self, paper):
        if self.version < 2:
            return True
        row = self.db.execute('SELECT proposed_fingerprint FROM papers WHERE id=?',
                              (paper.arxiv_id,)).fetchone()
        return row is None or row[0] != fingerprint(paper)

    def saved_analysis(self, paper):
        from .analyze import Analysis
        row = self.db.execute('''SELECT data FROM analyses WHERE paper_id=? AND fingerprint=?
                              ORDER BY id DESC LIMIT 1''', (paper.arxiv_id, fingerprint(paper))).fetchone()
        if row is None:
            return None
        data = json.loads(row[0])
        data['paper'] = paper
        return Analysis(**data)

    def pending_publication(self, root):
        if self.version < 2:
            return None
        row = self.db.execute('SELECT data FROM pending_publications WHERE repo_root=?',
                              (str(Path(root).resolve()),)).fetchone()
        return json.loads(row[0]) if row else None

    def save_publication(self, root, data):
        with self._write():
            self.db.execute('INSERT OR REPLACE INTO pending_publications VALUES(?,?)',
                            (str(Path(root).resolve()), json.dumps(data, sort_keys=True)))

    def finish_publication(self, root, analyses, reference):
        with self._write():
            for analysis in analyses:
                paper = analysis.paper
                fp = fingerprint(paper)
                # Do not mark a newer metadata revision as proposed by an older draft.
                self.db.execute('''UPDATE papers SET proposed_fingerprint=?
                    WHERE id=? AND fingerprint=?''', (fp, paper.arxiv_id, fp))
                self._event(paper.arxiv_id, 'proposed', {'fingerprint': fp, 'reference': reference})
            self.db.execute('DELETE FROM pending_publications WHERE repo_root=?',
                            (str(Path(root).resolve()),))

    def ingest(self, papers, analyses=()):
        """Atomic, repeatable ingestion; retain decisions and all prior analyses."""
        papers = list(papers)
        with self._write():
            for p in papers:
                fp = fingerprint(p)
                old = self.db.execute('SELECT fingerprint FROM papers WHERE id=?',
                                      (p.arxiv_id,)).fetchone()
                now = self.now()
                self.db.execute('''INSERT INTO papers(id,metadata,fingerprint,first_seen,last_seen)
                    VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                    metadata=excluded.metadata,fingerprint=excluded.fingerprint,
                    last_seen=excluded.last_seen''',
                    (p.arxiv_id, json.dumps(asdict(p)), fp, now, now))
                if old is None or old[0] != fp:
                    self._event(p.arxiv_id, 'discovered' if old is None else 'revision', {'fingerprint': fp})
            for a in analyses:
                fp = fingerprint(a.paper)
                row = self.db.execute('SELECT fingerprint FROM papers WHERE id=?',
                                      (a.paper.arxiv_id,)).fetchone()
                if row is None or row[0] != fp:
                    raise ValueError('Analysis does not match ingested paper revision')
                data = json.dumps(asdict(a), sort_keys=True)
                cur = self.db.execute('''INSERT OR IGNORE INTO analyses
                    (paper_id,fingerprint,recorded_at,data) VALUES(?,?,?,?)''',
                    (a.paper.arxiv_id, fp, self.now(), data))
                self.db.execute('UPDATE papers SET processed_fingerprint=? WHERE id=?',
                                (fp, a.paper.arxiv_id))
                if cur.rowcount:
                    self._event(a.paper.arxiv_id, 'classified', {'fingerprint': fp, 'scored_by': a.scored_by})

    def review(self, pid, status, note, *, actor="legacy-unattributed", expected_revision=None):
        if status not in REVIEW_STATES:
            raise ValueError('Invalid review status')
        if not note.strip() or not actor.strip():
            raise ValueError('A review note and actor are required')
        with self._write(expected_revision):
            cur = self.db.execute('''UPDATE papers SET review_status=?,note=?,
                review_fingerprint=fingerprint WHERE id=?''', (status, note, pid))
            if not cur.rowcount:
                raise ValueError(f'Unknown paper: {pid}')
            self._event(pid, 'review', {'status': status, 'note': note, 'actor': actor,
                'fingerprint': self.db.execute('SELECT fingerprint FROM papers WHERE id=?', (pid,)).fetchone()[0]})

    def link(self, pid, source, status, reference='', tests='', note='', *, actor='legacy-unattributed', expected_revision=None):
        if status not in IMPLEMENTATION_STATES or not source.strip():
            raise ValueError('Valid implementation status and source are required')
        if status in ('implemented', 'validated') and not reference.strip():
            raise ValueError('Implemented work requires a commit or PR reference')
        if status == 'validated' and not tests.strip():
            raise ValueError('Validated work requires test evidence')
        if not actor.strip():
            raise ValueError('An actor is required')
        with self._write(expected_revision):
            row = self.db.execute('SELECT fingerprint FROM papers WHERE id=?', (pid,)).fetchone()
            if not row:
                raise ValueError(f'Unknown paper: {pid}')
            self.db.execute('''INSERT INTO implementations
                (paper_id,source,status,reference,tests,note,updated_at,paper_fingerprint,actor)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(paper_id,source) DO UPDATE SET status=excluded.status,
                reference=excluded.reference,tests=excluded.tests,note=excluded.note,
                updated_at=excluded.updated_at,paper_fingerprint=excluded.paper_fingerprint,
                actor=excluded.actor''', (pid, source, status, reference, tests, note, self.now(), row[0], actor))
            self._event(pid, 'implementation', dict(source=source, status=status,
                        reference=reference, tests=tests, note=note, actor=actor, fingerprint=row[0]))

    def snapshot(self):
        if self.db.in_transaction:
            return self._snapshot()
        self.db.execute('BEGIN')
        try:
            return self._snapshot()
        finally:
            self.db.rollback()

    def _snapshot(self):
        result = {'schema_version': 2, 'database_version': self.version, 'revision': self.revision, 'papers': [], 'analyses': [], 'implementations': [], 'events': []}
        for row in self.db.execute('SELECT * FROM papers ORDER BY id'):
            item = dict(row)
            item['metadata'] = json.loads(item['metadata'])
            item['needs_processing'] = item['fingerprint'] != item['processed_fingerprint']
            item['review_stale'] = bool(item['review_fingerprint'] and item['review_fingerprint'] != item['fingerprint'])
            item['needs_proposal'] = item['fingerprint'] != item.get('proposed_fingerprint')
            result['papers'].append(item)
        queries = {
            'analyses': 'SELECT * FROM analyses ORDER BY id',
            'implementations': 'SELECT * FROM implementations ORDER BY paper_id, source',
            'events': 'SELECT * FROM events ORDER BY id',
        }
        for table, query in queries.items():
            result[table] = [dict(r) for r in self.db.execute(query)]
        fingerprints = {p['id']: p['fingerprint'] for p in result['papers']}
        for item in result['implementations']:
            item['implementation_stale'] = item.get('paper_fingerprint') != fingerprints[item['paper_id']]
            item['evidence_status'] = 'recorded_only'
        result['pending_publications'] = (
            [dict(row) for row in self.db.execute('SELECT * FROM pending_publications ORDER BY repo_root')]
            if self.version >= 2 else []
        )
        return result
