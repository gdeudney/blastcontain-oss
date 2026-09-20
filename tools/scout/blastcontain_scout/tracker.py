"""Local research provenance. Discovery and classification never imply ratification."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

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
            self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        version = self.db.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1, 2) or (readonly and version == 0):
            self.db.close()
            raise ValueError(f'Unsupported Scout database version: {version}')
        if not readonly:
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS papers (
                    id TEXT PRIMARY KEY, metadata TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    processed_fingerprint TEXT, review_fingerprint TEXT,
                    review_status TEXT NOT NULL DEFAULT 'unreviewed', note TEXT NOT NULL DEFAULT '',
                    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY, paper_id TEXT NOT NULL REFERENCES papers(id),
                    fingerprint TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL,
                    UNIQUE(paper_id, fingerprint, data));
                CREATE TABLE IF NOT EXISTS implementations (
                    paper_id TEXT NOT NULL REFERENCES papers(id), source TEXT NOT NULL,
                    status TEXT NOT NULL, reference TEXT NOT NULL, tests TEXT NOT NULL,
                    note TEXT NOT NULL, updated_at TEXT NOT NULL,
                    PRIMARY KEY(paper_id, source));
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY, paper_id TEXT NOT NULL REFERENCES papers(id),
                    recorded_at TEXT NOT NULL, action TEXT NOT NULL, data TEXT NOT NULL);
            ''')
            with self.db:
                columns = {r[1] for r in self.db.execute('PRAGMA table_info(papers)')}
                if 'proposed_fingerprint' not in columns:
                    self.db.execute('ALTER TABLE papers ADD COLUMN proposed_fingerprint TEXT')
                self.db.execute('''CREATE TABLE IF NOT EXISTS pending_publications (
                    repo_root TEXT PRIMARY KEY, data TEXT NOT NULL)''')
                self.db.execute('PRAGMA user_version=2')
        self.version = 2 if not readonly else version

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
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO pending_publications VALUES(?,?)',
                            (str(Path(root).resolve()), json.dumps(data, sort_keys=True)))

    def finish_publication(self, root, analyses, reference):
        with self.db:
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
        with self.db:
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

    def review(self, pid, status, note):
        if status not in REVIEW_STATES:
            raise ValueError('Invalid review status')
        if not note.strip():
            raise ValueError('A review note is required')
        with self.db:
            cur = self.db.execute('''UPDATE papers SET review_status=?,note=?,
                review_fingerprint=fingerprint WHERE id=?''', (status, note, pid))
            if not cur.rowcount:
                raise ValueError(f'Unknown paper: {pid}')
            self._event(pid, 'review', {'status': status, 'note': note})

    def link(self, pid, source, status, reference='', tests='', note=''):
        if status not in IMPLEMENTATION_STATES or not source.strip():
            raise ValueError('Valid implementation status and source are required')
        if status in ('implemented', 'validated') and not reference.strip():
            raise ValueError('Implemented work requires a commit or PR reference')
        if status == 'validated' and not tests.strip():
            raise ValueError('Validated work requires test evidence')
        with self.db:
            if not self.db.execute('SELECT 1 FROM papers WHERE id=?', (pid,)).fetchone():
                raise ValueError(f'Unknown paper: {pid}')
            self.db.execute('''INSERT INTO implementations VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(paper_id,source) DO UPDATE SET status=excluded.status,
                reference=excluded.reference,tests=excluded.tests,note=excluded.note,
                updated_at=excluded.updated_at''', (pid, source, status, reference, tests, note, self.now()))
            self._event(pid, 'implementation', dict(source=source, status=status,
                        reference=reference, tests=tests, note=note))

    def snapshot(self):
        result = {'schema_version': 1, 'papers': [], 'analyses': [], 'implementations': [], 'events': []}
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
        return result
