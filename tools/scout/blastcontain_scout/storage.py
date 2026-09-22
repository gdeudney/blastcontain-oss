"""Transactional Scout migrations and explicit, non-overwriting recovery artifacts."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import tempfile

VERSION = 3

BASE_TABLES = (
    '''CREATE TABLE IF NOT EXISTS papers (
        id TEXT PRIMARY KEY, metadata TEXT NOT NULL, fingerprint TEXT NOT NULL,
        processed_fingerprint TEXT, review_fingerprint TEXT,
        review_status TEXT NOT NULL DEFAULT 'unreviewed', note TEXT NOT NULL DEFAULT '',
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)''',
    '''CREATE TABLE IF NOT EXISTS analyses (
        id INTEGER PRIMARY KEY, paper_id TEXT NOT NULL REFERENCES papers(id),
        fingerprint TEXT NOT NULL, recorded_at TEXT NOT NULL, data TEXT NOT NULL,
        UNIQUE(paper_id, fingerprint, data))''',
    '''CREATE TABLE IF NOT EXISTS implementations (
        paper_id TEXT NOT NULL REFERENCES papers(id), source TEXT NOT NULL,
        status TEXT NOT NULL, reference TEXT NOT NULL, tests TEXT NOT NULL,
        note TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY(paper_id, source))''',
    '''CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY, paper_id TEXT NOT NULL REFERENCES papers(id),
        recorded_at TEXT NOT NULL, action TEXT NOT NULL, data TEXT NOT NULL)''',
)


def migrate(db):
    """DDL and version update commit together; competing writers re-read under lock."""
    db.execute('BEGIN IMMEDIATE')
    try:
        version = db.execute('PRAGMA user_version').fetchone()[0]
        if version not in range(VERSION + 1):
            raise ValueError(f'Unsupported Scout database version: {version}')
        if version < VERSION:
            for statement in BASE_TABLES:
                db.execute(statement)
            columns = {row[1] for row in db.execute('PRAGMA table_info(papers)')}
            if 'proposed_fingerprint' not in columns:
                db.execute('ALTER TABLE papers ADD COLUMN proposed_fingerprint TEXT')
            db.execute('''CREATE TABLE IF NOT EXISTS pending_publications (
                repo_root TEXT PRIMARY KEY, data TEXT NOT NULL)''')
            columns = {row[1] for row in db.execute('PRAGMA table_info(implementations)')}
            if 'paper_fingerprint' not in columns:
                db.execute('ALTER TABLE implementations ADD COLUMN paper_fingerprint TEXT')
            if 'actor' not in columns:
                db.execute('ALTER TABLE implementations ADD COLUMN actor TEXT')
            # Never infer the revision or actor of old implementation annotations.
            db.execute('''CREATE TABLE IF NOT EXISTS tracking_meta (
                id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=0))''')
            db.execute('INSERT OR IGNORE INTO tracking_meta VALUES(1,0)')
            db.execute('PRAGMA user_version=3')
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return VERSION


@contextmanager
def exclusive_output(path, *, binary=False):
    """Publish a complete private file atomically without replacing an existing name."""
    path = Path(path).absolute()
    if any(parent.is_symlink() or getattr(parent.lstat(), 'st_file_attributes', 0) & 0x400
           for parent in path.parents):
        raise ValueError('Output parent must not be a symlink or reparse point')
    if path.exists() or path.is_symlink():
        raise FileExistsError('Output already exists')
    fd, temporary_name = tempfile.mkstemp(prefix='.scout-', dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, 'wb' if binary else 'w', **({} if binary else {'encoding': 'utf-8'})) as stream:
            yield stream, temporary
            stream.flush()
            os.fsync(stream.fileno())
        # Unlike Windows CRT O_EXCL, link publication cannot follow a dangling
        # destination symlink. It also rejects a concurrently created file.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def copy_database(source, destination):
    """Snapshot a valid database, including committed WAL pages, to a new private file.

    Restore uses the same operation. The caller chooses a new path and then changes
    --database explicitly; a running database is never overwritten or migrated here.
    """
    from .tracker import Tracker

    destination = Path(destination).absolute()
    with Tracker(source, readonly=True) as tracker:
        if tracker.db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('Scout database integrity check failed')
        if tracker.db.execute('PRAGMA foreign_key_check').fetchone() is not None:
            raise ValueError('Scout database has broken references')
        tracker.snapshot()  # Verify expected data shape before creating the output.
        with exclusive_output(destination, binary=True) as (_, temporary):
            output = sqlite3.connect(temporary)
            try:
                tracker.db.backup(output)
            finally:
                output.close()
    return destination


def export_audit(source, destination):
    """Portable history export, not an execution acceptance file or a restore format."""
    from .tracker import Tracker

    with Tracker(source, readonly=True) as tracker:
        snapshot = tracker.snapshot()
    with exclusive_output(destination) as (stream, _):
        json.dump(snapshot, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write('\n')
