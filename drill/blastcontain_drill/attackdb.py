"""
Effective-attack database (drill-spec §8) — a local, queryable catalogue of attacks
that ACTUALLY bypassed a target.

SENSITIVE: these are working jailbreak prompts against named models. The DB file and the
`*.attacks.jsonl` capture sidecars are gitignored — never commit or share them. The
*article* should use aggregates (`stats`) and excerpts, not the raw prompts.

A row is one (prompt, target) bypass, deduped (hit_count bumps on re-discovery), tagged
with the technique / operator / language so you can ask "which encodings or languages
beat which models?". Records are produced by `jailbreak_study` runs (which reconstruct
the effective prompt from the corpus + the generative jailbreaks sidecar) and ingested
here.

    python -m blastcontain_drill.attackdb stats --db study/attacks.db
    python -m blastcontain_drill.attackdb query --db study/attacks.db --operator morse
    python -m blastcontain_drill.attackdb query --db study/attacks.db --model qwen3.6 --min-severity HIGH
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone

import click

# Operator names the corpus encodes into an attack's `technique` (corpus/operators.py).
# The last "/"-segment of a technique matching one of these is the obfuscation used.
_OPERATORS = frozenset({
    "base64", "leetspeak", "many_shot", "persona", "payload_split", "prefix_injection",
    "multilingual", "rot13", "caesar", "atbash", "morse", "binary", "url_encode",
    "reverse", "char_space", "zero_width", "homoglyph",
})

_SEVERITY_RANK = {"LOW": 1, "HIGH": 2, "CRITICAL": 3}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id             TEXT PRIMARY KEY,
    attack_key     TEXT,
    prompt         TEXT NOT NULL,
    excerpt        TEXT,
    category       TEXT,
    technique      TEXT,
    operator       TEXT,
    language       TEXT,
    goal           TEXT,
    layer          TEXT,
    severity       TEXT,
    target_model   TEXT,
    attacker_model TEXT,
    judge_model    TEXT,
    guard_model    TEXT,
    scorer         TEXT,
    evidence       TEXT,
    source         TEXT,
    first_seen     TEXT,
    last_seen      TEXT,
    hit_count      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_attacks_operator ON attacks(operator);
CREATE INDEX IF NOT EXISTS idx_attacks_language ON attacks(language);
CREATE INDEX IF NOT EXISTS idx_attacks_target   ON attacks(target_model);
CREATE INDEX IF NOT EXISTS idx_attacks_key      ON attacks(attack_key);
"""


def parse_operator(technique: str) -> tuple:
    """
    (operator, language) from an attack `technique`. The multilingual operator maps to a
    language tag; a `language:<code>` segment (the future any-language operator) sets the
    language directly. Returns (operator_or_None, language).
    """
    parts = [p.strip() for p in (technique or "").split("/") if p.strip()]
    operator = next((p for p in reversed(parts) if p in _OPERATORS), None)
    language = "en"
    for p in parts:
        if p.startswith(("language:", "lang:")):
            language = p.split(":", 1)[1] or "en"
    if operator == "multilingual" and language == "en":
        language = "fr"   # the current single multilingual framing is French
    return operator, language


def make_id(prompt: str, target_model: str) -> str:
    """Row identity = (prompt, target): the same attack against another model is a new row."""
    return hashlib.sha256(f"{target_model}\x00{prompt}".encode()).hexdigest()[:16]


def make_attack_key(prompt: str) -> str:
    """Attack identity across models = the prompt alone (groups one attack's per-model rows)."""
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    # Migrate DBs created before attack_key existed.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(attacks)").fetchall()}
    if "attack_key" not in cols:
        conn.execute("ALTER TABLE attacks ADD COLUMN attack_key TEXT")
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def upsert(conn: sqlite3.Connection, rec: dict, now: str = "") -> bool:
    """Insert a bypass, or bump hit_count/last_seen if already known. Returns True if new."""
    now = now or _now()
    prompt = rec.get("prompt") or ""
    target = rec.get("target_model") or ""
    if not prompt:
        return False
    rid = make_id(prompt, target)
    operator, language = parse_operator(rec.get("technique", ""))
    operator = rec.get("operator") or operator
    language = rec.get("language") or language
    if conn.execute("SELECT 1 FROM attacks WHERE id=?", (rid,)).fetchone():
        conn.execute(
            "UPDATE attacks SET hit_count = hit_count + 1, last_seen = ? WHERE id = ?",
            (now, rid),
        )
        conn.commit()
        return False
    conn.execute(
        "INSERT INTO attacks (id, attack_key, prompt, excerpt, category, technique, operator,"
        " language, goal, layer, severity, target_model, attacker_model, judge_model,"
        " guard_model, scorer, evidence, source, first_seen, last_seen, hit_count)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
        (
            rid, make_attack_key(prompt), prompt, prompt[:160], rec.get("category"),
            rec.get("technique"), operator, language, rec.get("goal"), rec.get("layer"),
            rec.get("severity"), target, rec.get("attacker_model"), rec.get("judge_model"),
            rec.get("guard_model"), rec.get("scorer"), (rec.get("evidence") or "")[:300],
            rec.get("source"), now, now,
        ),
    )
    conn.commit()
    return True


def ingest_records(conn: sqlite3.Connection, records, now: str = "") -> tuple:
    """Upsert many records. Returns (new, seen_again)."""
    now = now or _now()
    new = seen = 0
    for rec in records:
        if upsert(conn, rec, now):
            new += 1
        else:
            seen += 1
    return new, seen


def query(conn, operator=None, language=None, model=None, category=None,
          min_severity=None, limit=50):
    sql = ["SELECT * FROM attacks WHERE 1=1"]
    args: list = []
    if operator:
        sql.append("AND operator = ?")
        args.append(operator)
    if language:
        sql.append("AND language = ?")
        args.append(language)
    if model:
        sql.append("AND target_model LIKE ?")
        args.append(f"%{model}%")
    if category:
        sql.append("AND category = ?")
        args.append(category)
    if min_severity:
        floor = _SEVERITY_RANK.get(min_severity.upper(), 0)
        keep = [s for s, r in _SEVERITY_RANK.items() if r >= floor]
        sql.append(f"AND severity IN ({','.join('?' for _ in keep)})")
        args.extend(keep)
    sql.append("ORDER BY hit_count DESC, last_seen DESC LIMIT ?")
    args.append(limit)
    # Fragments are module-constant literals; every value is a bound parameter (?).
    return conn.execute(" ".join(sql), args).fetchall()


# Explicit per-column GROUP BY queries — literal SQL (no interpolation), so the stats
# aggregation can never be an injection vector and needs no nosec.
_GROUP_QUERIES = {
    "by_operator": "SELECT operator AS k, COUNT(*) AS n FROM attacks GROUP BY operator ORDER BY n DESC",
    "by_language": "SELECT language AS k, COUNT(*) AS n FROM attacks GROUP BY language ORDER BY n DESC",
    "by_target": "SELECT target_model AS k, COUNT(*) AS n FROM attacks GROUP BY target_model ORDER BY n DESC",
    "by_category": "SELECT category AS k, COUNT(*) AS n FROM attacks GROUP BY category ORDER BY n DESC",
    "by_severity": "SELECT severity AS k, COUNT(*) AS n FROM attacks GROUP BY severity ORDER BY n DESC",
}


def stats(conn) -> dict:
    out = {"total": conn.execute("SELECT COUNT(*) AS n FROM attacks").fetchone()["n"]}
    for key, sql in _GROUP_QUERIES.items():
        out[key] = [(r["k"], r["n"]) for r in conn.execute(sql).fetchall()]
    return out


# Literal SQL per matrix dimension (no interpolation → bandit-clean, injection-safe).
_MATRIX_QUERIES = {
    "operator": "SELECT COALESCE(operator,'(plain)') AS r, target_model AS m, COUNT(*) AS n FROM attacks GROUP BY operator, target_model",
    "technique": "SELECT technique AS r, target_model AS m, COUNT(*) AS n FROM attacks GROUP BY technique, target_model",
    "category": "SELECT category AS r, target_model AS m, COUNT(*) AS n FROM attacks GROUP BY category, target_model",
    "language": "SELECT language AS r, target_model AS m, COUNT(*) AS n FROM attacks GROUP BY language, target_model",
}


def matrix(conn, by: str = "operator") -> dict:
    """{row_key: {target_model: bypass_count}} — an attack dimension × the model it beat."""
    sql = _MATRIX_QUERIES.get(by)
    if sql is None:
        raise ValueError(f"matrix dimension must be one of {sorted(_MATRIX_QUERIES)}")
    out: dict = {}
    for row in conn.execute(sql).fetchall():
        out.setdefault(row["r"], {})[row["m"]] = row["n"]
    return out


def coverage(conn, operator=None, language=None, model=None, limit=30) -> list:
    """Per individual attack (by attack_key): the target models it bypassed + severity."""
    rows = query(conn, operator=operator, language=language, model=model, limit=100000)
    by_attack: dict = {}
    for r in rows:
        entry = by_attack.setdefault(r["attack_key"], {
            "excerpt": r["excerpt"], "operator": r["operator"], "language": r["language"],
            "technique": r["technique"], "models": [],
        })
        entry["models"].append((r["target_model"], r["severity"]))
    return sorted(by_attack.values(), key=lambda e: -len(e["models"]))[:limit]


# ── CLI ──────────────────────────────────────────────────────────────────────
@click.group()
def main():
    """Query the effective-attack database (SENSITIVE — local only, gitignored)."""


@main.command("ingest")
@click.option("--db", required=True, help="SQLite DB path")
@click.argument("jsonl", nargs=-1, required=True)
def ingest_cmd(db, jsonl):
    """Ingest one or more *.attacks.jsonl capture sidecars into the DB."""
    conn = connect(db)
    total_new = total_seen = 0
    for path in jsonl:
        with open(path, encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh if line.strip()]
        n, s = ingest_records(conn, records)
        total_new += n
        total_seen += s
        click.echo(f"  {path}: +{n} new, {s} already known")
    click.echo(f"Total: +{total_new} new, {total_seen} seen again.")


@main.command("query")
@click.option("--db", required=True)
@click.option("--operator", default=None, help="e.g. morse | base64 | homoglyph")
@click.option("--language", default=None, help="e.g. fr | sw")
@click.option("--model", default=None, help="target model substring")
@click.option("--category", default=None)
@click.option("--min-severity", default=None, type=click.Choice(["LOW", "HIGH", "CRITICAL"]))
@click.option("--limit", default=50, type=int)
def query_cmd(db, operator, language, model, category, min_severity, limit):
    """List effective attacks matching the filters (prompts shown as excerpts)."""
    conn = connect(db)
    rows = query(conn, operator=operator, language=language, model=model,
                 category=category, min_severity=min_severity, limit=limit)
    if not rows:
        click.echo("No matching attacks.")
        return
    for r in rows:
        head = (r["excerpt"] or "").splitlines()[0][:80] if r["excerpt"] else ""
        click.echo(f"[{(r['severity'] or '—'):8}] {(r['operator'] or r['layer'] or '—'):12} "
                   f"{(r['language'] or ''):4} -> {r['target_model']:26} x{r['hit_count']}  {head}")
    click.echo(f"\n{len(rows)} attack(s).")


@main.command("stats")
@click.option("--db", required=True)
def stats_cmd(db):
    """Aggregate bypass counts (the article tables) — no raw prompts."""
    conn = connect(db)
    s = stats(conn)
    click.echo(f"Effective attacks: {s['total']}\n")
    for title, key in [("By operator", "by_operator"), ("By language", "by_language"),
                       ("By target", "by_target"), ("By category", "by_category"),
                       ("By severity", "by_severity")]:
        click.echo(f"{title}:")
        for k, n in s[key]:
            click.echo(f"  {str(k or '—'):28} {n}")
        click.echo("")


@main.command("matrix")
@click.option("--db", required=True)
@click.option("--by", default="operator",
              type=click.Choice(["operator", "technique", "category", "language"]))
def matrix_cmd(db, by):
    """Which attacks bypass which models — a <by> × target-model bypass grid."""
    conn = connect(db)
    m = matrix(conn, by)
    if not m:
        click.echo("No attacks recorded yet.")
        return
    models = sorted({mdl for row in m.values() for mdl in row})
    click.echo(f"{by} × target model — bypass counts (0 = held, or not tested vs that model):\n")
    click.echo(f"  {'':16} " + "  ".join(f"[{i}]" for i, _ in enumerate(models)))
    for r in sorted(m, key=str):
        cells = "  ".join(f"{m[r].get(mdl, 0):>3}" for mdl in models)
        click.echo(f"  {str(r):16} {cells}")
    click.echo("\n  models: " + " · ".join(f"[{i}] {mdl}" for i, mdl in enumerate(models)))


@main.command("coverage")
@click.option("--db", required=True)
@click.option("--operator", default=None, help="filter to one obfuscation, e.g. morse")
@click.option("--language", default=None)
@click.option("--model", default=None)
@click.option("--limit", default=30, type=int)
def coverage_cmd(db, operator, language, model, limit):
    """Per individual attack: which target models it bypassed (not every attack hits every model)."""
    conn = connect(db)
    items = coverage(conn, operator=operator, language=language, model=model, limit=limit)
    if not items:
        click.echo("No matching attacks.")
        return
    for e in items:
        head = (e["excerpt"] or "").splitlines()[0][:58] if e["excerpt"] else ""
        mods = ", ".join(f"{mdl}({sev or '—'})" for mdl, sev in e["models"])
        click.echo(f"[{e['operator'] or e['technique'] or '—'}] {head}")
        click.echo(f"      → {mods}")
    click.echo(f"\n{len(items)} distinct attack(s).")


if __name__ == "__main__":
    main()
