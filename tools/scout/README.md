# BlastContain Scout

A **separate, scheduled agent** that scans arXiv for new jailbreak / prompt-injection /
LLM-agent-attack research and opens a **draft pull request** proposing additions to the Drill
corpus. It embodies BlastContain's **derive-then-ratify** tenet: the scout *derives* candidate
attacks; a human *ratifies* by reviewing the PR. It never auto-touches a security corpus.

## How it works

```
arXiv API ─▶ dedupe (seen-ledger) ─▶ classify ─▶ render ─▶ draft PR
            (only new papers)        dataset/    digest +   (you review
                                     technique/  inert       & merge)
                                     intel        scaffolds
```

1. **Scan** — query the arXiv API (no key) for recent `cs.CR/cs.CL/cs.AI/cs.LG` papers matching
   jailbreak / prompt-injection / agent-attack terms, newest first.
2. **Dedupe** — skip anything already in `tools/scout/state/seen-arxiv.json` (committed, so the state
   travels with the repo).
3. **Classify** — a local LM Studio model (or a keyword fallback) labels each paper
   **dataset** / **technique** / **intel**, suggests a Drill category, and flags the license.
4. **Render** — a markdown **digest** plus, for each dataset/technique paper, an **inert
   `AttackSource` scaffold** under `drill/.../corpus/contrib/` whose `is_available()` returns
   `False` (so `load_corpus` skips it until ratified — the PR is safe to merge).
5. **Draft PR** — branch, commit, `gh pr create`. You review, verify the license, vendor the
   data, implement `dataset()`, flip availability, and register it with an `enable_*` flag.

## Install

```powershell
# from blastcontain-oss/
pip install -e tools/scout
# or run without installing:
python -m blastcontain_scout --help     # (run from the tools/scout/ directory)
```

Requires `git` and an authenticated `gh` CLI for `--open-pr`. For LLM classification, LM Studio
must be serving a model on `:1234`.

## Usage

```powershell
# Dry-run preview — no writes, no git (the default; start here):
blastcontain-scout --max 50

# Use a local model for richer classification:
blastcontain-scout --model "qwen/qwen3-30b-a3b-2507"

# Write the digest + scaffolds and commit on a new branch:
blastcontain-scout --model "qwen/qwen3-30b-a3b-2507" --apply

# ...and push + open the draft PR:
blastcontain-scout --model "qwen/qwen3-30b-a3b-2507" --open-pr
```

| Flag | Meaning |
|---|---|
| `--max N` | arXiv results to scan (newest first) |
| `--model ID` | LM Studio model id for classification (omit → keyword heuristic) |
| `--base-url URL` | OpenAI-compatible endpoint (default `http://localhost:1234/v1`) |
| `--threshold 0..1` | relevance cutoff (default 0.5) |
| `--apply` | write files + commit on a new branch |
| `--open-pr` | also push + open the PR via `gh` (implies `--apply`) |

## Ratifying a proposal (the human half)

A merged scaffold is **inert**. To turn it into a live source:
1. **Verify the license** permits vendoring (Apache / MIT / BSD — reject Llama-Community,
   gated datasets, JAILJUDGE-style).
2. Vendor the data (pin the commit) or implement `dataset()` to load it.
3. Flip `is_available()` to a real check and set `revision` to the dataset version.
4. Register the source in `corpus/__init__.py` behind an `enable_*` flag.

## Schedule it (Windows Task Scheduler)

Run weekly against your local bench. Save a wrapper `run-scout.ps1`:

```powershell
# run-scout.ps1 — assumes LM Studio is serving the model
Set-Location "C:\Users\deudn\blastcontain-oss\tools\scout"
python -m blastcontain_scout --model "qwen/qwen3-30b-a3b-2507" --open-pr *>> "$env:USERPROFILE\scout.log"
```

Register a weekly task (Mondays 09:00):

```powershell
schtasks /Create /TN "BlastContain arXiv Scout" /SC WEEKLY /D MON /ST 09:00 `
  /TR "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\deudn\blastcontain-oss\tools\scout\run-scout.ps1"
```

The task only ever opens a **draft PR** — nothing reaches the corpus without your review.

## Research database: processed, reviewed, implemented

Scout can keep a local SQLite database at `tools/scout/state/scout.sqlite3`.
SQLite ships with Python; no database service or new dependency is required.
The existing scan command and JSON ledger remain compatible. Plain scans remain
read-only; `--record` explicitly saves paper metadata and classifier results:

```bash
blastcontain-scout --max 200 --record
blastcontain-scout-track report
```

Once a database exists, scans reuse unchanged papers' recorded classifications.
Classification does not consume proposal eligibility: recorded previews and imported
analyses can still be published with `--apply` or `--open-pr`. Successful publication
marks only the exact paper revision as proposed, without changing its review or
implementation status. Existing version-1 databases are read without modification
by previews and upgraded additively on the next write; old publication state is
unknown and is not inferred from classification or the legacy seen ledger.

Publishing saves an exact pending draft in the database before Git changes. A failed
commit, push or PR creation can be retried with the same command, including on a later
day or while arXiv is unavailable. Retry reuses the original branch and any completed
commit; it refuses unrelated changes or edits to the proposal files. Keep the same
checkout and database for retries. `--apply` and `--open-pr` also record classifications
and publication state; ordinary previews remain read-only. A pending draft is retried
before fetching newer papers. Once complete, the next scan resumes normal discovery.
Successful `--apply` means committed locally; `--open-pr` requires a PR URL before
marking the draft published. External pushes and PR creation still require those flags.

Discovery alone does not count as processing. Changed paper metadata is reprocessed;
prior analyses, review decisions and implementation links remain available. A changed
paper marks an existing review stale until it is reviewed again. This tracks observed
metadata revisions, not a complete arXiv version history. The normal scan still fetches
only `--max` newest results; it does not provide historical pagination.

Import saved research, including the catch-up artifacts:

```bash
blastcontain-scout-track import docs/demos/scout-catchup-2026-09-20/papers.json \
  --analyses docs/demos/scout-catchup-2026-09-20/analyses.json
blastcontain-scout-track import-ledger tools/scout/state/seen-arxiv.json
```

Both imports are repeatable. Legacy seen dates do not imply classification or human
review. Import the legacy ledger first when preserving its original first-seen dates
is important. Without a database, the original JSON ledger still controls deduplication.

Record review decisions separately from implementation progress:

```bash
blastcontain-scout-track review 2609.18217 --status selected \
  --note "Abstract reviewed; reproduce fragmented-channel attacks before adoption"
blastcontain-scout-track link 2609.18217 \
  --source drill/blastcontain_drill/corpus/example.py --status planned \
  --note "Proposed scenario; no implementation yet"
blastcontain-scout-track report --paper-id 2609.18217
```

Review states: `unreviewed`, `reviewed`, `selected`, `deferred`, `rejected`.
Implementation states: `planned`, `in_progress`, `implemented`, `validated`, `retired`.
One paper can link to multiple sources, and a source can cite multiple papers.
`implemented` and `validated` require `--reference` (PR or commit); `validated` also
requires `--tests` describing test evidence. References are recorded attestations:
the tracker does not check GitHub merge state, inspect referenced files, run tests,
verify licenses, or enable any corpus. Use `in_progress` for an unmerged draft PR.
An implementation link never changes the paper's review state automatically.

Use `blastcontain-scout-track --database /path/to/scout.sqlite3 ...` for a shared
location across local checkouts. Scout scanning accepts the same `--database` option.
Binary databases and journal files are gitignored. Keep the database on local disk.
Use the recovery commands for a consistent SQLite backup, including committed WAL
pages while the database is open:

```bash
blastcontain-scout-track backup scout-backup.sqlite3
blastcontain-scout-track restore scout-backup.sqlite3 scout-restored.sqlite3
blastcontain-scout-track --database scout-restored.sqlite3 report
blastcontain-scout-track export-audit scout-history.json
```

Outputs must be new paths. Restore does not replace an active database; select the
restored copy explicitly. New database/backup/export files use private permissions
on Unix. Backups retain pending publication retries as well as paper metadata,
analyses, review events and implementation annotations. The JSON audit snapshot is
portable history, not a restore format or an execution acceptance file. Pending
publication data can include local paths and unpublished draft text.

Version 3 migrations commit their DDL and version change in one transaction, roll
back together on failure, and preserve old versions for read-only previews. Old
implementation rows keep their original claims but have unknown actor/revision;
those fields are not inferred. New `review` and `link` commands accept `--actor`.
Omitting it preserves compatibility and records `legacy-unattributed`. Implementation
annotations bind the current paper fingerprint and become stale when metadata
changes. `evidence_status: recorded_only` remains explicit even when the supplied
status is `validated`; this does not independently verify a test or PR.

For concurrent editing, read `revision` from `report --json-output`, then supply
`--expected-revision N` to `review` or `link`. A changed database refuses the edit
and asks you to reload. Without that option, legacy commands apply to the latest
state. Snapshot schema 2 adds `database_version`, `revision`, implementation
staleness/actor fields and pending publication history. No cloud sync or
scheduled monitoring is enabled. `--record` only records processing; it does not publish
the generated proposal. Review/import/link commands do not commit or push anything.

### Map Scout papers to Drill coverage

Drill now has a data-only paper registry at
`drill/blastcontain_drill/corpus/arxiv/registry.json`, seeded from the 20-paper
implementation audit. Inspect it alongside the local database:

```bash
blastcontain-scout-track coverage
blastcontain-scout-track coverage --paper-id 2404.01318 --json-output
```

`--registry PATH` selects another checkout's mapping. This lookup is read-only:
it keeps checked-in audit claims and local implementation records separate.
A missing registry entry means **not audited**, not **not implemented**.
Scout proposals still go to `corpus/contrib/arxiv/<YYYY-MM>/`; reviewed dedicated
implementations can live under `corpus/arxiv/`. Existing working modules are linked
in place. Registry entries never enable attacks or import code automatically.
