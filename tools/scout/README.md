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
