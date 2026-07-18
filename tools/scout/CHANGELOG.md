# Changelog

All notable changes to `blastcontain-scout` are documented here. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [semver](https://semver.org).

## [Unreleased]

## [0.1.0] — 2026-07-05

Initial release. Corpus scout for [BlastContain Drill](https://pypi.org/project/blastcontain-drill/) — scans arXiv for new jailbreak / prompt-injection / agent-attack research and opens draft pull requests proposing additions to the Drill corpus. Embodies the derive-then-ratify tenet: Scout *derives* candidate attacks; a human *ratifies* by reviewing the PR.

### Added
- **arXiv pipeline** — `scan → dedupe → classify → render → draft PR` (`blastcontain_scout.pipeline`).
- **arXiv client** (`blastcontain_scout.arxiv`) — queries the public Atom feed for
  `cs.CR / cs.CL / cs.AI / cs.LG`, newest first; no API key. XML parsing hardened via `defusedxml`.
- **Classifier** (`blastcontain_scout.analyze`) — local LM Studio model with a keyword fallback;
  labels each paper `dataset` / `technique` / `intel`, suggests a Drill category (from
  `blastcontain-core` `DRILL_CATEGORIES`), and flags the license.
- **Dedupe ledger** (`blastcontain_scout.ledger`) — JSON ledger at `tools/scout/state/seen-arxiv.json`;
  first-run creation, committed alongside the PR so state travels with the repo.
- **Renderer** (`blastcontain_scout.render`) — a Markdown digest plus inert `AttackSource` scaffolds
  under `drill/blastcontain_drill/corpus/contrib/`; scaffolds' `is_available()` returns `False`
  so `load_corpus` skips them until a maintainer ratifies.
- **CLI** (`blastcontain-scout`) — `--max`, `--model`, `--base-url`, `--threshold`, `--apply`,
  `--open-pr`. `--apply` writes the digest + scaffolds; `--open-pr` also branches, commits, and
  runs `gh pr create`.
- **Publish pipeline** — release workflow (`.github/workflows/release.yml`) now fires on
  `scout-v*` tags and maps the tag prefix to `tools/scout` at build time.

### Notes
- **Derive-then-ratify contract.** Scout opens draft PRs; a maintainer verifies license, vendors
  the data, implements `dataset()`, flips `is_available()`, and registers an `enable_*` flag. Scout
  never auto-touches a security corpus.
- Tooling scope: Scout runs on a schedule (or one-shot), not as part of a Drill scan.
