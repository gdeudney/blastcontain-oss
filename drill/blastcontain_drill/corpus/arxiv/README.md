# arXiv research → Drill coverage

This is Drill's paper-to-implementation registry and the home for future dedicated,
reviewed paper-specific attack sources. `registry.json` joins to Scout's SQLite
tracker by `paper_id` (the versionless arXiv ID). It records 20 audited papers.

Existing working modules stay in place: the registry links to them rather than
copying code. No entry automatically loads a module or enables an attack.

| Location | Purpose |
|---|---|
| `corpus/contrib/arxiv/<YYYY-MM>/c_<id>.py` | Scout-generated inactive proposals, excluded from wheels |
| `corpus/arxiv/registry.json` | Reviewed mapping, implementation scope, references and tests |
| `corpus/arxiv/c_<id>.py` | Convention for future dedicated implementations; none added by this registry |
| `tools/scout/state/scout.sqlite3` | Local discovery, classifier, review and implementation history |

## Coverage and implementation status

Coverage describes what is actually present: `dataset_only`, `partial_method`,
`research_informed_examples`, `not_implemented`, or
`no_paper_specific_implementation_identified`. The last value records a bounded
negative finding, not proof that no equivalent technique exists anywhere.

Status is independent: `implemented`, `validated`, `in_progress`, or null for an
entry without an implementation claim. Validation applies only to the documented
scope. A validated dataset loader is not a reproduced paper benchmark. Two paper
citations may refer to the same four synthetic scenarios; do not count them twice.

Every entry includes its paper title/ID, code or inspected area, source commit/PR,
coverage, relationship, limitations and test evidence. `audited_at`, `main_commit`
and `draft_pr_head` pin the audit: this file does not automatically refresh when a
PR merges. The draft MCP module may not exist on main yet; its PR is the reference.

## Scout lookup

From a source checkout with Scout installed:

```bash
blastcontain-scout-track coverage
blastcontain-scout-track coverage --paper-id 2404.01318 --json-output
```

The command combines registry coverage with local processing/review information
and database implementation records, without modifying either. A paper absent
from the registry is **not audited**, not **not implemented**. Database links and
registry records are shown separately if they differ; neither silently overrides
the other. Use `--registry PATH` for a registry in another checkout.

## Adding an implementation

1. Keep the Scout candidate inactive while reviewing the method and artifact license.
2. Implement a narrowly scoped source or extend an existing one; retain source attribution.
3. Add tests of payload delivery and observable effects, plus benign utility cases.
4. Register the source behind an explicit opt-in flag in the existing corpus loader.
5. Add/update its registry entry and evidence. Use `blastcontain-scout-track link`
   to record local implementation progress against the same paper ID.

The registry is data, not an execution manifest. Never import modules or execute
commands from it. External attack tools are considered in
[`drill/docs/open-source-integrations.md`](../../../docs/open-source-integrations.md).
