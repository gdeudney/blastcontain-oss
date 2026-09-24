# Git-bound research provenance (phase 5B)

Scout can now join papers to exact Drill sources, scenarios, plugins, review records
and code/test/license artifacts in Git. It can then trace a locked suite or verified
run in either direction. It never imports attack code, enables a plugin, grants an
acceptance, fetches a repository or reruns a recorded test.

Install Core, Drill and Scout from the same checkout to use these optional commands.
Ordinary Scout scans, legacy tracking and database recovery retain their independent
dependency set. The optional integration requires the Python version supported by
Drill (currently 3.11 or later).

## What is authoritative

- A committed `ResearchMap` records source snapshots, exact plugin manifests,
  selected scenario IDs, paper fingerprints, limited coverage, artifact hashes,
  license review and separate content/plugin acceptance histories.
- Current local Git objects are checked against an explicit main reference. An
  unmerged mapping, changed artifact, changed source/plugin scope, revoked acceptance,
  unknown/changed paper metadata or unresolved license review remains visible.
- SQLite stores append-only refresh events with an actor. It does not replace Git
  or choose whichever copy has the newer timestamp. Tracing rechecks Git and reports
  `database_divergence`; only `refresh-mapping` changes the recorded snapshot.
- A suite still requires its own exact plan acceptance through Drill. Research
  metadata is not a run permit. Unchanged accepted suites do not require repeated
  approvals because a database exists or an unrelated paper was discovered.
- Run signatures, model/Agent graphs and evidence replay use Drill's existing
  verifier. A missing replay input remains unreplayed; a self-signed advisory result
  does not become operator-trusted through a research citation.

Coverage is declared and reviewed separately from validation. Supported labels are
`dataset_only`, `partial_method`, `research_informed_examples`, and
`full_reproduction`. The last requires a separate committed comparison protocol in
addition to code, validation and license artifacts. File integrity cannot establish
semantic equivalence to a paper; the review must justify that claim. The output
therefore labels test material `committed_records_not_independently_rerun`.

## Author a mapping

First commit the implementation, test results or validation record, and applicable
license files. A mapping points to that **earlier full commit ID**, which avoids a
self-referential file hash. Commit the resulting mapping afterward. Keep its source,
plugin metadata and acceptance histories identical to the reviewed suite inputs.
Never put credentials, sensitive traces or raw customer content in Git.

The schema is defined by `blastcontain_scout.provenance.ResearchMap`; it is strict
JSON and rejects unknown fields, duplicate keys, path traversal and unsupported
coverage shapes. A creation example, after preparing/reviewing the bounded PyRIT
inputs and importing the actual paper metadata into Scout:

```python
from pathlib import Path
from blastcontain_drill.contracts import PluginManifest
from blastcontain_drill.plugins.catalog import parse_json, read_acceptances
from blastcontain_drill.suites.catalog import SourceSnapshot
from blastcontain_scout.provenance import (
    ArtifactRef, CoverageReview, GitObjects, PaperRef, ResearchMap,
)
from blastcontain_scout.storage import exclusive_output
from blastcontain_scout.tracker import Tracker
import hashlib
import json

repo = GitObjects(Path.cwd())
code_revision = repo.commit("origin/main")  # Explicit local reference; no fetch.
inputs = Path("crescendo-review")
source = SourceSnapshot.from_dict(parse_json((inputs / "source.json").read_bytes()))
plugin = PluginManifest.from_dict(parse_json((inputs / "pyrit.drill-plugin.json").read_bytes()))
records = tuple(r for r in read_acceptances(inputs / "content-decisions.json")
                if r.kind in ("content", "plugin"))
with Tracker("tools/scout/state/scout.sqlite3", readonly=True) as tracker:
    paper = next(p for p in tracker.snapshot()["papers"] if p["id"] == "2404.01833")

# The validation record must already exist in the chosen commit. Include all code,
# dependency/build inputs and license artifacts relevant to the reviewed claim.
paths = [
    ("drill/plugins/pyrit/crescendo.py", "code"),
    ("drill/plugins/pyrit/crescendo_templates.py", "code"),
    ("drill/plugins/pyrit/requirements.lock", "code"),
    ("drill/plugins/pyrit/Containerfile.crescendo", "code"),
    ("path/to/committed-validation-record.json", "validation"),
    ("drill/LICENSE", "license"),
    ("drill/plugins/pyrit/LICENSE.pyrit", "license"),
]
files = tuple(ArtifactRef(path, hashlib.sha256(repo.blob(code_revision, path)).hexdigest(), kind)
              for path, kind in paths)
mapping = ResearchMap(
    id="pyrit.crescendo.original",
    papers=(PaperRef(paper["id"], paper["fingerprint"]),),
    source=source, plugins=(plugin,), scenario_ids=tuple(s.id for s in source.scenarios),
    code_revision=code_revision, files=files, coverage="partial_method",
    limitations="Native bounded algorithm with original templates; no paper benchmark or live efficacy reproduction.",
    review=CoverageReview("Gordon", "Reviewed the stated scope and original payload license",
                          "Apache-2.0", "reviewed"),
    acceptances=records,
)
with exclusive_output("crescendo.research-map.json") as (stream, _):
    json.dump(mapping.to_dict(), stream, indent=2)
```

The example intentionally requires your real validation record, paper fingerprint,
accepted image and review history. It does not invent reusable approvals or imply
that rebuilding an image will produce the same digest. A different operator can
inspect the same committed inputs and reproduce the documented build/review process;
a changed image requires the normal new acceptance.

Mappings support up to 32 papers, 128 committed files, and 2 MiB per file. Git reads
are local, bounded and limited to regular blob entries at full commit IDs. Files
are hashed as committed bytes, independent of working-tree line endings. Historical
artifacts whose current-main bytes changed are stale even if the old file still exists.

## Inspect and explicitly refresh

After committing the mapping and fetching Git yourself when appropriate:

```sh
blastcontain-scout-track inspect-mapping --repo . \
  --commit <full-mapping-commit> --manifest path/to/crescendo.research-map.json
blastcontain-scout-track report --json-output
blastcontain-scout-track refresh-mapping --repo . \
  --commit <full-mapping-commit> --manifest path/to/crescendo.research-map.json \
  --actor Gordon --expected-revision <revision-from-report>
```

`--main-ref` defaults to the local `origin/main`; set it explicitly for another
reference. A draft mapping can be recorded as unmerged workflow state, but cannot
be reported as current merged evidence. Refresh after merge explicitly. Repeating
the same snapshot creates no duplicate event. Missing cited paper metadata causes
the whole refresh to roll back. Concurrent database changes reject stale edits.
A stale/unresolved record is retained as such rather than silently discarded.

## Trace a suite or saved run

```sh
blastcontain-scout-track trace --repo . --lock accepted.lock.json
blastcontain-scout-track trace --repo . --lock accepted.lock.json \
  --run drill-runs/<run-id> --trusted-key operator-public.key
blastcontain-scout-track trace --repo . --lock accepted.lock.json \
  --paper-id 2404.01833
```

Adaptive replay accepts the same `--scenarios` and `--states` files as Drill's
verifier. `--allow-advisory` is explicit when checking an advisory run. No model,
plugin or target is executed during tracing.

Each case exposes source/scenario/plugin identities, matching papers, coverage,
code and mapping commits, artifact hashes, reviews, stale diagnostics, and the
verified case result when available. `identity_matches` compares exact source
content/code/revision and selected plugin review digests. Merely sharing an ID or
including a plugin elsewhere in the suite is insufficient.

`run_security_passed` describes the run's verified security result.
`provenance_complete` separately requires at least one traced case and a current,
identity-matching mapping for each displayed case. An empty or unmapped selection
cannot produce complete provenance. Neither field upgrades the other.

Paper metadata revisions, capability changes and revocations are checked against
fresh local Git/Scout state. `database_divergence` identifies a changed snapshot;
this read-only command does not reaccept a suite or rewrite a stored review. Backups
and audit exports preserve refresh history through the existing Scout recovery
commands. Restoring in a different clone requires an explicit refresh there.
