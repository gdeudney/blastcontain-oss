# Suite planning and locking (phase 3A)

`blastcontain-drill-suite plan` resolves a suite into a complete case roster before
anything executes. `check-lock` checks a saved lock against current planning inputs
and local decisions. Both commands are offline: no model calls, plugin imports,
worker launches, runtime probes, package installs or image pulls.

This guide covers the offline planning boundary. A `ready` case means its declared
planning requirements are satisfied, **not** that it ran, passed a security check or
has a functioning runtime. See the [suite CLI walkthrough](suite-cli.md) for
explicit acceptance, execution and verification.
[Evidence authority and offline reduction](evidence-reduction.md) are available as an
additive API in 3B. [Fixture execution and shared budgets](suite-execution.md) are available
as a development API in 3C/3D, including adaptive execution and in-memory cancellation.
[Durable cancellation and signing](suite-runs.md) are available as services in 3E.
The [3F suite CLI](suite-cli.md) exposes these services.
The existing Drill CLI and local abliterated attacker remain unchanged.

## First plan

From the repository root after installing Drill:

```sh
blastcontain-drill-suite plan drill/examples/suites/agent.json --output agent-plan.json
blastcontain-drill-suite plan drill/examples/suites/mcp.json --output mcp-plan.json
```

The Agent example expands to 28 cases: 14 built-in scenarios at two seeds. The MCP
example expands to four controlled description/response poisoning cases. The MCP
target is an agent consuming fixture MCP metadata/responses; this does not test an
arbitrary production MCP server. The built-in environment is a trusted simulation,
not an OS sandbox. No containers are started by either example.

Each output includes `content_digest`, `ready`, the normalized specification,
source/binding/plugin identities and every case. Each case has a stable ID, source,
scenario snapshot, seed, required flag and one planning disposition:

| Disposition | Meaning |
|---|---|
| `ready` | Planning requirements are satisfied |
| `blocked` | A required case cannot be planned; the plan exits nonzero |
| `excluded` | An optional case cannot be planned; its reasons stay in the roster |

A wholly excluded plan also exits nonzero. An absent wildcard source has one explicit
unresolved `*` row; Drill cannot enumerate data it does not have. An optional exclusion
is therefore a coverage gap, never successful coverage. Invalid schema, duplicate
selectors and overlapping selections are errors. Use distinct seeds for repetitions;
the same scenario with a different strategy is a distinct selection.

## Review and create a lock

Inspect the **whole plan**, including exclusions, identities, settings and limits.
Record your decision in the existing local acceptance-history format:

```json
{
  "schema_version": 1,
  "records": [{
    "schema_version": 1,
    "subject_id": "agent-fixture-review",
    "kind": "suite",
    "artifact_digest": "sha256:<copy the plan's 64-character content hash>",
    "actor": "<your reviewer identity>",
    "decision": "accepted",
    "recorded_at": "2026-09-20T12:00:00Z",
    "rationale": "<why this exact plan is acceptable>",
    "granted_access": []
  }]
}
```

Replace the placeholders and timestamp with your actual review details, then:

```sh
blastcontain-drill-suite plan drill/examples/suites/agent.json \
  --acceptances acceptances.json --lock agent-lock.json
blastcontain-drill-suite check-lock agent-lock.json --acceptances acceptances.json
```

The planner re-resolves the inputs before writing the lock. It requires acceptance of
the exact content digest. This is a local technical decision record, not an invented
organizational governance policy. The [3F `accept` command](suite-cli.md) writes
this history with an explicitly reviewed digest and scope.
Files are created exclusively; existing outputs are never overwritten. Choose a new
filename when replanning. Without `--output`, plan JSON goes to stdout; the summary and
errors go to stderr. Failure to create a lock can still leave the reviewable plan output.

Decisions are ordered by file position: the last record for a kind/subject wins, even
if its timestamp is older or its digest differs. Append a rejected/revoked decision
to invalidate a prior acceptance. `check-lock` requires the current history; it never
substitutes the lock's historical acceptance or probe snapshots.

## Suite schema and built-ins

Schema 1 requires `id`, `target`, `environment`, `evaluators`, and `selections`.
Each selection has `id`, `source`, `scenarios` (explicit IDs or exactly `["*"]`),
optional `required` (default true) and optional `strategy`. Seeds default to `[0]`;
concurrency defaults to 1 and is bounded to 64. There are at most 10,000 expanded cases.

| Source ID | Definitions |
|---|---:|
| `builtin` | 14 |
| `jailbreakbench` | 200 |
| `operators` | 266 materialized deterministic variants |
| `multi-turn` | 5 |
| `system-card` | 12 |
| `mcp-poisoning` | 4 |

`builtin` preserves the legacy attack provenance name (the old source class is named
`builtin-replay`). Operators are materialized through the existing trusted, deterministic
source, not imported from an external plugin. All 501 legacy definitions remain available;
selecting a definition does not imply the chosen evaluator can score it.

| Binding ID | Planning role |
|---|---|
| `builtin.target.resistant` / `builtin.target.vulnerable` | Synthetic target behavior |
| `builtin.target.llm` | Model-backed target; requires `target` model settings |
| `builtin.environment.fixture` | Existing controlled agent/MCP fixture capabilities |
| `builtin.evaluator.heuristic` | Harm/refusal rubric support; no freeform rubric support |
| `builtin.strategy.pair` | Existing single-prompt PAIR-style strategy; requires `attacker` settings and an explicit scenario attack objective |

Capabilities and observations are checked separately. Intrinsic requirements are also
derived from turns, goals and injection surfaces; omitting their declarations from an
external snapshot cannot bypass these checks. New fixture references/task checks remain
blocked until their adapters exist. A current heuristic cannot silently score a freeform
rubric. Target `mcp` requires a controlled MCP poisoning scenario.

`global_limits` and `case_limits` each contain `model_calls`, `tool_steps`,
`strategy_iterations`, `wall_seconds`, and `artifact_bytes`, all positive integers.
Per-case limits cannot exceed global limits. Planning validates these declarations;
execution enforces them through a shared ledger. Global limits may be lower than
the sum of per-case maxima; unstarted or unfinished cases remain explicit outcomes.

Optional `models` is a list with one entry per selected `target`, `attacker` or
`evaluator` channel. For example, a local abliterated attacker can be planned with:

```json
{
  "channel": "attacker",
  "endpoint_url": "http://127.0.0.1:1234/v1",
  "model_ref": "local-abliterated",
  "identity": "alias",
  "temperature": 0.0,
  "max_output_tokens": 512
}
```

An endpoint is explicit and included in the digest; it is never contacted during
planning. URLs containing userinfo, queries, fragments, escapes or whitespace are
rejected. Model/credential references are symbolic labels. `credential_ref` may name
a future trusted secret binding; put no credential values in any input. Arbitrary
headers/configuration are rejected. `identity: "pinned"` additionally requires a
`model_digest`; an alias does not promise reproducible live outputs. A seed alone
does not make live model behavior reproducible. Planning does not resolve credentials.

## Reviewed external inputs

Repeat `--source snapshot.json`, `--plugin manifest.drill-plugin.json`, and
`--probe probe.json` to supply explicit files. External data cannot shadow a built-in
source or binding. No source path, plugin entry point or artifact path is taken from
untrusted JSON and executed or followed.

A `SourceSnapshot` contains schema version 1, `id`, an exact `revision`, a pinned
`code_digest`, and a `scenarios` array of `ScenarioSpec` records. Every scenario must
identify that same source/revision. Revisions `unknown`, `latest`, `main` and `head`
block planning. The source's `content_digest` binds its normalized JSON, including code
identity, all scenario data and provenance. External sources require a separate
`kind: "content"` acceptance whose subject is the source ID. The Python API's
`SourceSnapshot.content_digest` gives the digest for review.

External plugin acceptance remains bound to `review_digest(manifest)`, including the
exact container image and full metadata, with matching access scope. Changing image,
manifest, data, source code, target/model settings or budgets invalidates the relevant
review. Only the current `attack_strategy` worker role is supported; declaring another
role in a manifest cannot create its adapter. The empty-config, broker-only worker
profile is unchanged. `broker.attacker` access requires attacker model settings.

External workers also require an explicit prior probe observation:

```json
{
  "schema_version": 1,
  "plugin_id": "reference",
  "artifact_digest": "sha256:<exact local image ID>",
  "available": true,
  "observed_at": "2026-09-20T12:00:00Z",
  "profile": "linux-rootless-podman-v1"
}
```

This operator-supplied record is a planning observation, not proof of current availability
or isolation. Planning works on Linux and Windows, while external workers still require
the supported Linux rootless Podman profile. Future execution must freshly check actual
images/isolation and current acceptance at run start and before each case. No age-based
validity, cryptographic probe attestation or organizational approver authentication is
claimed by this format.

## Integrity and API boundary

The Python API is `plan_suite(spec, catalog, records=..., probes=...)`, followed by
`create_lock(plan, catalog, ...)` and `validate_lock(lock, catalog, ...)`. `Catalog`
is a trusted application input; the CLI constructs built-ins itself and accepts only
external data/manifests, never user-supplied declarations of trusted built-ins.

Hashes are SHA-256 of UTF-8 JSON with sorted object keys, compact separators,
`ensure_ascii=True`, and no nonfinite numbers. Set-like suite inputs, source scenario
order, identities, acceptance snapshots and probe snapshots are sorted; prompt turn
order and decision history remain significant. Whitespace/key order in input JSON do
not affect digests. Unknown/duplicate fields, invalid versions and invalid types fail.

The content digest excludes acceptance records and probe timestamps to avoid circular
approval hashes. The lock digest additionally covers those snapshots. Built-in identity
hashes installed Drill/Core Python and vendored CSV bytes, excluding inert proposals and
bytecode, so an editable code change also invalidates the plan. Dependency/runtime
identity and actual execution evidence belong to the later run envelope.

Reading a `SuiteLock` validates internal hashes, not current permission to execute.
`validate_lock` re-resolves current inputs and decisions. These digests detect content
changes; they are not signatures or a substitute for a trusted decision-history source.
Readers reject oversized files (16 MiB for suite artifacts, existing 64 KiB limits for
plugin metadata/history), traversal and symlinks. No filenames are derived from case IDs.
Prompts and reviewer rationale remain reviewable data: do not embed real secrets in them.

Validation covers deterministic plans/locks, all 501 definitions, complete required/optional
rosters, compatibility, separate content/plugin/suite acceptance, stale/revoked decisions,
tampering, configuration secrets, safe artifact handling, CLI round trips and planning
with process/network calls disabled. Existing unit and signed-report compatibility tests
remain part of the validation gate.
