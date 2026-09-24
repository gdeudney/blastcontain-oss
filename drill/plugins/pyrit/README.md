# Pinned static PyRIT adapter — phase 4A

This optional container integrates the real **PyRIT 1.1.0 `PromptSendingAttack`**
through Drill's existing SDK and target broker. It requires no host runner, CLI,
config-class or dependency changes. It sends one reviewed user prompt with no
retry, then leaves evidence reduction and the final security gate to Drill.

For adaptive attacks, use the separately reviewed [Crescendo image](CRESCENDO.md).
This image remains the static portion of phase 4. Crescendo, TAP, multi-turn conversations,
backtracking, converters, upstream scorers, multimodal content and arbitrary MCP
servers are **not supported** by this image. Repeated executions require reset;
reset clears PyRIT's in-memory SQLite state but never renews the host call budget.

## Pin and scope

- [PyRIT 1.1.0 release](https://pypi.org/project/pyrit/1.1.0/), source tag
  [v1.1.0](https://github.com/microsoft/PyRIT/tree/v1.1.0), commit
  `d0524f0714840519b826eb770687ca1d4f46a761`
  (annotated tag object `db359fb2157283cec6c43941c3b42e53b340425b`).
- Upstream wheel SHA-256:
  `84581036bace7ff2aa92712e1e3f472a3a3bccc77567d5fbe642540c0ba20b0a`.
- Linux/Python 3.12 closure: 109 exact package versions with hashes in
  `requirements.lock`. Dependencies remain inside the plugin image.
- Python base image pinned by digest in `Containerfile`; runs are accepted against
  the resulting immutable local image ID. A rebuild can require new acceptance.
- Original Drill adapter code is Apache-2.0; upstream PyRIT is MIT, with its license
  retained as `LICENSE.pyrit`. Transitive packages retain their installed license
  material. The framework license is not a blanket review of third-party payloads.
- Bundled PyRIT datasets/templates are removed from this static image. Examples use
  original controlled prompts supplied by the operator, separately content-reviewed.
  No dataset is downloaded during execution.

The adapter accepts only a single text prompt with an explicit objective. It uses
PyRIT's native `PromptSendingAttack` with `max_attempts_on_failure=0`, an in-memory
SQLite database and one broker-backed `PromptTarget`. It does not create an OpenAI
client or receive target credentials. The existing worker profile keeps networking
disabled, the root read-only, UID 65532, 256 MiB memory, 64 processes and 16 MiB tmpfs.

PyRIT returns `undetermined` without an upstream scorer. This is recorded as an
untrusted framework claim; it cannot establish HELD/BYPASS. The host executes the
controlled Agent fixture, emits trusted observations, applies the selected
heuristic/evaluator policy and signs its evidence. Current broker feedback may be
truncated to 2,000 characters; no equivalence for longer upstream feedback is claimed.

## Build, review and run

From the repository root, with Core/Drill installed and supported local rootless
Podman available:

```sh
podman build --iidfile pyrit-image-id -f drill/plugins/pyrit/Containerfile .
python drill/plugins/pyrit/prepare.py \
  --image-id sha256:<full-id-from-pyrit-image-id> --output pyrit-review
```

The preparation script performs a read-only runtime probe and creates a manifest,
original controlled source, probe and resistant/vulnerable fixture suites. It
records a fixed `runtime_diagnostic` code in `review.json` if readiness fails;
for example, `host_info_timeout` identifies a host-query deadline rather than a
missing image. The host query is bounded to ten seconds to allow cold startup.
The script prints their review digests, also saved in `review.json`. It does **not** accept
content, launch a worker or alter a registry. Inspect these files before recording
separate plugin, content and suite decisions:

```sh
blastcontain-drill-suite accept pyrit-review/pyrit.drill-plugin.json --kind plugin \
  --expected-digest 'sha256:<reviewed plugin digest>' --grant-access broker.target \
  --reviewer Gordon --reason 'Reviewed static PyRIT image and target-only scope' \
  --output pyrit-review/plugin-decisions.json
blastcontain-drill-suite accept pyrit-review/source.json --kind content \
  --expected-digest 'sha256:<reviewed source digest>' \
  --reviewer Gordon --reason 'Reviewed original controlled content' \
  --acceptances pyrit-review/plugin-decisions.json --output pyrit-review/content-decisions.json
blastcontain-drill-suite plan pyrit-review/resistant.json \
  --source pyrit-review/source.json --plugin pyrit-review/pyrit.drill-plugin.json \
  --probe pyrit-review/probe.json --acceptances pyrit-review/content-decisions.json \
  --output pyrit-review/plan.json
blastcontain-drill-suite accept pyrit-review/plan.json \
  --expected-digest 'sha256:<reviewed plan digest>' \
  --source pyrit-review/source.json --plugin pyrit-review/pyrit.drill-plugin.json \
  --probe pyrit-review/probe.json --acceptances pyrit-review/content-decisions.json \
  --reviewer Gordon --reason 'Reviewed fixture roster and limits' \
  --output pyrit-review/suite-decisions.json
blastcontain-drill-suite plan pyrit-review/resistant.json \
  --source pyrit-review/source.json --plugin pyrit-review/pyrit.drill-plugin.json \
  --probe pyrit-review/probe.json --acceptances pyrit-review/suite-decisions.json \
  --lock pyrit-review/lock.json
blastcontain-drill-suite run pyrit-review/lock.json \
  --source pyrit-review/source.json --plugin pyrit-review/pyrit.drill-plugin.json \
  --probe pyrit-review/probe.json --acceptances pyrit-review/suite-decisions.json \
  --run-root pyrit-runs --raw-retention-seconds 3600
blastcontain-drill-suite verify pyrit-runs/<run-id> --allow-advisory
```

The example opts into short private retention for offline replay inputs and uses
advisory signing. For attestation, use `keygen`, `run --signing-key ...
--require-signing` and `verify --trusted-key ...` as described in the
[suite CLI guide](../../docs/suite-cli.md). Purge expired raw inputs explicitly.

The resistant suite should complete two HELD fixture cases; the vulnerable suite
should complete two BYPASS cases and exit 2. Plan and accept the vulnerable suite
separately, using new output filenames and the latest decision history. These are
synthetic behavior checks, not estimates of a live model's vulnerability.

## Validation and updating

`validate.py` runs the real pinned upstream strategy directly and through the
adapter with identical deterministic responses. It compares exact prompt order,
reset isolation, no-repeat execution and untrusted outcome handling. Container
conformance additionally checks host call limits across resets, rejected scope,
resistant/vulnerable signed suite replay and independent active cancellation.
Missing image/runtime support fails these checks; no mock or skip counts as coverage.

Build this image and the [Crescendo image](CRESCENDO.md), then set `DRILL_PYRIT_IMAGE`
and `DRILL_PYRIT_CRESCENDO_IMAGE` to their complete image IDs and run:

```sh
python -m pytest drill/plugins/pyrit/tests -q
```

The dedicated CI workflow builds both pinned images, audits their shared closure, then runs
these checks, including upstream parity inside the bounded container. It also runs
weekly so a newly disclosed dependency vulnerability is visible. The normal host
pip-audit sets and Drill dependency tree are unchanged.

To update deliberately, change `requirements.in`, regenerate the Linux/Python 3.12
hash lock using the command in its header, audit it, review the upstream API and
license/data changes, update the version assertion/provenance, and rebuild. Compare
parity again, record the new image ID, and obtain new explicit acceptance. Do not
change only a model/framework name in an existing lock.

The initial dependency audit on September 21, 2026 found no known vulnerabilities
in the 109-package closure. That is a point-in-time result. Live-model validation
is pending because no local model endpoint was available; the controlled tests do
not establish live attack effectiveness.

Initial Linux validation: 602 Core/Drill/Scout regression tests, nine real PyRIT
container checks, Ruff and medium-severity Bandit passed. The actual container
retained the existing 256 MiB worker profile; no larger-memory exception or host
execution fallback was added.
