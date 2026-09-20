# Drill redesign baseline — September 20, 2026

The first milestone adds contracts and compatibility bridges on the isolated
`codex/drill-contracts` branch. Main and the original development checkout were
not changed. This is the baseline for later plugin and suite work, not a release
of the complete redesign.

## Branch dependencies

- Main inspected at `bd8d93c3a20098baac43e8a139e9bb10f2bde298`.
- [Draft PR #62](https://github.com/gdeudney/blastcontain-oss/pull/62), MCP poisoning,
  was still open at `a98993bca535e37c17cc08cdd90ea3a65719b18c`.
- Local Scout tracker/registry/plan work was checkpointed at `c1cedc5`, then
  brought onto the MCP branch as signed-off commit `ae60529`.
- This milestone is stacked on those changes. It does not merge PR #62, publish
  packages, update the user's Scout database or mark research as implemented.

Review the Scout checkpoint and contract milestone separately. Before any eventual
PR to main, reconcile these dependencies so the same work is not proposed twice.

## Frozen source inventory

The checked-in [inventory fixture](../tests/fixtures/contracts-v1-baseline.json)
records hashes of every attack field, source revisions and deterministic built-in
outcomes before routing through the new adapters.

| Source | Revision | Cases |
|---|---|---:|
| Built-in replay | `v2026.06.1` | 14 |
| JailbreakBench | `886acc3` | 200 |
| Operators | `v3` | 266 (19 transforms × 14 seeds) |
| Multi-turn | `v1` | 5 |
| System card | `fable5-mythos5-2026.06` | 12 |
| MCP poisoning | `v1` | 4 |
| **Total** | | **501** |

Every case round-trips Attack → ScenarioSpec → JSON → ScenarioSpec → Attack
without field loss. Representative wrapped executions match the old path,
including multi-turn actions, MCP exposure, rubrics and generative feedback.

The [signed report fixture](../tests/fixtures/contracts-v1-signed-report.json)
contains 20 controlled stub cases: 14 built-ins, four MCP cases and two JBB cases.
It uses the public default HMAC key and is marked **advisory**; it is a compatibility
fixture, not an attestation. Times, ID, canary and measured latency are normalized.
The wrapped report payload matches exactly, signature tampering is detected, and
the existing diff reader reports no differences.

To capture a fresh candidate for review, use a new output directory:

```sh
PYTHONPATH=core:drill python drill/tests/fixtures/capture_signed_baseline.py /tmp/drill-baseline-candidate
```

Do not automatically replace the baseline after a failed comparison. An intentional
corpus or outcome change needs its own reviewed revision and explanation.

## Local validation

Validated on Linux with Python 3.12.13:

- Baseline before contract changes: **234** Core/Drill/Scout tests passed.
- After this milestone: **280** Core/Drill/Scout tests passed, including **46** new
  contract/report compatibility checks. No skips in this invocation.
- Podman integration: **6 passed**, including all four MCP scenarios;
  **1 live-model test deselected**, not claimed as passing.
- Ruff passed for Core, Drill and Scout. Bandit passed for the new contract package.
- Mypy passed for the new contract package with dependency imports followed silently.
- Core, Drill and Scout wheels built; package data and license/notice files checked.
  Inactive Scout proposals under `corpus/contrib` are excluded. Scout's missing
  wheel license/notice files were added during this check.
- A clean wheel installation loaded all 501 scenarios, passed all four CLI help
  entry points and ran the four controlled MCP cases with their expected outcomes.

Commands from the repository root, with the test dependencies installed:

```sh
PYTHONPATH=core:drill:tools/scout python -m pytest core/tests drill/tests/unit tools/scout/tests -q
PYTHONPATH=core:drill python -m pytest drill/tests/integration -m podman -q
ruff check core drill tools/scout
bandit -q -r drill/blastcontain_drill/contracts
python -m mypy --follow-imports=silent --ignore-missing-imports drill/blastcontain_drill/contracts
python -m pip wheel --no-deps --wheel-dir /tmp/drill-redesign-wheels ./core ./drill ./tools/scout
python -m venv /tmp/drill-redesign-install
/tmp/drill-redesign-install/bin/python -m pip install /tmp/drill-redesign-wheels/*.whl
/tmp/drill-redesign-install/bin/python -I drill/tests/fixtures/check_installed_baseline.py /tmp/drill-redesign-wheels
```

The MCP fixtures need loopback sockets. Podman needs a working local container
runtime and its test image. Restrictive execution environments must allow those
capabilities explicitly; a socket/runtime failure is not a successful security test.

## Platform and optional-runtime matrix

| Path | Supported/tested scope | This milestone |
|---|---|---|
| Core/Drill/Scout model-free tests | Existing CI: Linux and Windows, Python 3.11/3.12 | Linux 3.12 run locally; other combinations await CI |
| In-process MCP fixtures | Loopback HTTP, synthetic resistant/vulnerable agents | Validated locally |
| Podman cage | Linux with usable Podman and fixture image | Six integration tests passed |
| Generative attacker bridge | Any existing compatible backend, including local abliterated models | Stub and recording-backend parity passed; no new live-model run |
| AIG / remote scorers / DeepEval | Optional external service or extra dependencies | Existing model-free tests only; no new live-service validation |
| PyRIT / AgentDojo / garak | Future optional integrations | Not implemented by this milestone |

The CI path filter now reruns Scout tests when Drill's arXiv registry changes.
No new dependencies or minimum Python-version changes are introduced.

## Compatibility examples

Existing CLI flags and YAML configuration remain valid. The following commands
exercise installed help without contacting a model:

```sh
blastcontain-drill --help
blastcontain-drill-diff --help
blastcontain-scout --help
blastcontain-scout-track --help
```

Existing generative configuration still selects a local abliterated model:

```yaml
agent_id: example-agent
cage: inprocess
target_base_url: http://localhost:1234/v1
target_model: your-target-model
generative: true
attacker_base_url: http://localhost:1234/v1
attacker_model: your-local-abliterated-model
generative_iters: 2
max_steps: 4
```

This is a configuration example, not a record of a live run. The current loop is
PAIR-style sequential refinement; documentation claiming TAP was corrected.
See [contracts v1](contracts-v1.md) for the additive Python API and report migration
rules. The next implementation unit is data-only plugin discovery and the bounded
worker protocol, followed by suite planning and evidence reduction.
