# Run reviewed Agent and MCP fixture suites (phase 3F)

The `blastcontain-drill-suite` CLI uses the same planning, acceptance, execution
and evidence services as the Python API. The existing `blastcontain-drill`, diff,
plugin and local abliterated-attacker interfaces remain available.

## Review, accept, lock and run

After installing Core and Drill, run this from the repository root. Outputs must
have new filenames; commands never overwrite an existing plan, lock or decision
history. Read the whole plan before copying its printed digest into `accept`.

```sh
blastcontain-drill-suite plan drill/examples/suites/agent.json --output agent-plan.json
blastcontain-drill-suite accept agent-plan.json \
  --expected-digest 'sha256:<reviewed content_digest>' \
  --reviewer Gordon --reason 'Reviewed controlled fixture scope and limits' \
  --output decisions.json
blastcontain-drill-suite plan drill/examples/suites/agent.json \
  --acceptances decisions.json --lock agent-lock.json
blastcontain-drill-suite keygen suite-keys
blastcontain-drill-suite run agent-lock.json --acceptances decisions.json \
  --run-root suite-runs --signing-key suite-keys/signing-key.pem --require-signing
```

`keygen` creates a new owner-only directory containing an Ed25519 PEM private key
and a raw 32-byte public key. Keep the public key's trusted identity outside the
run report; an embedded key alone cannot attest identity. An existing run root
must already be owner-only. The commands create a new private root if it is absent.

The run command emits one JSON line with `event=created`, a run ID and its directory
before any case dispatch, followed by a sanitized final summary. Use that directory
in subsequent commands. `inspect` does not establish trust; `verify` replays retained
evidence against the original lock and an explicitly trusted key.

```sh
blastcontain-drill-suite inspect suite-runs/<run-id>
blastcontain-drill-suite verify suite-runs/<run-id> --lock agent-lock.json \
  --trusted-key suite-keys/verification-key.pub
blastcontain-drill-suite rerun suite-runs/<run-id> agent-lock.json \
  --acceptances decisions.json --run-root suite-runs \
  --trusted-key suite-keys/verification-key.pub \
  --signing-key suite-keys/signing-key.pem --require-signing
```

A rerun creates a new ID, binds the prior completed envelope and checks current
acceptance. It never resumes uncertain actions. For a demo without configured
signing, omit the signing options and explicitly use `--allow-advisory` when
verifying/rerunning. Such results cannot have `attested_pass=true`.

## Stop and interpret

From another terminal, submit `blastcontain-drill-suite cancel suite-runs/<run-id>`.
`requested=true` acknowledges the request, not cleanup completion. Inspect again
for a terminal signed result. An inactive run returns `requested=false`. Stop
requests are scoped to the active run, never a PID supplied from disk. A killed
controller leaves an interrupted run, and inspection cannot turn its unsigned
progress snapshot into completed evidence.

| Output/exit | Meaning |
|---|---|
| `run` / `rerun`: 0 | Required fixture security gate passed |
| `run` / `rerun`: 2 | Run recorded, but security gate failed or coverage/cancellation is incomplete |
| `verify`: 0 | Signature policy satisfied, evidence replayed, security gate passed |
| `verify`: 2 | Valid signed bytes but replay unavailable or security gate failed |
| `verify`: 1 | Signature, artifact or replay consistency validation failed |
| `inspect`: 0 | Summary read successfully; this is not a passing security result |
| 1 | Input/storage/service error; no successful run is implied |
| 2 on invalid arguments | Standard CLI usage error, separate from a completed run's failed gate |
| 130 | Operator interrupted the command |

`reported_security_passed` is the signed producer's claim; `security_passed` requires
replay. `attested_pass` also requires trusted configured signing. A blocked attempted
action can be a legacy BYPASS with containment blocked; that is not proof of a real
external effect. Missing required exposure, evaluator observations or source inputs
cannot produce a verified pass. Read the [evidence model](evidence-reduction.md).

## Acceptance changes, external sources and plugins

Use `--acceptances previous-decisions.json --output next-decisions.json` to append
a decision while retaining prior history. `--decision revoked` or `rejected` invalidates
prior acceptance for that subject. Use the new history on subsequent checks/runs;
Drill does not discover a newer file automatically. It reloads the selected file
before dispatch. These records do not authenticate an organizational approver.

For a reviewed `SourceSnapshot`, use `accept source.json --kind content`; copy its
content digest from the planning identities. For a plugin manifest, use `--kind
plugin` with the review digest reported by `blastcontain-drill-plugins` and repeat
`--grant-access` for **every** requested scope. Missing/extra grants are rejected.
Plugin acceptance, content acceptance and suite acceptance are separate decisions.
The metadata history limit is 64 KiB; the later review database is not implemented.

Repeat `--source source.json`, `--plugin manifest.json`, `--probe probe.json` and
`--acceptances history.json` on plan, accept, check-lock, run and rerun as needed.
These explicitly selected files form current inputs. A saved probe is not evidence
that a runtime still works: the external worker independently checks containment
before executing. See the [reference plugin walkthrough](../plugins/reference/README.md)
and [worker profile](plugin-workers.md). External workers currently require Linux
rootless Podman; fixture CLI and native-process tests also run on Windows.

## Credentials and sensitive evidence

Model settings specify credential references, never credential values. Map a
reference explicitly at execution, for example `--credential local=DRILL_LOCAL_KEY`
when the lock uses `credential_ref="local"`. Supply the environment value through
your normal local secret mechanism. Workers do not inherit the provider credential.
Commands do not accept arbitrary model endpoints or plugin code outside the lock.

Raw prompts and responses are off by default. For adaptive replay, either retain
inputs with an explicit `--raw-retention-seconds 3600`, or preserve the attempt
scenarios separately and supply `verify --scenarios attempt-scenarios.json` (an
object mapping opaque attempt IDs to full `ScenarioSpec` objects). Without those
inputs a signed adaptive report can be intact but not replayable.

`purge-raw RUN_DIRECTORY` deletes validated raw files after expiry, including
interrupted runs, while refusing an active controller. Expiry blocks
reads immediately, but physical deletion requires that command; no background job
is installed. `--storage-limit` caps retained run bytes separately from execution
budgets. See [storage, signing and recovery](suite-runs.md) for precise limits.

`export-legacy RUN_DIRECTORY --lock LOCK --trusted-key PUBLIC --output legacy.json`
creates an explicitly **unsigned**, sanitized and lossy report for existing readers.
Keep the original envelope for verification.

## Examples and release validation

| Example | Controlled behavior |
|---|---|
| `drill/examples/suites/agent.json` | Resistant synthetic Agent, 14 built-in scenarios at two seeds |
| `drill/examples/suites/agent-vulnerable.json` | Same selection with vulnerable synthetic behavior |
| `drill/examples/suites/mcp.json` | Vulnerable Agent consuming four poisoned MCP description/response fixtures |
| `drill/examples/suites/mcp-resistant.json` | Same MCP fixtures with resistant synthetic behavior |
| `drill/examples/suites/benign-control.json` | Deliberate over-refusal: resistant stub refuses a benign task, so the gate fails with utility failure |
| `drill/examples/suites/adaptive.py` | Recording target/attacker/evaluator, two PAIR attempts and six shared calls |

These are controlled simulations. MCP cases test the consuming Agent's behavior;
this is not an arbitrary production MCP-server scanner. Native fixture subprocesses
run trusted code; OS containment evidence comes from separate Podman tests.
The recording example tests the same PAIR message/history path used by a configured
local abliterated attacker. It does not measure model attack effectiveness.

`drill/scripts/validate_suite_release.py` runs using only installed packages and
stdlib fixtures. It covers plan/accept/lock, key generation, signed run/verify,
rerun, legacy export, a failing vulnerable gate and cancellation from a separate
command during a real loopback HTTP request. CI builds and installs wheels in fresh
environments on Linux and Windows, Python 3.11/3.12; the 501-definition baseline
and four CLI entry points are checked. Real Podman integration remains separate.

Live validation is **pending**: on September 21, 2026 neither the local :1234 nor
:11434 OpenAI-compatible endpoint was reachable. No live pass is claimed. For a
bounded run once a local model is available:

1. Copy the recording adaptive example's controlled source/scenario and suite to
   JSON. Set actual `target` and `attacker` model settings, and an `evaluator` when
   selecting the LLM evaluator. Keep a single single-prompt scenario, three seeds,
   concurrency one, case model calls six, strategy iterations two and wall time
   60 seconds; set global model calls 18 and wall time 180 seconds.
2. Record the actual model names/revisions/digests where known, local server version,
   temperature and token cap. An alias is not reproducible model identity. Review
   and accept source content and the resolved suite separately, then create a lock.
3. Run through this CLI with explicit credentials and short raw retention if
   replay inputs are needed. Verify every run, record all three repetitions,
   outcomes and budget use; distinguish model variability from runtime correctness.
   A security failure is a finding to inspect, not a reason to hide a repetition.

Local 3F validation: 602 Core/Drill/Scout tests passed on Linux/Python 3.12;
clean installed wheels passed the release script, and the recording adaptive demo
produced two attempts with six shared model calls. Ruff, suite type checking with
untyped-body checking and medium-severity Bandit passed. Cross-platform wheel and
container results are checked on the actual PR head before merge.
