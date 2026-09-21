# Durable suite runs (phase 3E)

The `blastcontain_drill.suites.durable` API adds persistent results to the
[execution service](suite-execution.md). The [3F CLI](suite-cli.md) exposes these lifecycle services.
The same accepted lock and current acceptance checks apply before any dispatch.

## Execute and verify

```python
from blastcontain_drill.suites.durable import execute_run, inspect_run, verify_run
from blastcontain_drill.suites.signatures import Signer

# Load an operator-managed Ed25519 PEM key from a protected location.
signer = Signer.from_pem(private_key_pem)
stored = await execute_run(
    lock,
    run_root,  # New private directory, or an existing owner-only directory.
    current_inputs=current_inputs,  # Re-read current catalog/acceptance/probes.
    signer=signer,
    require_signing=True,
)
summary = inspect_run(stored.directory)
verified = verify_run(
    stored.directory, lock=lock, trusted_public_key=signer.public_key
)
assert verified.replayed
# This additionally requires trusted signing AND a passing security gate.
print(verified.attested_pass)
```

Without a configured signer, execution uses an ephemeral advisory Ed25519 key.
Verification requires an operator-trusted raw 32-byte public key unless the caller
explicitly sets `allow_advisory=True`. Trusting the key embedded in the report alone
never establishes operator identity. Required signing fails before dispatch if its
key is absent; invalid PEM, signing errors and persistence errors cannot silently
fall back to advisory signing or publish a successful completion marker.

`reported_security_passed` is the signed producer's claim. `security_passed` requires
offline reduction of retained evidence. `attested_pass` additionally requires trusted
configured signing. Inspection reports the claim with `trusted=False`; it is not
verification. A cryptographically intact report without replay inputs has
`replayed=False` and `security_passed=False`, even when its signed claim says pass.

## Stored representation and retention

Each generated run ID has a private directory containing:

- `initial.json`: signed identity, policy and complete pending case roster, committed
  before dispatch.
- `state.json`: unsigned progress snapshot; never accepted as a completion result.
- `evidence/`: immutable content-addressed normalized evidence bundles.
- `envelope.json`: signed final roster, results, lock/runtime/reducer identities,
  reduction policy, usage, model-call hashes and artifact inventory. Its publication
  marks completion, including completed cancellation cleanup.
- `control.json`, `lease.lock` and optional `cancel.json`: private local control data.
- `raw/`: empty by default; opt-in lock inputs, adaptive scenarios and successful
  model request/response traces, stored separately.

Default files omit source prompts, raw responses, reviewer/rationale strings,
provider/model names and free-text diagnostics. Opaque hashes retain identity;
normalized evidence distinguishes attempted actions from independently observed
effects. Known broker credentials are removed from provider echoes before the
response reaches workers or optional traces. This is not a general secret detector:
raw inputs may contain other sensitive data. Raw traces do not include HTTP headers
or provider exception text, and capture successful model calls only.

Set `raw_retention_seconds` explicitly (1 second through 31 days) to retain raw
inputs. Expiry is signed into the run, and readers refuse expired raw inputs.
`purge_expired_raw(directory)` explicitly deletes expired validated raw files
from completed or interrupted runs while refusing an active controller; there
is no background deletion scheduler. Evidence hashes remain signed after deletion.
Operators must arrange purge calls if physical deletion at expiry is required.

The default retained-file budget is 64 MiB, adjustable from 1 KiB to 1 GiB. Each
file is capped at 16 MiB. This is separate from the suite's execution artifact
budget, temporary atomic-write disk overhead and small bounded control/lease files.
Exhaustion cancels active work and prevents publication of a completed envelope.
Current native fixtures do not generate external proof stores; that unsupported
artifact type is rejected rather than silently discarded.

POSIX paths require current-user ownership with no group/other access. Windows
uses a protected current-user DACL and checks its owner and access entries, using
[SetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow)
and [GetNamedSecurityInfoW](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow).
Symlinks, Windows reparse points, non-regular files and multiply linked files are
rejected. These are local file-access controls, not isolation from another process
running as the same user or an administrator. Use a local filesystem supporting
atomic file publication and process locks.

## Replay, stopping and recovery

Normal replay requires the original lock supplied as `lock=`. Adaptive runs also
need their materialized attempt scenarios, either from unexpired retained raw
inputs or `scenarios={case_id: ScenarioSpec(...)}`. Missing source inputs make replay
unavailable, never passing. Changing a lock, required evidence file, roster or
recorded conclusion fails verification. Unexpired raw files are also integrity
checked; expired raw files may be deliberately absent. No model is called during
verification. Historical verification does not renew acceptance.

`request_cancel(directory)` from `suites.run_store` submits a run-specific stop
request only while a controller holds its OS lease. The controller checks a private
capability bound to this run and nonce. It never signals a PID read from disk.
Stopping prevents further dispatch, cleans up owned processes/workers and retains
terminal outcomes for unstarted cases. Cancelling the caller coroutine also saves
a signed cancelled roster when cleanup/persistence succeed, then re-raises
`CancelledError`. A remote request's cancellation cannot prove remote side effects
stopped.

If the controller dies before the final envelope, the OS lease is released and
inspection reports `interrupted`. Inspection conservatively uses the signed initial
roster with incomplete outcomes rather than trusting unsigned progress. Earlier
blobs may remain for diagnosis. No automatic restart/resume occurs. Podman workers
retain their independent engine deadline if the controller is killed; inspection
does not claim immediate container cleanup after that failure.

`rerun_run(directory, root, lock=..., current_inputs=..., ...)` checks a completed
parent envelope, creates a new run ID linked to its digest, and revalidates current
acceptance. Old cancellation capabilities cannot affect it. For interrupted runs,
start an explicit fresh `execute_run` after assessing uncertain effects.

`legacy_projection(directory, **verification_options)` requires replay inputs and
returns an explicitly unsigned, sanitized and lossy `DrillReport` dictionary for
existing readers. It includes the original envelope digest and uses opaque case
IDs. Legacy report schemas and existing CLI behavior are unchanged.

## Validation

Tests exercise tampered/missing artifacts, untrusted and failing signers, absent
raw inputs, retention/purge, secret sentinels, storage exhaustion, file links,
forged/stale cancellation, caller cancellation, revocation before rerun and an
actually killed controller process. Real Podman tests separately check that a
persisted cancellation removes the worker. Fixture results do not measure live
model effectiveness or establish arbitrary remote MCP-server coverage.

Local validation on Linux/Python 3.12: 592 Core/Drill/Scout regression tests and
28 real plugin-worker checks passed, including durable cancellation. Ruff,
`mypy --check-untyped-defs` for suite services and medium-severity Bandit passed.
Clean Core/Drill wheels loaded all 501 definitions and executed/verified a 28-case
fixture run. The PR matrix separately exercises Linux/Windows on Python 3.11/3.12.
