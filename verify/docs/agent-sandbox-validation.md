# Live agent sandbox validation

The `agent-sandbox-v1` profile checks four containment boundaries from **inside the
invoking Linux process's environment**. It combines allowed operations with expected
denials, writes only uniquely named probe files, reads only explicitly declared dummy
canaries, and connects only to one operator-owned private-network test endpoint.

This is control validation, before Drill attacks. It does not attempt a kernel
escape, exploit another process, or use real credentials.

| Check | Evidence required |
|---|---|
| SBX-01 Filesystem | Create and remove a new file in the allowed workspace; creation in the protected directory must be denied |
| SBX-02 Credential isolation | Read and verify a public canary; reading a separately provisioned dummy credential must be denied |
| SBX-03 Privilege | Non-root UID, zero effective capabilities, no-new-privileges, seccomp filter mode, and a fixed child process unable to switch to UID 0 |
| SBX-04 Network | Working loopback TCP positive control; connection to the forbidden test endpoint blocked by permission or missing-route evidence |

A sandbox protecting a developer workstation can use the same profile: run Verify
through the **same sandbox launcher, UID, mounts, network namespace, capabilities
and security policy as the agent**, with `--env local_developer_workstation`. Running
Verify directly on the developer host tests the host process, not a sandboxed agent.
A separately hardened scanner container cannot certify another container. Namespace
identifiers and UID are recorded for inspection, not treated as external attestation.

## Run against your agent environment

Provision a writable test directory, a protected test directory, a readable canary,
an unreadable dummy credential, and a TCP listener in a network the agent must not
reach. Use synthetic data only. Verify the fixtures exist and the listener is healthy
from outside the sandbox before and after the scan. Do not point these tests at
production secrets or unrelated services.

```bash
blastcontain-verify --target-type agent --agent-id my-agent --env staging \
  --search-path /app --validate-controls /input/sandbox.json --allow-live-tests \
  --output /reports/audit.json --report /reports/report.md --sarif /reports/scan.sarif
```

Example manifest structure (replace the canary hashes with SHA-256 of the exact
bytes you provisioned):

```json
{
  "adapter": "agent-sandbox-v1",
  "agent_id": "my-agent",
  "writable_directory": "/work",
  "protected_directory": "/protected",
  "readable_canary": {"path": "/input/readable", "sha256": "<64 lowercase hex characters>"},
  "forbidden_canary": {"path": "/private-canary/token", "sha256": "<64 lowercase hex characters>"},
  "network": {"host": "10.89.0.2", "port": 18081}
}
```

The TCP listener accepts the fixed bytes `VERIFY_SANDBOX_PROBE\n` and responds with
`VERIFY_SANDBOX_CANARY\n`. The validator sends no credentials, files or manifest
content. Only literal RFC1918 IPv4 addresses and ports 1024–65535 are accepted;
there is no DNS lookup, public-internet probe or metadata-service access in this
profile. Existing baseline Verify checks still run with their own settings; set
`--egress-probe-target` to the controlled test endpoint when demonstrating locally.

Both live flags are required. YAML cannot grant CLI live consent, and SBX checks
cannot be suppressed. Linux is required; unsupported systems return incomplete
validation without executing these probes. Ordinary agent scans retain their
existing behavior when no control manifest is supplied.

## Failures, bounds and cleanup

A missing fixture, wrong canary digest, symlink, unreadable evidence, or unexpected
I/O error produces ERROR rather than PASS. Closed ports, timeouts and host-unreachable
errors do not prove network containment. A successful forbidden TCP connection is
FAIL even if its subsequent I/O fails. Permission denials or `ENETUNREACH` establish
only that the tested path was blocked at that moment, not that every destination is
restricted. The external demo harness checks listener liveness separately.

File operations walk directory descriptors without following symlinks. Creation is
exclusive with random filenames; existing files are never overwritten. Only files
created by the probe are removed. If removal fails, the report retains their recovery
paths and marks validation incomplete. Canaries must be regular files of at most
4 KiB; their bytes never appear in the report. Paths are bounded to 4096 characters
and 32 components. Fixture filesystems must be trustworthy local filesystems:
filesystem system calls have no hard cancellation deadline, so avoid remote/FUSE
mounts that may block indefinitely.

The fixed child process has a three-second timeout and attempts only `setuid(0)`
before exiting; no shell, arbitrary manifest code or supplied executable is run.
Socket phases have one- or two-second timeouts. The manifest cannot request extra
processes, arbitrary commands or unrestricted network scans.

Privilege flags are kernel observations, not proofs that every seccomp rule works.
A rootless container's UID 0 is still rejected by this profile even though it may map
to an unprivileged host UID. We do not test noexec bypasses, DNS/UDP/proxy egress,
resource exhaustion, process tracing, kernel isolation strength, or every credential
location. No model is involved: the probes represent actions a compromised caller
could attempt directly.

Signed agent packets containing live sandbox evidence use schema `1.3`; existing
agent packets without live checks remain `1.1`, and MCP packets remain `1.2`.
Markdown and SARIF include the same redacted evidence. Baseline findings remain in
the overall status; passing four live checks cannot erase them. Incomplete validation
or baseline scanner errors retain ERROR. Default-key signatures are advisory, as
explained in the usage guide.

## Reproduce with rootless Podman

Build the normal Verify image, then run the demonstration:

```bash
podman build -t blastcontain-verify:test -f verify/Containerfile .
python verify/examples/agent-sandbox/run_demo.py \
  --base-image blastcontain-verify:test --output-dir /tmp/agent-sandbox-demo
```

The harness runs Verify as the test agent process itself in each container. The
hardened variant uses a non-root UID, read-only protected storage, dropped
capabilities, no-new-privileges, default seccomp and no network. The broken variant
allows protected writes, runs as container root, and can reach the isolated witness.
Both variants retain resource limits and run without privileged mode, host namespaces,
host secrets or host port publication. The network is internal and disposable.

Expected: hardened PASS and broken FAIL for all four SBX groups. The full scan may
still be QUARANTINED by baseline findings, such as the absence of stronger kernel
isolation. Inspect `sandbox_validation` for this demonstration's control outcomes.

The harness saves signed packets, Markdown, SARIF, manifests and cleanup evidence;
checks canary liveness before and after; verifies probe-file removal; and removes its
own containers, network and image tag. CI runs the demonstration using the image
built by the existing hardened-container integration job.
