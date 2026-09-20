# Practical MCP control validation

`mcp-scenarios-v1` runs an operator-authored case plan against an existing MCP tool
endpoint. It negotiates MCP, discovers tools, invokes the named tools with scoped
credentials, and compares the resulting state through a separately authenticated
observer. Unlike `customer-record-v1`, tool names, arguments, credentials and
expected state are not hardcoded into Verify.

This adapter currently supports **stateless JSON Streamable HTTP**, MCP protocol
`2025-11-25`, and literal loopback HTTP(S) endpoints. It rejects session-bearing,
SSE, paginated discovery and unnegotiated protocol responses as incomplete. There
is no automatic stdio command launch, redirect following, proxy use, OAuth login,
or credential acquisition. Normal Verify scans remain passive.

## Reproduce the official-SDK integration

Install the example/test dependencies (the SDK is not needed by Verify itself):

```bash
pip install -c verify/constraints-validation.txt -e ./core -e './verify[validation-test]'
python verify/examples/practical-validation/run_demo.py --output-dir /tmp/practical-validation
```

The reference server uses the [official Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk)
2.2.0, performs real JWT signature, issuer, audience and expiry validation, and
stores synthetic records in a unique run namespace. Its separately hosted observer
creates that namespace, reads record/audit state, issues exact-action approvals,
revokes a caller and deletes only the run's data afterward. The local example owns
both components and their in-memory data; it does not prove the observer can resist
a compromised target process.

The 21-case plan tests valid/missing/invalid/expired/wrong-audience credentials;
allowed/limited roles, same-tenant records, other tenants and fields; approval
substitution/reuse; repeated operation IDs; sequential call budgets; and external
revocation. All six CTL groups pass with enforcement and fail with deliberately
broken enforcement. The tests also reject deny-all behavior and denials that mutate
records. A language model is not involved: these checks directly exercise enforcement
under a caller that can submit unauthorized tool calls.

Both demo packets remain **REJECTED** overall because the passive HTTP finding is
retained. Case PASS is limited to that case's expected outcome, not a certification
of the whole control family. Reports, signed packets and SARIF omit credentials,
raw responses and tool arguments; they include state hashes and the manifest hash.
Temporary ports and credentials expire when the example ends.

## Connect your own server

Use a non-production tenant or disposable data namespace. Run Verify in the target
environment and explicitly enable live writes:

```bash
blastcontain-verify --target-type mcp --target-id your-server \
  --mcp-config mcp.json --policy policy.json \
  --validate-controls validation.json --allow-live-tests \
  --output audit.json --report report.md --sarif scan.sarif
```

For runtime assessment, add `--scan-scope runtime`, the appropriate `--environment`
and `--search-path` inside the target runtime. A scan from a separate machine or
container only establishes configuration and remote observed behavior, not the
server's filesystem or container containment.

Start from the generated `validation.json` or `examples/practical-validation/plan.py`.
Replace these manifest fields:

- `adapter`: `mcp-scenarios-v1`.
- `target_id` and `mcp_url`: exactly match the selected passive target.
- `control_url`: origin of your trusted observer, separate from the MCP endpoint.
- `admin_token_env`: environment-variable name for the observer's administrative token.
- `credentials`: caller labels mapped to environment-variable names; never literal secrets.
- `discovery_credential`: label of a credential authorized to initialize and list tools.
- `cases`: ordered explicit tool operations and expected observed state.

Each case has `id`, `check_id` (`CTL-01` through `CTL-06`), `credential` (or `null`),
`tool`, `arguments`, `expect` (`allow` or `deny`) and `after`. Every claimed group
requires both allowed and denied cases. These labels express the operator's test
intent; Verify cannot infer that a case exhaustively tests the named control.

For allowed calls, `after` is the **entire expected observer JSON object**, including
any audit events. The before and after state must differ: this first adapter targets
writes, not read-only access tests. For denied calls, `after` must be `unchanged`,
and `denial_code` must name either an explicit `http:401`, `http:403`, `http:409` or
`http:429`, or your tool's structured `denial_code` in a result with `isError: true`.
Generic JSON-RPC errors, schema errors, timeouts and server failures never count as
successful security denials. Adapt your server's denial response to this contract;
do not map arbitrary errors into a security-denial code.

`$RUN_ID` string values are replaced by a fresh namespace ID. An object containing
only `{"$binding":"approval"}` is replaced by a named value supplied by the observer.
An optional `prepare` object contains `operation` and `arguments`, for example to
issue an approval or revoke a caller before the next tool call. These operations
are sent only to the fixed observer endpoint; no arbitrary URLs or commands run.
Preparations are privileged mutations and belong in the reviewed case plan.

## Observer contract

All observer calls use its separate Bearer token. Requests and responses are JSON
objects. Success is HTTP 200 or 201.

| Request | Contract |
|---|---|
| `POST /runs` | Receives `run_id` and `adapter`; creates an isolated namespace and returns both unchanged, with optional `bindings` object |
| `GET /runs/{run_id}/state` | Returns stable, complete record/effect/audit state for exact comparison; omit volatile timestamps or normalize them in the observer |
| `POST /runs/{run_id}/prepare` | Receives an allowlisted `operation` and `arguments`; performs the requested setup/approval/revocation, optionally returning `bindings` |
| `DELETE /runs/{run_id}` | Deletes only that test namespace and returns `{"deleted":true}`; should be idempotent even when setup's response was lost |

The operator must implement this observer against the real datastore and audit
sink. Restrict its operations and access independently of the caller. A server's
self-reported success or telemetry alone is not independent evidence. Include
append-only audit effects where possible: an unchanged final record alone cannot
prove there was no transient action, external request or write followed by rollback.
The reference observer is an example of the contract, not a production adapter for
your database or authorization provider.

The manifest has 2–32 cases; the adapter caps the full run at 100 HTTP requests,
64 KiB per uncompressed response and a 60-second budget checked between I/O steps.
HTTP phase timeouts are three seconds, so the budget is not hard cancellation of an
in-flight request. One cleanup request is reserved. Large plans may exhaust the
budget and correctly report ERROR. Requests are not retried after uncertain writes.

Cleanup is attempted even if setup fails. Missing evidence, protocol mismatch or
cleanup failure makes validation incomplete; the packet retains `fixture_run_id`
for operator recovery. An evidence error stops further tool writes. An ordinary
failed security expectation is recorded and subsequent declared cases still run.

Omitted CTL groups remain listed as not tested and make overall coverage incomplete.
A subset is useful diagnostically, but cannot earn a complete assessment. Full
coverage of all six groups still means only the cases supplied were evaluated.

## Remaining boundaries

This does not finish agent sandbox validation, stdio/stateful/SSE support, OAuth
conformance, queued/in-flight revocation, concurrency, delegation or egress testing.
Use existing Verify runtime assessment for containment configuration. The next
agent-specific step needs a real agent runtime and its filesystem/network policy;
MCP control results cannot substitute for that evidence. Drill adversarial research
and Charter governance remain separate later stages.
