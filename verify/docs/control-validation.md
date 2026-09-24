# Opt-in control validation

The `customer-record-v1` adapter tests six control groups against a **synthetic
loopback fixture**, using allowed requests as positive controls and checking both
denied responses and the resulting data state. This is the first control-validation
slice after passive Verify assessment. It is not a general production MCP scanner,
an OAuth conformance suite, or an adversarial Drill run.

For an existing MCP server, use the [practical scenario adapter](practical-validation.md).
It supports explicit tool/caller/state mappings and official-SDK protocol negotiation.

## Run the complete demonstration

From the repository root, with this Verify checkout and Core installed in your
Python environment:

```bash
python verify/examples/control-validation/run_demo.py --output-dir /tmp/verify-controls-demo
```

The demo starts loopback-only MCP and control endpoints on temporary ports, runs
Verify against enforced controls and deliberately broken controls, then shuts down
the services. It uses only in-memory synthetic customer records and fresh fixture
credentials. No models, email, payments or real customer systems are involved.

Expected: all six `CTL-*` checks PASS for `enforced` and FAIL for `broken`.
Both overall scans may still be REJECTED because passive MCP-02 flags the fixture's
HTTP configuration. Passing control cases does not erase other findings or prove
production security. Inspect each report's `control_validation` section.

Each output directory contains console output, Markdown, signed JSON and SARIF.
Manifests contain environment-variable names rather than credentials. Their
recorded temporary endpoints cease to exist after the demo; rerun the script to
create new fixtures. Packets signed with the default key are advisory, as described
in the [usage guide](usage.md).

## Cases in this adapter

| Check | Positive control and negative cases |
|---|---|
| CTL-01 Authentication | Valid caller succeeds; absent, invalid, expired and wrong-audience fixture credentials are denied without changing state |
| CTL-02 Authorization | Allowed phone update succeeds; wrong tool, limited role, different record in the same tenant, other tenant and forbidden field are denied |
| CTL-03 Approval | Exact authorized bank update succeeds; missing, substituted, wrong-caller, reused and expired approval is denied; caller cannot mint its own approval |
| CTL-04 Replay | First operation succeeds; repeat operation ID is rejected without another state change or audit event |
| CTL-05 Budget | Two allowed calls succeed; the third call under the same budget is denied without changing state |
| CTL-06 Revocation | Credential works before external revocation and stops working immediately afterward |

The fixture uses server-held opaque credential metadata to exercise expiry and
audience decisions; it does not issue or validate real OAuth/JWT tokens. The tool
request is MCP-shaped JSON-RPC `tools/call` with adapter-specific arguments and
approval metadata. General MCP initialization/session/streaming negotiation is not
implemented. Field rules, operation IDs and approval tokens are this fixture's
contract, not standard MCP fields.

State is read through the separately authenticated fixture control endpoint. Verify
compares the expected record update and event with the actual state on success,
and requires unchanged state on denial. A server that denies every request fails
the positive controls. A denied response alone cannot earn PASS.

The control endpoint is a trusted test observer. These tests do not establish that
a compromised server cannot forge its own telemetry or that production data is
independently observed. That requires an appropriate external observer adapter.

## Explicit live opt-in

Existing scans remain passive. Both options are required, and `--allow-live-tests`
must be supplied on the command line; an auto-loaded YAML file cannot grant live
execution consent:

```bash
blastcontain-verify --target-type mcp --target-id synthetic \
  --mcp-config mcp.json --policy policy.json \
  --validate-controls validation.json --allow-live-tests \
  --output audit.json --report report.md
```

Example manifest (the fixture must already be running):

```json
{
  "adapter": "customer-record-v1",
  "target_id": "synthetic",
  "mcp_url": "http://127.0.0.1:8080/mcp",
  "control_url": "http://127.0.0.1:8081",
  "admin_token_env": "VERIFY_FIXTURE_ADMIN_TOKEN"
}
```

Both URLs must use literal loopback IPs. The MCP URL must exactly match the selected
passive target. Remote deployments, stdio, agent targets and arbitrary request
scripts are not supported by this adapter. The admin token must be present in the
named environment variable, distinct from issued caller credentials. Passive
coverage must be complete first; existing configuration findings do not block tests.

The validator disables environment proxies and redirects, limits each uncompressed response to
64 KiB and HTTP phase timeouts to three seconds, and checks a 60-second test
budget between requests and response chunks. In-flight I/O can overrun the deadline
until its timeout; this is not a hard process cancellation deadline. A bounded
cleanup attempt is reserved. At most 100 requests, including cleanup,
are allowed. No retry loop repeats a possibly successful write.

Every run creates a unique fixture namespace and deletes only that namespace in a
finally block. Cleanup failure or unavailable/malformed evidence makes the overall
assessment ERROR and incomplete. If the service becomes unreachable, its run data
may remain until the fixture is shut down. The fixture stores only synthetic data
in memory. Control-check suppression is rejected; the existing `--acknowledge-risk`
report-only exit override still applies, so consume packet status and coverage.

Artifacts contain case labels, outcomes, HTTP status and state hashes, never raw
responses or fixture credentials. State hashes are evidence of observed changes,
not cryptographic attestation by an independent witness.

## Still to come

Additional production integration adapters; agent control validation; actual OAuth token validation;
concurrent/distributed budget and replay tests; egress/redirect tests; delegation;
queued and in-flight revocation; and independently observed production effects.
Drill's adversarial tests and Charter governance remain later stages.
