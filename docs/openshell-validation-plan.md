# OpenShell containment integration and Ubuntu agent-host pilot

Status: planned, 2026-10-02. No OpenShell deployment or adapter is validated by
this document. This extends the [technical security checklist](technical-security-checklist.md)
and the [Drill integration plan](../drill/docs/integration-redesign-plan.md).

## Objective and sequence

Add OpenShell as a supported containment runtime beneath BlastContain. Preserve
the agreed order for agents and MCP servers: **Verify assessment → practical
control validation → Drill adversarial testing → Charter reconciliation**.
Organizations decide acceptable access, approvals, exceptions, and governance.
Tool results provide bounded technical evidence, not security certification.

The next practical pilot is one research/coding worker on an Ubuntu MacBook,
with a separate VM boundary, followed by a comparison on the existing Ubuntu
iMac. Keep the working iMac deployment until the pilot passes. This plan does
not authorize host migration, reboots, credential changes, or agent deployment.

## Deployment context

The user reports Macs configured with Ubuntu for agents. The setup discussion
also reports the following baseline; these are planning inputs, not fresh host
inspection or attestation. Keep addresses, credentials, and operational inventory
in private deployment records, outside this repository.

| System | Reported state / proposed role | Qualification still required |
|---|---|---|
| Intel iMac | Existing research agent inside a container in a dedicated KVM VM; dashboard display | Record the actual host/guest/container isolation and management-network paths |
| Intel MacBook Pro | Ubuntu installed, 16 GB RAM, KVM available; first OpenShell pilot worker | Check installed kernel/runtime, memory, storage, CPU mitigations and sustained workload health |
| Main AMD computer | Existing Qwen inference service | Permit only the approved inference API; exclude model-server administration and unrelated services |
| Separate monitoring computer | Intended location for traces, security events, health checks and alerts | Hardware sizing and observability backend selection remain open |
| NAS | Archive and backup destination for the monitoring system | Scoped archive account and restore test; no worker NAS credentials or direct archive access |

rEFInd was reported configured to default to Ubuntu on both Macs; reboot
verification was still outstanding in the setup discussion. Do not turn that
configuration report into a claim of tested recovery. The initial pilot keeps
inference outside the worker VM and does not require GPU passthrough.

## Responsibility boundaries

| Component | Planned responsibility |
|---|---|
| OpenShell | External filesystem, process, network and provider-credential enforcement for each supported workload |
| Verify | Inspect effective configuration and validate allowed/denied behavior in the actual workload identity and sandbox |
| Drill | Exercise authorized hostile inputs and misuse of permitted capabilities; observe effects independently |
| Guard | Action-specific authorization and exact-action approval through an enforced integration; evaluate OpenShell for portions of the currently planned external services |
| Charter / discovery | Later record intended and observed agent/tool relationships, ownership, permissions, policy revisions and exceptions |
| Observability | Correlate application traces with independently collected runtime/security events; keep the backend replaceable |
| Scout | Map relevant papers/advisories to proposed and implemented scenarios, without treating a mapping as reproduction evidence |

An agent sandbox does not contain a remote MCP server. Assess each server in its
own runtime where access is available; otherwise record missing runtime evidence.
Represent agent → agent, agent → MCP, and MCP → downstream-service relationships
separately. Shared caches, storage and credential brokers are also relationships.

Keep untrusted research, disposable coding, restricted private retrieval and
privileged publishing as separate workload profiles. Treat summaries and model
handoffs as untrusted data. The privileged executor receives bounded actions,
caller identity and provenance; it does not inherit authority from a summary or
an incoming scheduled/message trigger. An in-process Guard callback alone cannot
prevent a compromised worker from making a direct request.

## Deliverables and acceptance gates

### OS-0 — Qualify one host and record the baseline

Deliver a private deployment manifest covering host and guest OS/kernel,
architecture, virtualization, mitigations, runtime/driver versions, image digests,
OpenShell release, policy revision, network boundaries and resource limits.
Check requirements against the pinned release, not the moving `latest` docs.
Define rollback, resource budgets and a safe maintenance window. Confirm the
chosen runtime inside the VM actually supports the required controls.

Acceptance: qualification evidence identifies every boundary and unresolved
requirement. Missing kernel/runtime support blocks this profile; no silent
fallback to a host process or less restricted environment. No claim of Apple
Silicon, GPU passthrough, or all-Mac compatibility follows from one Intel pilot.

### OS-1 — Establish a useful reference workload and external evidence

Deliver a version-pinned reference deployment with separate research and coding
policies, synthetic fixtures, one disposable repository, approved inference and
search/fetch routes, and narrowly scoped dependency access. Management interfaces,
container sockets, home directories and archive credentials stay outside the
worker. Add a separately authorized executor fixture for publishing tests.

Collect application traces through OpenTelemetry where practical. Langfuse is a
candidate, not a required dependency: the other setup discussion is evaluating
alternatives. Send OpenShell OCSF records to a durable external collector. Use
trusted mappings for run, host, VM, sandbox, agent/tool, policy and trace IDs;
retain producer identity, timestamps, delivery gaps and policy hashes. Redact
content and credentials before export. Application traces are not authoritative
proof of containment. Alert on missing logs as well as denied actions.

Acceptance: a bounded useful task succeeds; logs remain readable after worker
deletion and collector restart; the worker cannot delete collected records or
modify collection rules. Demonstrate loss detection and archive restoration.
Record measured resource use before selecting fleet size or the monitoring stack.

### OS-2 — Extend Verify assessment and validate controls

Deliver an opt-in OpenShell assessment/profile and replayable positive/negative
fixtures. Inspect the effective policy, including provider-contributed access,
observed enforcement mode, degradation events and policy revision. Reuse existing
`agent-sandbox-v1` checks where their semantics apply; add dedicated proxy/API
probes rather than claiming its four current checks cover OpenShell completely.
Retain explicit live-test consent and bounded, operator-owned endpoints.

Run probes through the agent's actual identity, launcher, mounts and policy.
Collect host/VM evidence separately through a trusted harness: a container's
observations cannot attest the hypervisor. Present shared-kernel findings at the
correct boundary without suppressing them merely because a VM is declared.

Include the field feedback from the older Verify 0.4.1 deployment scan: a custom
`TOOLS_TOKEN` environment variable was missed. Add synthetic tests for custom
credential names, empty values, placeholders and non-secret token settings;
report names/reasons/confidence without values. Describe a negative scan as no
matching credentials detected, not proof that credentials are absent. Verify
provider mediation by testing whether the real credential remains unreadable
and whether it is supplied only at the intended endpoint. Do not assume that
attaching OpenShell removes application environment secrets automatically.

| Control | Positive control | Required negative / failure case |
|---|---|---|
| Filesystem and credentials | Read public canary; create and remove a workspace file | Deny planted private-file access and protected writes; detect incomplete filesystem-policy application |
| Network and API policy | Approved inference/search and a specific permitted API operation succeed | Deny forbidden destinations, management services, writes on a read-only API, and redirect/proxy bypasses |
| Provider binding | Controlled endpoint receives the intended synthetic credential | Worker cannot recover it or cause injection into an unrelated host/path; exceptions are visible |
| Privilege and resources | Useful task completes within declared limits | Deny privilege changes; verify resource limits and independent timeout/termination |
| Policy and approval | Approved exact action succeeds once | Changed recipient/record/arguments, expired approval and replay fail; a durable endpoint approval is reported as a policy expansion |
| Evidence and revocation | Correlated external observations are retained | Detect missing logs; stop already-running tools and revoke access, not only model inference |

Acceptance: run hardened and deliberately weakened fixture configurations.
The weakened fixture must be detected, while the useful positive control still
works in the hardened fixture. Missing/unhealthy fixtures and unsupported probes
remain explicit ERROR/SKIP/incomplete results, never PASS. Signed reports record
scope, versions, policy hashes, observations, limitations and cleanup evidence.
Each deployed MCP server has separate coverage. Required checks cannot be waived
by agent-controlled input or a failed upstream service.

### OS-3 — Add an OpenShell target environment to Drill

After OS-2 passes, deliver a bounded runtime/target adapter through the existing
suite plan, acceptance, lock, broker, evidence and cancellation contracts. An
OpenShell runtime is not an attack-strategy plugin. Preserve the current rootless
Podman isolation for third-party attack workers; replacing that boundary requires
its own conformance work. Keep attacker, target, evaluator and policy authority
separate. Existing local abliterated-attacker support remains available through
the broker, subject to the same budget and endpoint restrictions.

Initial scenarios: poisoned repository instructions/build scripts, malicious MCP
metadata and responses, misuse of allowed destinations, credential misuse,
approval argument substitution/replay, policy expansion attempts, and a poisoned
agent-to-agent handoff. Test both agents and operator-owned MCP fixtures. Use
synthetic secrets and controlled effect witnesses; the target cannot author its
own success verdict. Measure legitimate task completion alongside attack outcomes.

Acceptance: deterministic resistant/vulnerable controls produce the expected
observed effects; timeout, cancellation, revocation and cleanup leave no active
test workloads. Lock deployment/policy identities and reject stale acceptance
after relevant changes. Live-model runs record model/configuration, repeated
trials and uncertainty. No generic remote-MCP or kernel-escape coverage claim.

### OS-4 — Reconcile Guard and Charter, then expand the fleet

Deliver the reviewed mapping from Charter requirements to OpenShell capabilities
and Guard/MCP/API enforcement. Unsupported requirements fail explicitly rather
than compiling to a weaker rule. Compare intended, effective and observed access
and show expansions or missing evidence. Keep policy administration and approval
authority outside untrusted workers. Organization-specific approval rules remain
operator decisions, not model-generated authorization.

Acceptance: changing a Charter, provider binding or runtime policy causes the
appropriate revalidation; exact-action approval is independently enforced; the
relationship graph preserves caller identity and highlights cascading exposure.
Existing server authentication/authorization and console security blockers must
be resolved before those draft components administer a real fleet.

Roll out to the iMac only after the MacBook pilot meets its gates, resource budget
and rollback test. Qualify each additional host independently. Host-event detection
(for example Falco) is later work; additional scanners/evaluation engines enter
through the existing adapter, license-review and acceptance process rather than
creating a competing suite runner.

## Review units and evidence

1. Host qualification template, reference deployment and external logging fixture.
2. Verify credential-detection regression and layered-runtime reporting.
3. Verify OpenShell configuration assessment, then active control-validation probes.
4. Drill runtime adapter and deterministic scenario suite, then bounded live trials.
5. Guard/Charter policy reconciliation and monitoring views; per-host rollout.

Keep these as independent PRs with rollback points. The priority starts with
Verify/control validation; unrelated Drill adapter breadth need not block it.
No dates or support claims are committed before the host/version spike completes.

Retain redacted manifests, positive and negative outcomes, external observations,
cleanup results and model/utility limits for each gate. CI covers portable
schemas and fixtures; an actual Ubuntu host/VM run is also required before
declaring support. Missing optional hardware is a disclosed skip; missing required
pilot evidence blocks rollout. For the articles, publish the chain **requirement
→ configured control → observed behavior → adversarial test → retained evidence**.

## References and version caveats

Reviewed 2026-10-02; recheck against the selected release during OS-0:

- [OpenShell source and license](https://github.com/NVIDIA/OpenShell)
- [OpenShell security guidance](https://docs.nvidia.com/openshell/latest/security/best-practices):
  additional filesystem policy can degrade under `best_effort`; request-rule
  `audit` mode forwards violations; endpoint approval changes durable policy.
  Distinguish additional-policy degradation from the mandatory Landlock baseline.
- [OpenShell log access](https://docs.nvidia.com/openshell/latest/observability/accessing-logs):
  the gateway's recent-log buffer is volatile; external durable collection is required.
- [Langfuse OpenTelemetry tracing](https://langfuse.com/docs/observability/get-started)
- [Existing Verify sandbox profile](../verify/docs/agent-sandbox-validation.md)
- [Existing MCP assessment and coverage](../verify/docs/mcp.md)
- [Drill suite execution and current simulation limits](../drill/docs/suite-execution.md)
- [Drill isolated plugin workers](../drill/docs/plugin-workers.md)
