# Local Drill workbench

The workbench reviews the same source/plugin metadata and suite plans as
`blastcontain-drill-suite`. It uses the shared planner, exact-scope acceptance,
lock, runner, cancellation and verifier. It is a local technical security tool;
its reviewer names are operator-provided audit labels, not authenticated
organizational identities or Charter approvals.

## Start

Install Core and Drill from the same checkout. Scout is optional and must also
come from that checkout for the Research screen:

```bash
python -m pip install ./core ./drill ./tools/scout
blastcontain-drill-ui --workspace /path/to/new-private-workbench
```

Use a new directory or an existing owner-only directory, separate from the code
checkout. Open the one-use link printed in the terminal within five minutes.
The server binds only `127.0.0.1`; its default port is chosen by the OS. Keep the
terminal running. Ctrl+C cancels active work and closes the session. A second
server cannot own the same workspace.

Optional flags:

- `--signing-key /private/signing-key.pem` uses your explicit Ed25519 key. Without
  it, signatures are advisory and the UI never claims an attested pass.
- `--credential alias=ENVIRONMENT_VARIABLE` resolves host credentials. Do not paste
  secret values into a model, paper, review or metadata document.
- `--scout-database /private/research.sqlite3` explicitly selects a **writable**
  Scout database, initializing/upgrading it when required. Back up valuable
  databases with Scout's backup command before upgrading.
- `--repository /path/to/repository` checks recorded research mappings against the
  current local `origin/main`. It does not fetch, check out, accept or execute code.

## Review and run

1. **Compose suite:** select an Agent or MCP fixture, scenario sources and
   strategies. Set limits, seeds and model bindings. Provider model IDs may include
   organization/name, tags and version suffixes. Credential references remain
   host-resolved symbolic names. Advanced JSON exposes the full suite schema.
2. **Review & include:** import source snapshots and plugin manifests. Imports are
   metadata only. Review the exact digest, complete metadata, changed fields,
   license and each requested grant. Plugin acceptance, source acceptance and
   suite acceptance are separate records. The image-availability check never pulls
   an image. Build/review/install approved images outside the UI.
3. Save and inspect preflight. Unavailable images, unsupported capabilities, missing
   model roles and stale acceptance stay visible as blockers. Accept the ready
   suite's exact plan, then create its lock.
4. **Runs & evidence:** start the accepted lock. The service revalidates current
   inputs. Stop requests cancellation independently of the agent. Each browser
   start carries an idempotency key, so retrying a lost response cannot dispatch
   the same action twice within that server session.
5. Verify the evidence. Reported run state is not verification. Signature trust,
   replay completeness, security outcome, task utility and attested pass are shown separately.
   Private raw replay inputs are off by default; the explicit checkbox retains
   them for one hour. Branching/adaptive replay can be incomplete without its
   retained inputs. Use the CLI for externally supplied replay material.

Fixture actions are simulated. A model-backed target uses the configured model
endpoint, but its tool actions still occur in the supported controlled fixture.
The UI does not make arbitrary external agents or MCP servers safe to attack.

For the [AgentDojo banking environment](../plugins/agentdojo/README.md), build and
prepare its pinned image outside the UI, then import its source and manifest and
paste the prepared suite into Advanced JSON. The environment is explicitly selected
there as both environment and evaluator. Its `broker.environment` grant authorizes
the reviewed simulation oracle; inspect that authority before accepting it.

The **Research** screen shows Scout review staleness and recorded implementation
claims without turning them into validation. Reviews use Scout's current database
revision; concurrent changes require refresh. Committed mapping checks preserve
recorded history and disclose divergence. Verified case records identify their source
and scenario; with both optional launch flags, the verification response also traces
exact source/plugin identities to current Git mappings and papers. Unmapped research
remains incomplete even when the security result passes. Missing Scout/database/repository
configuration does not prevent suite work.

**Export inputs** downloads a bundle with the exact CLI document formats under
`suite`, `sources`, `plugins`, `probes`, `acceptances` and `lock`. Save these members
as individual JSON documents to use the existing suite CLI flags. The export is
not a full workspace or Scout backup and contains no private signing key or host
credential values. Imported metadata can itself contain sensitive text: handle
exports accordingly.

## Boundaries and recovery

- Launch secrets are removed from browser history immediately, exchanged once,
  then kept in per-tab session storage. There is no ambient authentication cookie.
  Every API read requires the session bearer; writes also require the exact local
  Origin. Host checks prevent rebinding to an attacker domain. No CORS is enabled.
- CSP forbids inline/external scripts, framing and form submissions. Untrusted
  metadata and results render as text. No shell, package-install, arbitrary-file
  read/write or user-selected executable route exists.
- Local users with the same OS identity can read the private workspace/session
  memory. This is not a multi-user or remotely deployed server. Do not expose it
  through a tunnel or reverse proxy; that needs a separate access-control design.
- Workspace edits carry the state and installed-code revision. A stale draft is
  preserved but disabled until **Reload latest**; reload replaces that draft.
  Import/accept/run are disabled while suite edits are unsaved.
- Metadata is content-addressed and checked when loaded. Invalid proposed catalog
  or plan changes are rejected before publishing state. Prior imported versions,
  decisions and run evidence remain available after later edits.
- Only one run is active per server; selected cases retain the runner's concurrency
  and shared budgets. HTTP requests have bounded bodies/concurrency, and the UI
  session has a 128-run limit. Restart to start a new session. No automatic package
  or data updates occur.

## Validation

Backend tests run in the normal Linux/Windows lanes. The separate browser lane
installs the pinned Playwright test extra and its Chromium build, then exercises
Agent/MCP composition, acceptance, verification, cancellation, stale edits,
metadata scope changes, research review, hostile text, responsive layout and
keyboard entry. A missing browser fails that lane rather than counting as success.

```bash
python -m pip install './drill[dev,ui-test]' ./core ./tools/scout
python -m playwright install chromium
python -m pytest drill/tests/unit/workbench drill/tests/browser -q
```

All automated browser tests use controlled fixtures, with no external model API.
These checks establish UI/control behavior, not live-model attack efficacy.
