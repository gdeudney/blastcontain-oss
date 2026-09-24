# BlastContain console prototype

Draft extraction from PR #20. This preserves the Fleet view and Charter wizard,
typed API client, mock responses, and the pinned Podman development toolbox.
The default is mock mode. The server implementation is reviewed separately.

Use the container workflow in [../SECURITY.md](../SECURITY.md), with commands
run from `platform/`: `pwsh gui/dev.ps1 build`, `verify-cage`, `install`, then
`build-app`. The source is intentionally isolated from host credentials.

Baseline on 2026-09-24: the sandbox check, ESLint, TypeScript, and an offline
Turbopack production build pass. The toolbox defaults to development mode;
`build-app` now explicitly selects `NODE_ENV=production`. Dependency audit reports
seven affected packages (one critical, five high, one moderate), so this remains
a draft. Browser and real-backend flows have not been validated.

Before merge:

- Refresh and audit the dated dependency lock and pinned toolbox image.
- Pass a production build, lint, and browser tests inside the sandbox.
- Replace the long-lived bearer token in browser local storage with a reviewed
  authentication/session design and test the real server path.
- Verify the API types against the server schema and review errors and
  authorization failures in every wizard step.
- Revalidate the containment checks (a failed write to `/` by an unprivileged
  user alone does not prove a read-only mount).

This draft does not change the existing Drill workbench or release workflows.
