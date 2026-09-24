# BlastContain GUI — secure development cage

> Why this exists: through 2025–2026 the npm registry has been under continuous
> supply-chain attack — self-replicating worms (Shai-Hulud / "Mini Shai-Hulud"),
> credential stealers in popular packages (`node-ipc`, `@bitwarden/cli`), a RAT
> in `axios`, typosquats harvesting AWS/Vault/CI secrets, and dependency-confusion
> recon payloads. The common thread: **payloads run at `npm install` time and at
> dev/build time, and they hunt for credentials, network egress, and your npm
> publish token.**
>
> So we never run npm on the host. All npm/Node work happens inside a hardened,
> credential-free Podman container. This is BlastContain's own thesis applied to
> itself: *Verify proves the cage; the cage contains the blast radius.*

## The rule

**Never run `npm`, `npx`, `pnpm`, `yarn`, or `node` against this project on your
Windows host.** Use `gui/dev.ps1`, which runs everything in the cage.

```powershell
pwsh gui/dev.ps1 build         # build the cage image
pwsh gui/dev.ps1 verify-cage   # PROVE the lockdown (do this first)
pwsh gui/dev.ps1 scaffold      # one-time: create the Next.js app in gui/web
pwsh gui/dev.ps1 install       # install dependencies (no scripts run)
pwsh gui/dev.ps1 dev           # dev server on http://127.0.0.1:3000
pwsh gui/dev.ps1 build-app     # production build, fully offline
pwsh gui/dev.ps1 audit         # npm audit
```

## What the cage stops, and how

| Control | Flag / setting | Attack it blunts |
|---|---|---|
| **No host credentials** | only `gui/web` is bind-mounted; no `$HOME`, `.ssh`, `.aws`, `.npmrc` token, env secrets, or Podman socket | credential & token theft, worm self-propagation via your npm token |
| **No install scripts** | `ignore-scripts=true` (image env + `.npmrc`) + `npm ci --ignore-scripts` | pre/install/postinstall payloads — the #1 trigger |
| **Integrity-checked installs** | `npm ci` against a committed `package-lock.json` (SRI hashes) | silent malicious-version resolution |
| **Packages stay off your disk** | `node_modules`, `.next`, caches live in **Podman named volumes inside the VM** | nothing executable is written to the Windows filesystem |
| **Non-root** | `USER node` (uid 1000) + `--user node` | container-escape leverage |
| **No privilege escalation** | `--security-opt no-new-privileges`, `--cap-drop ALL` | setuid / capability abuse |
| **Read-only root** | `--read-only` + tmpfs `/tmp` + writable volumes only | tampering with the toolchain |
| **Offline production build** | `build-app` runs `--network none` | exfiltration by code that runs at build time |
| **Loopback-only dev port** | `-p 127.0.0.1:3000:3000` | exposure to the LAN |
| **Reproducible base** | pin `FROM node:22-...@sha256:<digest>` | a swapped base image |

## The two-phase model

1. **Install (network on, but no code runs).** `npm ci --ignore-scripts` fetches
   packages over the network, but because lifecycle scripts are disabled, **no
   package code executes during install** — so there is nothing to exfiltrate
   even though the network is up. Packages land in a volume, not on your disk.
2. **Run (code runs, network scoped).** Dependency code only executes when your
   app imports it — at dev or build time.
   - `build-app` runs **fully offline** (`--network none`): even a malicious
     dependency that executes during bundling cannot phone home.
   - `dev` needs a network namespace to publish its port, so outbound is
     technically possible — see residual risk below.

## Residual risk (be honest)

- **Dev-server egress.** The dev server (`dev`) has outbound network. The
  mitigations are that there are **no credentials to steal** and the dependency
  set was installed with scripts disabled — but code in `node_modules` does run
  when imported. Treat new dependencies as untrusted: prefer `build-app`
  (offline) for anything you don't need live reload for, and review `npm audit`.
- **Writes into `gui/web`.** The cage can write to the mounted source directory
  (that's how editing works). A dev-time payload could therefore modify files in
  `gui/web` — but **only** there (never `.git`, the Python server, your home, or
  credentials), and any change shows up in `git diff` for review.
- **Base image trust.** We start from the official Node image. Pin it by digest
  (`dev.ps1 build` prints the digest) so it can't be silently swapped.

## Notes & knobs

- **Allow a script for ONE trusted package** (e.g. a native module that needs a
  build step): `pwsh gui/dev.ps1 install -- rebuild <pkg> --ignore-scripts=false`
- **Maximum isolation (optional):** pin the registry to before the recent attack
  wave when generating the lockfile —
  `pwsh gui/dev.ps1 install -- install --ignore-scripts --before 2026-05-01`,
  then commit `package-lock.json` and use plain `install`/`dev` thereafter.
- **Podman VM memory.** On Windows the Podman machine is WSL2, so memory comes
  from WSL's global config (default: ~50% of host RAM — `podman machine list`
  shows a cosmetic value instead; check truth with `podman machine ssh free -h`).
  To cap or raise it, set `[wsl2] memory=...` in `%USERPROFILE%\.wslconfig` and
  restart WSL (`wsl --shutdown`).
- **Talking to the FastAPI backend**: `pwsh gui/dev.ps1 dev real` proxies
  same-origin `/api/*` to the platform server. Note `host.containers.internal`
  resolves to the podman bridge (the WSL VM), **not** the Windows host — the
  host is the VM's default gateway, which `dev real` discovers automatically
  (override with `BLASTCONTAIN_API_URL`). The backend must listen on `0.0.0.0`.
