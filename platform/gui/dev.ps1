#requires -Version 5.1
<#
  BlastContain GUI - containerized, credential-free npm workflow (Podman).

  Never run host npm. Every npm/node action happens inside the hardened cage
  defined by gui/Containerfile, so malicious packages cannot reach the Windows
  host, your credentials, or your npm token. See gui/SECURITY.md for the model.

  Layout:
    gui/        the cage tooling (image build context)   (you are here)
    gui/web/    the Next.js app (created by 'scaffold')   (bind-mounted source)

  Commands:
    build         Build (or rebuild) the cage image; prints the base digest to pin.
    verify-cage   Prove the lockdown (run this before installing anything).
    scaffold      One-time: create the Next.js app inside the cage.
    install       Install deps from package.json/lockfile (no scripts run).
    dev [mode]    Hot-reload dev server on http://127.0.0.1:3000 (mode: mock|real)
    build-app     Production build, fully OFFLINE (--network none).
    audit         npm audit inside the cage.
    shell         Debug shell inside the cage (no network).
    clean         Remove the app's volumes (node_modules, caches).
    help          Show this help.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string]$Command = 'help',
  [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
  [string[]]$Rest
)

$ErrorActionPreference = 'Stop'

# --- Paths and names ----------------------------------------------------------
$GuiDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Join-Path $GuiDir 'web'
$Image  = 'blastcontain-gui-toolbox'
$Base   = 'docker.io/library/node:22-bookworm-slim'
$Port   = 3000

# Named volumes live inside the Podman VM - never on your Windows disk.
$VolModules = 'blastcontain-gui-node_modules'
$VolNext    = 'blastcontain-gui-next'
$VolCache   = 'blastcontain-gui-cache'

# Podman's WSL machine sees the Windows C: drive at /mnt/c. Bind mounts MUST use
# that in-VM path, not the Windows 'C:\...' form (which silently mounts a
# throwaway VM-local dir instead of your real folder, losing all writes).
$AppFull  = [System.IO.Path]::GetFullPath($AppDir)
$AppMount = '/mnt/' + $AppFull.Substring(0, 1).ToLowerInvariant() + ($AppFull.Substring(2) -replace '\\', '/')

# --- Helpers ------------------------------------------------------------------
function Require-Podman {
  if (-not (Get-Command podman -ErrorAction SilentlyContinue)) {
    throw "podman not found on PATH. Install Podman Desktop and run 'podman machine start'."
  }
}

function Ensure-AppDir {
  if (-not (Test-Path $AppDir)) { New-Item -ItemType Directory -Force -Path $AppDir | Out-Null }
}

# Security flags shared by every container run.
function Sec-Flags {
  @(
    '--user', 'node',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m',
    '--tmpfs', '/run/secrets:ro,noexec,nosuid,size=16k',  # mask the VM's RHSM subscription mount
    '--pids-limit', '2048'
  )
}

# Allocate a TTY only when attached to a real console (manual use). Under
# automation/CI there is no TTY and '-it' would misbehave.
function Tty-Flags {
  if ([Console]::IsInputRedirected) { @() } else { @('-it') }
}

# Source bind (rw) + node_modules/.next/cache volumes. ':U' chowns each volume to
# the 'node' user so the read-only-rootfs container can still write to them.
function Mount-Flags {
  @(
    '-v', ("{0}:/app:rw"             -f $AppMount),
    '-v', ("{0}:/app/node_modules:U" -f $VolModules),
    '-v', ("{0}:/app/.next:U"        -f $VolNext),
    '-v', ("{0}:/cache:U"            -f $VolCache)
  )
}

function Invoke-Podman {
  param([string[]]$PodArgs)
  Write-Host ("podman " + ($PodArgs -join ' ')) -ForegroundColor DarkGray
  & podman @PodArgs
  if ($LASTEXITCODE -ne 0) { throw "podman exited with code $LASTEXITCODE" }
}

function Show-Help {
  Write-Host ""
  Write-Host "BlastContain GUI cage - never run host npm; everything runs in Podman." -ForegroundColor Cyan
  Write-Host ""
  Write-Host "  pwsh gui/dev.ps1 COMMAND"
  Write-Host ""
  Write-Host "    build         Build/rebuild the cage image (prints base digest to pin)"
  Write-Host "    verify-cage   Prove the lockdown - run before installing anything"
  Write-Host "    scaffold      One-time: create the Next.js app in gui/web"
  Write-Host "    install       Install deps (no lifecycle scripts run)"
  Write-Host ("    dev [mock|real]  Hot-reload dev server -> http://127.0.0.1:{0} ('real' proxies /api/* to the platform server)" -f $Port)
  Write-Host "    build-app     Production build, fully offline"
  Write-Host "    gen-api       Regenerate the typed API client from server/docs/openapi.yaml"
  Write-Host "    audit         npm audit inside the cage"
  Write-Host "    shell         Debug shell inside the cage (no network)"
  Write-Host "    clean         Remove app volumes (node_modules, caches)"
  Write-Host ""
  Write-Host "  See gui/SECURITY.md for the threat model and controls." -ForegroundColor DarkGray
  Write-Host ""
}

# --- Commands -----------------------------------------------------------------
switch ($Command.ToLowerInvariant()) {

  'build' {
    Require-Podman
    Invoke-Podman @('build', '-t', $Image, $GuiDir)
    Write-Host ""
    $digest = (& podman image inspect $Base --format '{{.Digest}}' 2>$null)
    if ($digest) {
      Write-Host "Base image digest (pin this in gui/Containerfile for full integrity):" -ForegroundColor Cyan
      Write-Host ("  FROM {0}@{1}" -f $Base, $digest) -ForegroundColor Cyan
    }
    Write-Host ""
    Write-Host "Next:  pwsh gui/dev.ps1 verify-cage" -ForegroundColor Green
  }

  'verify-cage' {
    Require-Podman
    # No source, no node_modules - just the cage + the real dev hardening flags.
    $a = @('run', '--rm') + (Sec-Flags) + @(
      '--network', 'none',
      '-v', ("{0}:/cache:U" -f $VolCache),
      $Image, '/usr/local/bin/cage-check'
    )
    Invoke-Podman $a
  }

  'scaffold' {
    Require-Podman
    Ensure-AppDir
    # Volume mountpoints (node_modules/.next) trip create-next-app's empty-dir
    # check, and --skip-install needs neither: mount only the source + cache.
    # Also drop empty mountpoint dirs a previous container run left behind.
    foreach ($d in 'node_modules', '.next') {
      $p = Join-Path $AppDir $d
      if ((Test-Path $p) -and -not (Get-ChildItem $p -Force -ErrorAction SilentlyContinue | Select-Object -First 1)) {
        Remove-Item $p -Force
      }
    }
    Write-Host "Scaffolding Next.js into gui/web (first real package download)..." -ForegroundColor Yellow
    $cna = @(
      'create-next-app@15', '.',
      '--typescript', '--eslint', '--app', '--tailwind',
      '--src-dir', '--import-alias', '@/*',
      '--use-npm', '--skip-install', '--yes'
    )
    # create-next-app probes its PARENT dir for write access (it may mkdir the
    # target). /app's parent is the read-only rootfs, so for this one command
    # the source mounts at /work/app under a small writable tmpfs parent.
    $scaffoldMounts = @(
      '--tmpfs', '/work:rw,nosuid,size=16m',
      '-v', ("{0}:/work/app:rw" -f $AppMount),
      '-v', ("{0}:/cache:U" -f $VolCache)
    )
    $a = @('run', '--rm') + (Tty-Flags) + (Sec-Flags) + $scaffoldMounts + @('-w', '/work/app', $Image, 'npx', '-y') + $cna
    Invoke-Podman $a

    # create-next-app refuses to run if .npmrc pre-exists, so drop it in afterwards.
    $npmrc = @"
# Hardened npm defaults (the cage also enforces these). Never run host npm.
ignore-scripts=true
audit=true
fund=false
save-exact=true
update-notifier=false
"@
    Set-Content -Path (Join-Path $AppDir '.npmrc') -Value $npmrc -Encoding ascii
    Write-Host ""
    Write-Host "Scaffold complete. Review gui/web/package.json, then:" -ForegroundColor Green
    Write-Host "  pwsh gui/dev.ps1 install" -ForegroundColor Green
  }

  'install' {
    Require-Podman
    Ensure-AppDir
    if ($Rest) {
      $npmArgs = $Rest
    }
    elseif (Test-Path (Join-Path $AppDir 'package-lock.json')) {
      $npmArgs = @('ci', '--ignore-scripts')          # exact, integrity-checked
    }
    else {
      $npmArgs = @('install', '--ignore-scripts')     # first run: generate lockfile
    }
    # Network ON to fetch packages; ignore-scripts means no package code executes.
    $a = @('run', '--rm') + (Tty-Flags) + (Sec-Flags) + (Mount-Flags) + @('-w', '/app', $Image, 'npm') + $npmArgs
    Invoke-Podman $a
    Write-Host ""
    Write-Host "Done. Commit gui/web/package-lock.json, then:  pwsh gui/dev.ps1 dev" -ForegroundColor Green
  }

  'dev' {
    Require-Podman
    Ensure-AppDir
    # API mode: 'pwsh gui/dev.ps1 dev real' (or $env:NEXT_PUBLIC_API_MODE).
    # 'mock' (default) needs no backend; 'real' proxies same-origin /api/* to
    # the platform server. NOTE: host.containers.internal resolves to the
    # podman bridge gateway (the WSL VM), NOT the Windows host — verified
    # ECONNREFUSED. The Windows host is the VM's default gateway, which is
    # dynamic per WSL boot, so 'real' discovers it unless BLASTCONTAIN_API_URL
    # is set explicitly.
    $apiMode = if ($Rest -and $Rest[0]) { $Rest[0] }
               elseif ($env:NEXT_PUBLIC_API_MODE) { $env:NEXT_PUBLIC_API_MODE }
               else { 'mock' }
    if ($apiMode -notin @('mock', 'real')) {
      throw "dev API mode must be 'mock' or 'real', got '$apiMode'"
    }
    $envFlags = @('-e', ("NEXT_PUBLIC_API_MODE={0}" -f $apiMode))
    if ($apiMode -eq 'real') {
      $apiUrl = $env:BLASTCONTAIN_API_URL
      if (-not $apiUrl) {
        $route = & podman machine ssh "ip -4 route show default"
        $gw = if ("$route" -match 'via\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $Matches[1] } else { $null }
        if (-not $gw) {
          throw "could not discover the WSL gateway (Windows host); set BLASTCONTAIN_API_URL explicitly"
        }
        $apiUrl = "http://{0}:8080" -f $gw
      }
      $envFlags += @('-e', ("BLASTCONTAIN_API_URL={0}" -f $apiUrl))
      Write-Host ("  /api/* -> {0} (WSL gateway = Windows host)" -f $apiUrl) -ForegroundColor DarkGray
    }
    Write-Host ("Dev server -> http://127.0.0.1:{0}  (API mode: {1}; Ctrl+C to stop)" -f $Port, $apiMode) -ForegroundColor Green
    $a = @('run', '--rm') + (Tty-Flags) + @('--name', 'blastcontain-gui-dev') + (Sec-Flags) + (Mount-Flags) + $envFlags + @(
      '-p', ("127.0.0.1:{0}:{1}" -f $Port, $Port),
      '-w', '/app',
      $Image, 'node_modules/.bin/next', 'dev', '-H', '0.0.0.0', '-p', "$Port"
    )
    Invoke-Podman $a
  }

  'build-app' {
    Require-Podman
    Ensure-AppDir
    # Production build needs no network -> fully offline, so even a malicious
    # dependency that runs at build time cannot exfiltrate anything.
    $a = @('run', '--rm') + (Tty-Flags) + (Sec-Flags) + (Mount-Flags) + @(
      '--network', 'none', '-w', '/app',
      $Image, 'node_modules/.bin/next', 'build'
    )
    Invoke-Podman $a
  }

  'gen-api' {
    Require-Podman
    Ensure-AppDir
    # Single source of truth is server/docs/openapi.yaml — copy it in, then
    # generate the typed client OFFLINE in the cage (codegen executes JS).
    $spec = Join-Path (Split-Path -Parent $GuiDir) 'server\docs\openapi.yaml'
    if (-not (Test-Path $spec)) { throw "spec not found: $spec" }
    $apiDir = Join-Path $AppDir 'api'
    if (-not (Test-Path $apiDir)) { New-Item -ItemType Directory -Force -Path $apiDir | Out-Null }
    Copy-Item $spec (Join-Path $apiDir 'openapi.yaml') -Force
    $a = @('run', '--rm') + (Tty-Flags) + (Sec-Flags) + (Mount-Flags) + @(
      '--network', 'none', '-w', '/app',
      $Image, 'node_modules/.bin/openapi-typescript', 'api/openapi.yaml',
      '-o', 'src/lib/api/schema.d.ts', '--default-non-nullable=false'
    )
    Invoke-Podman $a
    Write-Host "Generated src/lib/api/schema.d.ts from server/docs/openapi.yaml" -ForegroundColor Green
  }

  'audit' {
    Require-Podman
    Ensure-AppDir
    $a = @('run', '--rm') + (Tty-Flags) + (Sec-Flags) + (Mount-Flags) + @('-w', '/app', $Image, 'npm', 'audit') + $Rest
    Invoke-Podman $a
  }

  'shell' {
    Require-Podman
    Ensure-AppDir
    $a = @('run', '--rm') + (Tty-Flags) + (Sec-Flags) + (Mount-Flags) + @('--network', 'none', '-w', '/app', $Image, 'bash')
    Invoke-Podman $a
  }

  'clean' {
    Require-Podman
    foreach ($v in @($VolModules, $VolNext, $VolCache)) {
      & podman volume rm $v 2>$null | Out-Null
    }
    Write-Host "Removed app volumes. Image '$Image' kept (rebuild with: dev.ps1 build)." -ForegroundColor Yellow
  }

  default { Show-Help }
}
