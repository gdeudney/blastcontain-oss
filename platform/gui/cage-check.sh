#!/bin/sh
# BlastContain GUI — cage self-test.
# Proves the runtime lockdown that keeps malicious npm packages away from the
# Windows host, your credentials, and your npm token. Exits non-zero on any FAIL.
#
# Run it with the real dev hardening flags:  pwsh gui/dev.ps1 verify-cage

fail=0
ok()   { printf '  [ PASS ]  %s\n' "$1"; }
bad()  { printf '  [ FAIL ]  %s\n' "$1"; fail=1; }
note() { printf '  [ .... ]  %s\n' "$1"; }

echo "BlastContain GUI — cage check"
echo "============================="

# 1. Non-root inside the container.
uid=$(id -u)
if [ "$uid" -ne 0 ] 2>/dev/null; then
  ok "non-root (uid=$uid user=$(id -un 2>/dev/null))"
else
  bad "running as ROOT inside the container — image must set 'USER node'"
fi

# 2. All Linux capabilities dropped.
cap=$(sed -n 's/^CapEff:[[:space:]]*//p' /proc/self/status)
if [ "$cap" = "0000000000000000" ]; then
  ok "all capabilities dropped (CapEff=$cap)"
else
  bad "capabilities present (CapEff=$cap) — run with --cap-drop ALL"
fi

# 3. Privilege escalation blocked.
nnp=$(sed -n 's/^NoNewPrivs:[[:space:]]*//p' /proc/self/status)
if [ "$nnp" = "1" ]; then
  ok "no_new_privs=1 (setuid escalation blocked)"
else
  bad "no_new_privs=$nnp — run with --security-opt no-new-privileges"
fi

# 4. Read-only root filesystem.
if touch /cage-probe 2>/dev/null; then
  rm -f /cage-probe
  bad "root filesystem is WRITABLE — run with --read-only"
else
  ok "root filesystem is read-only"
fi

# 5. npm lifecycle scripts disabled (the #1 supply-chain payload trigger).
isc=$(npm config get ignore-scripts 2>/dev/null)
if [ "$isc" = "true" ]; then
  ok "npm ignore-scripts=true (install/postinstall payloads neutralized)"
else
  bad "npm ignore-scripts=$isc — lifecycle scripts could execute"
fi

# 6. No host credentials, container sockets, or Windows drives reachable.
#    A socket is always a leak; a dir/file only counts if it is non-empty (an
#    empty system mountpoint such as a masked /run/secrets is harmless).
hits=""
for p in /root/.ssh /home/node/.ssh /root/.aws /home/node/.aws \
         /root/.config/gcloud /home/node/.config/gcloud \
         /root/.npmrc /home/node/.npmrc \
         /run/secrets /run/secrets/rhsm \
         /var/run/docker.sock /run/docker.sock \
         /var/run/podman/podman.sock /run/podman/podman.sock \
         /mnt/c /mnt/wsl; do
  [ -e "$p" ] || continue
  if [ -S "$p" ]; then
    hits="$hits $p"
  elif [ -d "$p" ]; then
    [ -n "$(ls -A "$p" 2>/dev/null)" ] && hits="$hits $p"
  elif [ -s "$p" ]; then
    hits="$hits $p"
  fi
done
if [ -z "$hits" ]; then
  ok "no host creds / container sockets / Windows drives mounted"
else
  bad "host-sensitive path(s) reachable in the cage:$hits"
fi

# 7. No credential-shaped environment variables leaked in.
leak=$(env | grep -iE '(secret|password|passwd|api[_-]?key|access[_-]?key|_token)=|^AWS_|^GH_TOKEN=|^GITHUB_TOKEN=|^NPM_TOKEN=' | grep -ivE '^NPM_CONFIG_' || true)
if [ -z "$leak" ]; then
  ok "no credential-shaped environment variables present"
else
  bad "credential-shaped env var(s) present:"
  printf '%s\n' "$leak" | sed 's/=.*/=<redacted>/; s/^/            /'
fi

# 8. node_modules kept in a volume (off the Windows disk) — informational.
if grep -q ' /app/node_modules ' /proc/self/mounts 2>/dev/null; then
  ok "/app/node_modules is a volume mount (packages stay in the VM, off your disk)"
else
  note "/app/node_modules not mounted yet (expected before the first install)"
fi

echo "============================="
if [ "$fail" -eq 0 ]; then
  echo "CAGE OK — the container is locked down."
else
  echo "CAGE NOT SECURE — address the FAIL lines above before installing anything."
fi
exit $fail
