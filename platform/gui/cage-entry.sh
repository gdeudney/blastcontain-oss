#!/bin/sh
# BlastContain GUI cage entrypoint.
# Named volumes mount empty, so make sure the writable dirs (npm cache, HOME)
# exist, then hand off to the requested command. No network, no secrets here.
mkdir -p "${NPM_CONFIG_CACHE:-/cache/npm}" "${HOME:-/cache/home}" 2>/dev/null || true
exec "$@"
