# BlastContain Discovery

**Shadow-AI enumeration — finds ungoverned agents, copilots, and MCP servers**

> Governance that contains the blast radius.

Discovery is the P1 enumeration component of
[BlastContain](../README.md): it walks the filesystem, running processes, and
IDE/desktop copilot configs to inventory AI agents and MCP wirings, cross-references
them against the Platform registry, and emits a **signed inventory report**.
Shadow finds can bootstrap a draft Charter (derive-then-ratify) so nothing stays
ungoverned.

```bash
pip install blastcontain-discovery

blastcontain-discovery --env prod --search-path .
```

Cross-reference against a running platform and draft Charters for shadow finds:

```bash
blastcontain-discovery \
  --env prod \
  --blastcontain-url http://localhost:8080 \
  --bootstrap-charter \
  --report ./discovery-report.json
```

## Scanners

| Scanner | What it finds |
|---|---|
| `repo` | Agent/MCP config files under `--search-path` |
| `process` | Running agent processes (needs `psutil` — used-if-present, silently skipped otherwise) |
| `copilot` | IDE/desktop copilots and their MCP wirings |
| `registry` | Cross-reference against the Platform registry (`--blastcontain-url`) |

## Exit codes

`--fail-on-shadow` (default on) makes the CLI a CI gate: exit `2` when shadow AI
is found, `0` when the inventory is clean.

## Develop

```bash
pip install -e ../core -e ".[dev]"
pytest
ruff check .
```

## License

Apache-2.0 — part of the [blastcontain-oss](../README.md) monorepo.
