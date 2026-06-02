# BlastContain OSS

The Apache-2.0 open-source packages of **BlastContain**, an agent governance
platform. *(The commercial platform — Charter, Ledger, GUI — lives in a separate,
private repository and is not here.)*

| Package | What it is | PyPI |
|---|---|---|
| [`core/`](core/) | Shared types, taxonomy (MIT AI Risk · MITRE ATLAS · OWASP Agentic), Ed25519 signing, SARIF, Charter schema | `blastcontain-core` |
| [`verify/`](verify/) | Pre-deployment compliance scanner — 27 checks, SARIF, signed audit packets | `blastcontain-verify` |
| [`drill/`](drill/) | Adversarial red-team — versioned attack corpus, cage action-ground-truth, signed DrillReport | `blastcontain-drill` |

`verify` and `drill` depend on `core`. The cage trilogy: **Verify** proves the
cage is built right · **Drill** attacks the agent inside it · **Guard** (planned)
adds the runtime locks.

## Develop

Editable installs link the packages to each other's source — no need to publish
`core` to test a change in a tool:

```
pip install -e ./core -e "./verify[dev]" -e "./drill[dev]"

( cd core && pytest )
( cd verify && pytest )
( cd drill && pytest -m "not live and not podman" )

ruff check core verify drill
```

CI (`.github/workflows/ci.yml`) is **path-filtered**: it runs only the packages a
change touches — and a change to `core/**` tests everything, since the tools
depend on it. Container/compose integration tests run in `integration.yml`.

## Release

Each package versions and ships **independently** via a prefixed tag:

```
git tag core-v0.2.0   && git push origin core-v0.2.0
git tag verify-v0.3.0 && git push origin verify-v0.3.0
git tag drill-v0.1.0  && git push origin drill-v0.1.0
```

`release.yml` builds the tagged package and publishes it to PyPI (via Trusted
Publishing — configure each PyPI project's publisher to point at **this repo** +
workflow `release.yml`), and pushes the `verify`/`drill` container images to GHCR.

## Open-core boundary

Everything here is Apache-2.0 and standalone. The OSS packages **never** import
from the closed-source platform — `ci.yml` enforces this (`import-policy` job). If
the platform needs something a tool has, it consumes the **published** package.

## License

Apache-2.0 — see each package's `LICENSE` / `NOTICE`. "BlastContain" and the logo
are trademarks; the commercial platform is proprietary.
