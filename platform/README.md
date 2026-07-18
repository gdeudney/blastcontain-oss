# BlastContain Platform

**Charter + Ledger + Fleet API + console GUI**

> Governance that contains the blast radius.

This directory is the BlastContain **platform**: the server that turns human
intent into enforceable policy (Charter), keeps the continuous, priced audit
trail (Ledger + MPL), and serves the fleet API consumed by the console GUI.
It is Apache-2.0, like every other package in this repo — see [LICENSE](LICENSE)
and [NOTICE](NOTICE).

| Component | Where | What it does | Roadmap |
|---|---|---|---|
| **Ledger** | [`server/`](server/) | Continuous audit trail. Financial exposure per finding (MPL). Fleet dashboard. | ✅ P2 |
| **Charter** | [`server/`](server/) | Agent policy constitution. Turns human intent into enforceable policy. | 🟡 P3 |
| **Console** | [`gui/`](gui/) | Next.js web console over the fleet API. | 🟡 |

The scanner/red-team/enforcer components (Verify, Drill, Guard, Scout) are the
sibling top-level packages in this repo; the spec set lives in
[`../docs/`](../docs/) — start at
[BlastContain-platform-spec.md](../docs/BlastContain-platform-spec.md).

---

## Layout

```
platform/
├── server/       # Charter + Ledger + Fleet API (FastAPI) — blastcontain-server
├── gui/          # console (Next.js) + hardened Containerfile
└── tests/        # platform tests: server unit, scenarios, container integration
```

---

## Develop

```bash
pip install -e ../core -e ../guard -e "./server[dev]"

pytest tests/server
```

The server depends on `blastcontain-core` (shared types, signing, Charter
schema) and uses `blastcontain-guard` in its closed-loop integration tests —
both resolved from this repo's source via editable installs (or `uv sync`).

Run the server:

```bash
python server/server.py    # FastAPI + uvicorn
```

GUI dev loop: see [`gui/dev.ps1`](gui/dev.ps1) and [`gui/web/README.md`](gui/web/README.md).

---

## Sovereign stack integration

BlastContain sits above Cisco AI Defense and Microsoft AGT. Both run in-process
inside each agent. BlastContain consumes their signals, enforces policy
consequences, and produces the unified Audit Packet.

| Layer | Component | Role |
|---|---|---|
| Foundation | Cisco AI Defense | Network defence, MCP inspection, model scanning, data classification |
| Framework | Microsoft AGT | Agent identity (Ed25519 DIDs), policy engine, MCP Security Gateway |
| Platform | **BlastContain** | Charter authoring, Verify scanning, Ledger audit, Drill testing, Guard enforcement, Discovery |

---

*BlastContain — governance that contains the blast radius.*
