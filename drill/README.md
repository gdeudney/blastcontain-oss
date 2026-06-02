# blastcontain-drill

Adversarial red-team scanner for AI agents. Drill runs a **versioned attack
corpus** against an agent **inside a cage** and scores the result on two planes —
what the model *said* (content) and what the agent *did* (action). It produces a
signed, MITRE-ATLAS-tagged **DrillReport** in the same Audit-Packet format as
[`blastcontain-verify`](https://github.com/blastcontain/verify).

> The cage trilogy: **Verify** proves the cage is built right · **Drill** attacks
> the agent inside it · **Guard** adds the runtime locks.

```
pip install blastcontain-drill
blastcontain-drill --agent-id my-agent --cage inprocess \
  --target-base-url http://localhost:1234/v1 --target-model qwen/qwen3.6-27b \
  --report drill.md --output drill.json
```

## What makes Drill different

Existing tools score the **model's output** (jailbroken text, PII in a response).
Drill, running the agent in a cage, also scores the **action**: did the canary
*actually* leave? did a forbidden tool *fire*? did the agent *attempt* an egress
the cage blocked? *Content scoring says "the model said something bad." Drill says
"the agent did something bad."*

| Plane | Asks | How |
|---|---|---|
| **Content** | did the model *say* something bad? | LLM-as-judge + a guardrail classifier (Qwen3Guard or IBM Granite Guardian) |
| **Action** ★ | did the agent *do* something bad? | cage ground truth — canary exfil · forbidden-tool fire · egress attempt · tool-call log |

A scenario returns **HELD** or **BYPASS** with a detection latency and the control
that blocked it. An action-plane bypass is **CRITICAL** and blocks prod promotion.

## The attack corpus — three layers, versioned

| Layer | Source | Catches |
|---|---|---|
| **Replay** | built-in seed set · HF datasets · AI-Infra-Guard curated sets | *known* attacks — a regression suite |
| **Operators** | arXiv techniques as transforms (PAIR, TAP, many-shot, encoding…) | known *methods* on fresh seeds |
| **Generative** | an abliterated attacker model | *novel* jailbreaks |

Every run is pinned to a corpus version (e.g. `v2026.06`) and recorded in the
DrillReport, so reports are reproducible and regression-comparable. All three
layers ship: **Replay** (a built-in seed corpus, no downloads), **Operators**
(model-free technique transforms — `--operators`), and **Generative**
(`--generative` — an abliterated/no-refusal attacker model crafts and refines
novel jailbreaks against the caged target in a PAIR/TAP loop; needs
`--attacker-model`). Discovered jailbreaks are written to a separate, sensitive
corpus (`--generative-corpus`), never into the signed report.

## The cage

The cage is an interface with two backends:

- **`inprocess`** — host-side cage that drives a *real* model (any OpenAI-compatible
  endpoint, e.g. LM Studio) through an agent loop with a tool allowlist, an egress
  allowlist, a planted canary, and a tool-call log. Used for live runs and fast tests.
- **`podman`** — a real container with deny-all egress (`--network none`), proving
  containment ground truth. Runs a non-LLM stub agent in CI.

Both produce the same observations, so the **action probes** (canary / egress /
forbidden-tool) score identically against either.

## Taxonomy

Every finding is tagged with **MITRE ATLAS** (primary; verified against
atlas.mitre.org), plus the MIT AI Risk domain and OWASP Agentic `T#`. The agent
techniques `AML.T0086` (Exfiltration via AI Agent Tool Invocation) and `AML.T0110`
(AI Agent Tool Poisoning) cover the action plane. The maps live in
[`blastcontain-core`](https://github.com/blastcontain/core).

## CLI flags (most common)

```
--agent-id              Target agent identifier (required)
--env                   dev | uat | staging | prod
--cage                  inprocess | podman   (default: inprocess)
--target-base-url       OpenAI-compatible endpoint for the in-cage agent
--target-model          model id to drive as the agent (e.g. qwen/qwen3.6-27b)
--judge-base-url        endpoint for the LLM judge (defaults to --target-base-url)
--judge-model           model id for the content-plane judge
--guard-model           guardrail classifier id (e.g. qwen3guard-gen-8b), if served
--agent-url             attack an already-running agent over HTTP (black-box mode)
--corpus                corpus version to pin (default: built-in latest)
--scenarios             comma-separated categories (default: all)
--charter               local charter.yaml — its permitted_tools define "forbidden"
--output PATH           write the signed DrillReport JSON
--report PATH           write the Markdown report
```

## Verifying a DrillReport

```python
import json
from blastcontain_core.signing import verify_packet

packet = json.load(open("drill.json"))
assert verify_packet(packet)
```

Ed25519 packets carry their public key inline. Set `BLASTCONTAIN_SIGNING_KEY_PATH`
to an Ed25519 PEM for production attestation; otherwise an advisory HMAC is used.

## Container

```
# from the blastcontain-oss/ root (dev build — installs core from local source)
podman build -t blastcontain-drill:0.1.0 -f drill/Containerfile .

# black-box: attack a running agent
podman run --rm -v "$PWD/reports:/reports:rw" blastcontain-drill:0.1.0 \
  --agent-id my-agent --agent-url http://agent:8080 \
  --report /reports/drill.md --output /reports/drill.json
```

Drill drives a model, so — unlike Verify — it is **not** run with `--network none`.
To point the inprocess cage at a model server on the host, see the Containerfile header.

## Safety

Drill emits live adversarial payloads. Run the corpus and any attacker model in
the cage, treat generated jailbreaks as secrets, and check dataset licenses before
redistribution. See [SECURITY.md](SECURITY.md).

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions require a DCO sign-off (`git commit -s`).
