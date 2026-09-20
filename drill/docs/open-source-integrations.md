# Open-source integration candidates

Research checked September 20, 2026. These are integration recommendations, not
installed dependencies, active adapters or reproduced benchmark results.

| Priority | Project | Useful addition | Proposed boundary |
|---|---|---|---|
| 1 | [Microsoft PyRIT](https://github.com/microsoft/PyRIT) (MIT) | Adaptive multi-turn orchestration, including Crescendo and TAP; more capable than Drill's existing independent converter implementations | Optional attacker adapter; route target calls through Drill's cage, preserve conversation state and enforce a query budget |
| 2 | [AgentDojo](https://github.com/ethz-spylab/agentdojo) (MIT) | Realistic tool-task environments, indirect prompt injection, and task-utility evaluation | Optional environment adapter with resettable state and explicit mapping of security and task-success results |
| 3 | [NVIDIA garak](https://github.com/NVIDIA/garak) (Apache-2.0 framework) | Broad model vulnerability probes and plugin ecosystem | Optional probe importer/adapter; keep text-level detection distinct from demonstrated tool effects |
| 4 | [DeepTeam](https://github.com/confident-ai/deepteam) (Apache-2.0) | Additional attack generation and single/multi-turn red-team workflows | Evaluate incremental coverage first; existing Drill operators already draw on some of the same technique families |

PyRIT's [documentation](https://github.com/microsoft/PyRIT/blob/main/doc/index.md)
explicitly lists multi-turn Crescendo and TAP. That makes it the clearest route to
closing the adaptive attack gap found in the Drill audit. AgentDojo is an environment
benchmark, not simply a list of prompts; preserving its state and utility checks
requires a more substantial adapter.

Repository licenses above describe the projects, not every bundled dataset/model.
Before selecting a release, pin its version and review the exact imported artifacts
and notices. Do not infer payload redistribution rights from the framework license.

The integration should preserve Drill's useful guarantees: explicit opt-in,
source/version provenance, bounded execution, observable action evidence, and a
separate utility outcome. Upstream attack-success scores must not automatically
become Drill BYPASS results. A failed or unexposed attack remains an error or
incomplete case rather than a successful defense.

The existing AI-Infra-Guard adapter and JBB data integration remain available.
No new third-party package is added by this document or the arXiv registry.
