# Drill contracts v1 — first migration milestone

These contracts are an additive Python API under `blastcontain_drill.contracts`.
The existing CLI, runner and signed-report format remain the production path.
No new runtime dependencies, plugin loading, suite execution or UI are introduced.

## What is available

| Record | Purpose |
|---|---|
| `ScenarioSpec` | Separates the legitimate task, attacker objective, entry prompt, injection surfaces, fixtures, security expectation, task checks and required capabilities/observations |
| `StrategyContext` | Carries an explicit objective and prior attempt feedback to an adaptive attacker |
| `PluginManifest` | Declares artifact identity, role(s), capabilities, configuration schema, license/notices and requested access |
| `AcceptanceRecord` | Records an actor's decision against a specific artifact digest and scope |
| `EvidenceEvent` / `EvidenceTrace` | Represents ordered execution, delivery, model output, attempted/blocked/performed actions and completion/error events |
| `ScenarioResult` | Separates execution, security, utility, evidence quality and containment; retains an upstream verdict as attributed data |

The five extension roles are `ScenarioSource`, `AttackStrategy`, `Target`,
`Environment` and `Evaluator`. `Lifecycle` declares prepare, reset, cancel,
evidence collection and close hooks; targets send injections and environments
execute scenarios. These are interface definitions. The isolated worker and
bounded session that will enforce them belong to subsequent milestones.

`ScenarioSpec` can represent direct user prompts, documents, MCP tool descriptions,
MCP responses and memory injection. Declaring a surface does not mean a particular
adapter can execute it. A required capability or observation must be supported
explicitly. Legacy cages reject unsupported declarations before target execution.
They also enforce the minimum requirements implied by the payloads, turns and goal,
even when a hand-authored scenario omits those declarations.

The source reference retains a revision and optional paper IDs. These provide
provenance, not a claim that a complete paper implementation has been validated.
A missing legacy revision is recorded as `unknown`, never converted into a pin.

## Serialization and validation

Top-level wire records require integer `schema_version: 1`; manifests also carry
`adapter_api: 1`. Nested value objects share their enclosing schema version.
`to_dict()` produces JSON-compatible data; `from_dict()` rejects missing required
fields, unknown fields, unsupported versions, wrong types and invalid enum values.
Defaults apply only to optional fields. There is no dynamic import or code evaluation.

Extension objects such as event data and configuration schemas accept JSON data
only: string keys, finite numbers, booleans, null, lists and objects. Cyclic data,
tuples and non-string keys are rejected rather than coerced. Records are frozen
at the field level; nested JSON objects remain mutable, so serialization revalidates
and copies them. They are not tamper-proof storage or canonical hash encodings.

Trace sequences begin with `started`, have contiguous sequence numbers and one
scenario ID, and cannot append events after `completed` or `cancelled`. A partial
trace is valid data, not a completed run. An `error` may precede completion.

A `held` result requires completed execution, observed evidence quality and
nonempty evidence references. Partial execution, partial observations and upstream
claims alone cannot establish `held`. A blocked attempted action can be represented
as `security="action_attempted"`, `containment="blocked"`, without asserting that
an effect occurred. Legitimate-task utility defaults to `not_measured`.

These checks enforce record consistency. They **do not verify** that evidence
references resolve, that an emitter deserves its authority label, or that an
observation proves an effect. The [phase 3B collector/reducer](evidence-reduction.md)
now establishes those checks through typed collector records and an independently
trusted host receipt; it does not promote arbitrary v1 traces based on their labels.
Likewise, a manifest declares a
license/configuration schema without validating an SPDX policy or configuration;
an acceptance record does not authenticate its actor or grant runtime access.

## Compatibility adapters

| Adapter | Current behavior |
|---|---|
| `LegacySourceAdapter` | Converts existing attacks into scenarios, retaining payloads, rubrics, goals, turns and source revision |
| `LegacyCageAdapter` | Checks declared capabilities/observations, converts the scenario back, then returns the original `CageObservation`; preserves setup/teardown |
| `LegacyStrategyAdapter` | Delegates to the existing attacker and can translate a `StrategyContext` into its goal/history inputs |
| `LegacyEvaluatorAdapter` | Delegates scoring while retaining axes, plane and the original scorer result dictionary |

The cage and evaluator bridges deliberately return legacy observations and scorer
results. They are **not** implementations of the new evidence-producing
`Environment` and `Evaluator` protocols. Routing them into a future suite requires
an explicit collector/reducer bridge; there is no implicit evidence conversion.
Phase 3B provides `collect_legacy_observation` for host-owned observations and
host-selected scorer verdicts, preserving the aggregate evidence's limitations.

Existing attacks do not acquire invented legitimate tasks or attacker objectives.
New fixtures or task-success checks cannot be silently discarded: conversion to
legacy attacks rejects them. Memory/user injection objects are also rejected by
that converter; legacy direct prompts remain in `entry_prompt`.

```python
from blastcontain_drill.contracts import ScenarioSpec
from blastcontain_drill.contracts.legacy import LegacySourceAdapter, attack_from_scenario
from blastcontain_drill.corpus import BuiltinReplaySource

scenario = LegacySourceAdapter(BuiltinReplaySource()).scenarios(limit=1)[0]
wire_data = scenario.to_dict()
restored = ScenarioSpec.from_dict(wire_data)
legacy_attack = attack_from_scenario(restored)
assert legacy_attack.id == scenario.id
```

The abliterated/local LLM attacker remains supported through `LLMAttacker` and
`LegacyStrategyAdapter`. Model/backend selection, prompts, feedback and generation
settings are preserved. Its current algorithm is PAIR-style sequential refinement;
TAP branching/pruning is not implemented. No live model was needed to validate
these adapter guarantees; generation quality still needs bounded live validation.

## Report compatibility and migration rules

1. The existing `DrillReport` envelope stays at schema **1.1**. Contract schema **1**
   is a separate version namespace and is not a replacement report schema.
2. No field, outcome, source ID, CLI flag or signing behavior changes in this milestone.
   Existing readers, diff and sweep continue to receive the same legacy report shape.
3. The new dimensions are not inferred from old `HELD`/`BYPASS` labels. In particular,
   legacy action `BYPASS` can record an attempted action that containment blocked.
   Existing heuristic/content limitations also remain; compatibility is not proof
   that every legacy result satisfies the new evidence requirements.
4. A future report migration must use an explicit versioned envelope and reader
   adapter. Lossy conversion must be identified, and incomplete/unsupported cases
   must never be downgraded to a passing legacy result.

See the [baseline record](redesign-baseline.md) for reproducible tests and the
[implementation plan](integration-redesign-plan.md) for remaining deliverables.
