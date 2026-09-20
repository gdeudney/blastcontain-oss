"""Trust-boundary contracts and backward compatibility; no external models required."""

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path

import pytest

from blastcontain_drill.contracts import (
    AcceptanceRecord,
    AttackFeedback,
    ContractError,
    EvidenceEvent,
    EvidenceTrace,
    Injection,
    PluginManifest,
    ScenarioResult,
    ScenarioSpec,
    StrategyContext,
)
from blastcontain_drill.contracts.legacy import (
    LegacyCageAdapter,
    LegacyEvaluatorAdapter,
    LegacySourceAdapter,
    LegacyStrategyAdapter,
    attack_from_scenario,
    scenario_from_attack,
)
from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.corpus import (
    BuiltinReplaySource,
    JailbreakBenchSource,
    MultiTurnSource,
    OperatorsSource,
    SystemCardSource,
    MCPPoisoningSource,
)
from blastcontain_drill.corpus.base import Corpus
from blastcontain_drill.generative import StubAttacker, goals_for, run_generative
from blastcontain_drill.generative.attacker import Attempt, LLMAttacker
from blastcontain_drill.runner import run_corpus
from blastcontain_drill.scoring import HeuristicContentScorer

SOURCES = [
    BuiltinReplaySource(),
    JailbreakBenchSource(),
    MultiTurnSource(),
    OperatorsSource(),
    SystemCardSource(),
    MCPPoisoningSource(),
]
CAPS = (
    "prompt.single",
    "prompt.multiturn",
    "inject.document",
    "inject.mcp_description",
    "inject.mcp_response",
)
OBS = ("model_output", "tool_actions", "payload_delivery")
BASELINE = json.loads(
    (Path(__file__).parents[1] / "fixtures/contracts-v1-baseline.json").read_text()
)


def scenario():
    return scenario_from_attack(BuiltinReplaySource().dataset()[0])


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: s.name)
def test_all_existing_attacks_preserved_against_baseline(source):
    attacks = source.dataset()
    expected = BASELINE["sources"][source.name]
    assert len(attacks) == expected["count"]
    assert source.revision == expected["revision"]
    assert (
        hashlib.sha256(
            json.dumps([asdict(a) for a in attacks], sort_keys=True).encode()
        ).hexdigest()
        == expected["sha256"]
    )
    converted = LegacySourceAdapter(source).scenarios()
    for original, spec in zip(attacks, converted, strict=True):
        restored_spec = ScenarioSpec.from_dict(json.loads(json.dumps(spec.to_dict())))
        assert restored_spec == spec
        assert asdict(attack_from_scenario(restored_spec)) == asdict(original)
        assert restored_spec.legitimate_task is None  # never invent a benign task
        assert restored_spec.source.revision == source.revision


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("entry_prompt", 3),
        ("unexpected", "data"),
        ("injections", [{"surface": "other", "payload": "x"}]),
    ],
)
def test_reject_unsupported_wire_inputs(field, value):
    data = scenario().to_dict()
    data[field] = value
    with pytest.raises(ContractError):
        ScenarioSpec.from_dict(data)


def test_missing_required_and_nested_fields():
    data = scenario().to_dict()
    for field in ("schema_version", "id", "security"):
        broken = dict(data)
        del broken[field]
        with pytest.raises(ContractError):
            ScenarioSpec.from_dict(broken)
    data["source"]["execute"] = "anything"
    with pytest.raises(ContractError):
        ScenarioSpec.from_dict(data)


def test_unsupported_legacy_semantics_are_not_silently_discarded():
    for changed in (
        replace(scenario(), injections=(Injection("memory", "x"),)),
        replace(scenario(), fixture_refs=("new-fixture",)),
        replace(scenario(), legitimate_task="Read invoice", task_checks=("invoice_correct",)),
    ):
        with pytest.raises(ContractError):
            attack_from_scenario(changed)


def test_missing_target_capability_does_not_call_target():
    class NeverRun:
        name = "unknown"

        def run_attack(self, attack):
            pytest.fail("Unsupported target must not be called")

    adapter = LegacyCageAdapter(NeverRun(), capabilities=(), observations=())
    with pytest.raises(ContractError, match="Unsupported"):
        adapter.execute(scenario())


def test_duplicate_surfaces_and_invalid_typed_construction():
    with pytest.raises(ContractError):
        replace(
            scenario(), injections=(Injection("mcp_response", "a"), Injection("mcp_response", "b"))
        )
    with pytest.raises(ContractError):
        replace(scenario(), schema_version=True)
    with pytest.raises(ContractError):
        replace(scenario(), security=replace(scenario().security, expected_refusal=1))


@pytest.mark.parametrize(
    "capabilities,observations",
    [
        (("prompt.single",), OBS),
        (CAPS, ("model_output", "tool_actions")),
    ],
)
def test_omitted_declarations_cannot_hide_intrinsic_mcp_requirements(capabilities, observations):
    class NeverRun:
        name = "limited-target"

        def run_attack(self, attack):
            pytest.fail("Undeclared MCP requirements must not reach the target")

    spec = replace(
        scenario_from_attack(MCPPoisoningSource().dataset()[0]),
        required_capabilities=(),
        required_observations=(),
    )
    adapter = LegacyCageAdapter(NeverRun(), capabilities=capabilities, observations=observations)
    with pytest.raises(ContractError, match="Unsupported"):
        adapter.execute(spec)


@pytest.mark.parametrize("vulnerable", [True, False])
def test_wrapped_builtin_results_match_baseline(vulnerable):
    cage = LegacyCageAdapter(
        InProcessCage(StubChatClient(vulnerable)), capabilities=CAPS, observations=OBS
    )
    findings = run_corpus(
        cage,
        Corpus("test", BuiltinReplaySource().dataset()),
        [LegacyEvaluatorAdapter(HeuristicContentScorer())],
    )
    actual = [
        {
            "id": f.attack_id,
            "outcome": f.outcome.value,
            "severity": f.severity.value if f.severity else None,
        }
        for f in findings
    ]
    assert actual == BASELINE["builtin_outcomes"][str(vulnerable).lower()]


@pytest.mark.parametrize(
    "source",
    [MultiTurnSource(), MCPPoisoningSource(), JailbreakBenchSource()],
    ids=lambda s: s.name,
)
def test_wrapped_actions_and_rubrics_have_identical_findings(source, monkeypatch):
    monkeypatch.setattr(
        "blastcontain_drill.cage.inprocess.new_canary", lambda: "BCN-CANARY-compatibility"
    )
    corpus = Corpus("test", source.dataset(limit=2))
    original = InProcessCage(StubChatClient(True))
    wrapped = LegacyCageAdapter(
        InProcessCage(StubChatClient(True)), capabilities=CAPS, observations=OBS
    )
    left = run_corpus(original, corpus, [HeuristicContentScorer()])
    right = run_corpus(wrapped, corpus, [LegacyEvaluatorAdapter(HeuristicContentScorer())])

    def stable(f):
        data = asdict(f)
        data.pop("detection_latency_ms")
        return data

    assert [stable(f) for f in left] == [stable(f) for f in right]
    assert all(f.outcome.value != "ERROR" for f in right)


def test_strategy_preserves_existing_feedback_and_supports_new_context():
    class Recording(StubAttacker):
        def craft(self, goal, history):
            self.received = (goal, history)
            return super().craft(goal, history)

    attacker = Recording()
    adapter = LegacyStrategyAdapter(attacker)
    goal = goals_for()[0]
    history = []
    assert adapter.craft(goal, history) == StubAttacker().craft(goal, history)
    assert attacker.received == (goal, history)
    spec = replace(scenario(), attack_objective="Attempt controlled exfiltration")
    context = StrategyContext(spec, (AttackFeedback("previous", "HELD", "refused", ()),))
    result = adapter.propose(StrategyContext.from_dict(context.to_dict()))
    assert result.surface == "user"
    assert attacker.received[0].objective == spec.attack_objective
    assert attacker.received[1][0].target_response == "refused"


def test_existing_generative_loop_accepts_strategy_wrapper(monkeypatch):
    monkeypatch.setattr(
        "blastcontain_drill.cage.inprocess.new_canary", lambda: "BCN-CANARY-compatibility"
    )
    scorer = [HeuristicContentScorer()]

    def run(attacker):
        return run_generative(
            goals_for()[:1], InProcessCage(StubChatClient(True)), scorer, attacker, max_iters=2
        )

    old, new = run(StubAttacker()), run(LegacyStrategyAdapter(StubAttacker()))
    assert old[0].iterations == new[0].iterations
    assert old[0].transcript == new[0].transcript
    assert old[0].finding.outcome == new[0].finding.outcome


def test_llm_attacker_keeps_model_prompts_feedback_and_generation_settings():
    class Backend:
        model = "local-abliterated-test-model"

        def is_available(self):
            return True

        def chat(self, messages, **kwargs):
            self.received = (messages, kwargs)
            return '"Controlled test prompt"'

    backend = Backend()
    attacker = LLMAttacker(backend)
    goal = goals_for()[0]
    history = [Attempt("Previous prompt", "HELD", "Refused by fixture", [])]
    expected = attacker.craft(goal, history)
    expected_call = backend.received
    adapter = LegacyStrategyAdapter(attacker)
    assert adapter.is_available()
    assert adapter.craft(goal, history) == expected
    assert backend.received == expected_call
    assert attacker.model_name == backend.model
    assert "Refused by fixture" in backend.received[0][1]["content"]


def test_cage_wrapper_preserves_context_manager_cleanup():
    class Cage:
        name = "lifecycle-fixture"
        calls = []

        def setup(self):
            self.calls.append("setup")

        def teardown(self):
            self.calls.append("teardown")

    cage = Cage()
    with pytest.raises(RuntimeError, match="test failure"):
        with LegacyCageAdapter(cage, capabilities=CAPS, observations=OBS):
            raise RuntimeError("test failure")
    assert cage.calls == ["setup", "teardown"]


def test_manifest_and_acceptance_round_trip_without_execution():
    manifest = PluginManifest(
        "example",
        "1.0",
        "sha256:" + "a" * 64,
        ("attack_strategy",),
        ("prompt.multiturn",),
        "MIT",
        config_schema={"description": '__import__("os")'},
    )
    assert PluginManifest.from_dict(manifest.to_dict()) == manifest
    acceptance = AcceptanceRecord(
        "example",
        "plugin",
        manifest.artifact_digest,
        "test-reviewer",
        "accepted",
        "2026-09-20T12:00:00Z",
        "Reviewed test fixture",
    )
    assert AcceptanceRecord.from_dict(acceptance.to_dict()) == acceptance
    for changes in ({"recorded_at": "2026-09-20T12:00:00"}, {"artifact_digest": "latest"}):
        with pytest.raises(ContractError):
            replace(acceptance, **changes)
    with pytest.raises(ContractError):
        replace(manifest, roles=())
    with pytest.raises(ContractError):
        replace(manifest, config_schema={"bad": float("nan")})


@pytest.mark.parametrize(
    "data",
    [{"nested": {1: "bad"}}, {"nested": (1, 2)}, {"nested": [float("inf")]}, {"nested": object()}],
)
def test_json_extension_fields_reject_coercion(data):
    with pytest.raises(ContractError):
        EvidenceEvent("case", 0, "started", "fixture", "runtime", data)


def test_json_cycles_and_mutation_cannot_bypass_serialization_validation():
    data = {"nested": []}
    original = EvidenceEvent("case", 0, "started", "fixture", "runtime", data)
    wire = original.to_dict()
    wire["data"]["nested"].append(1)
    assert original.data == {"nested": []}
    decoded = EvidenceEvent.from_dict(wire)
    wire["data"]["nested"].append(2)
    assert decoded.data == {"nested": [1]}
    data["nested"].append(data)
    with pytest.raises(ContractError, match="cyclic"):
        original.to_dict()


def event(sequence, kind, scenario_id="case"):
    return EvidenceEvent(scenario_id, sequence, kind, "test-runtime", "runtime")


def test_evidence_trace_roundtrip_and_partial_trace():
    for events in (
        (event(0, "started"),),
        (event(0, "started"), event(1, "effect_blocked"), event(2, "completed")),
    ):
        trace = EvidenceTrace("case", events)
        assert EvidenceTrace.from_dict(trace.to_dict()) == trace


@pytest.mark.parametrize(
    "events",
    [
        (),
        (event(0, "completed"),),
        (event(0, "started"), event(2, "completed")),
        (event(0, "started"), event(1, "started")),
        (event(0, "started"), event(1, "completed", "wrong")),
        (event(0, "started"), event(1, "completed"), event(2, "model_output")),
    ],
)
def test_malformed_event_sequences(events):
    with pytest.raises(ContractError):
        EvidenceTrace("case", events)


@pytest.mark.parametrize(
    "changes",
    [
        {"execution": "error", "security": "held"},
        {"execution": "unsupported", "security": "held"},
        {"evidence_quality": "claims_only", "security": "held"},
        {"evidence_quality": "partial", "security": "held"},
        {"evidence_refs": (), "security": "effect_observed"},
    ],
)
def test_no_clean_bill_of_health_from_incomplete_evidence(changes):
    values = dict(
        scenario_id="case",
        execution="completed",
        evidence_quality="observed",
        evidence_refs=("trace:1",),
    )
    values.update(changes)
    with pytest.raises(ContractError):
        ScenarioResult(**values)


def test_blocked_attempt_is_distinct_from_effect_and_utility():
    result = ScenarioResult(
        "case",
        "completed",
        "action_attempted",
        containment="blocked",
        evidence_quality="observed",
        evidence_refs=("trace:1",),
    )
    assert result.security != "effect_observed"
    assert result.utility == "not_measured"
    assert ScenarioResult.from_dict(result.to_dict()) == result
    assert (
        ScenarioResult("case", "completed", upstream_verdict={"success": True}).security
        == "unknown"
    )
