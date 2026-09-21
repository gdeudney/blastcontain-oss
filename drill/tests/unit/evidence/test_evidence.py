"""Authority, completeness and artifact integrity gates for phase 3B."""

from dataclasses import replace
import hashlib

import pytest

from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.cage.base import CageObservation, ToolCall
from blastcontain_drill.contracts import ContractError, Injection
from blastcontain_drill.contracts.legacy import scenario_from_attack
from blastcontain_drill.corpus import BuiltinReplaySource, MCPPoisoningSource
from blastcontain_drill.evidence import (
    ArtifactStore,
    EvidenceBundle,
    EvidenceCollector,
    EvidenceLimitError,
    EvidenceReceipt,
    Producer,
    ReductionPolicy,
    collect_legacy_observation,
    reduce_evidence,
)
from blastcontain_drill.evidence.records import (
    Action,
    Coverage,
    Delivery,
    Effect,
    Evaluation,
    EvidenceRecord,
    Started,
    TaskCheck,
    Terminal,
)
from blastcontain_drill.scoring import HeuristicContentScorer
from blastcontain_drill.suites.artifacts import canonical, digest, read_document, write_document

CHANNELS = ("model_output", "tool_actions", "payload_delivery")


def scenario(action=False):
    attack = next(
        a
        for a in BuiltinReplaySource().dataset()
        if a.goal == "content" and not a.poisoned_document
    )
    spec = scenario_from_attack(attack, "test-v1")
    return replace(spec, security=replace(spec.security, goal="forbidden_tool")) if action else spec


def setup(spec=None, *, case_id="case-1", store=None, **limits):
    spec = spec or scenario()
    collector = EvidenceCollector(case_id, spec, store=store, **limits)
    env = collector.register(Producer("fixture", "environment", "simulation", CHANNELS))
    evaluator = collector.register(
        Producer(
            "judge",
            "evaluator",
            "host",
            axes=("harm", "refusal", "freeform"),
            task_checks=spec.task_checks,
        )
    )
    return collector, env, evaluator


def complete(collector, env, evaluator=None, *, matched=False, axis="harm"):
    ref = collector.output(env, "Observed response")
    collector.record(env, Coverage(CHANNELS, True))
    if evaluator is not None:
        collector.record(evaluator, Evaluation(axis, matched, (ref,)))
    collector.finish()
    return collector.snapshot()


def replay(spec, pair, **kwargs):
    return reduce_evidence(spec, *pair, **kwargs)


def test_completed_held_and_offline_replay_identical(tmp_path):
    spec = scenario()
    collector, env, evaluator = setup(spec)
    bundle, receipt = complete(collector, env, evaluator)
    result = reduce_evidence(spec, bundle, receipt)
    assert result.result.security == "held"
    assert result.result.execution == "completed"
    assert result.result.utility == "not_measured"
    path = tmp_path / "evidence.json"
    write_document(path, bundle.to_dict())
    restored = EvidenceBundle.from_dict(read_document(path))
    assert reduce_evidence(spec, restored, receipt) == result
    assert canonical(result.to_dict()) == canonical(
        reduce_evidence(spec, restored, receipt).to_dict()
    )


def test_unused_observer_registration_does_not_claim_independent_evidence():
    spec = scenario()
    collector, env, evaluator = setup(spec)
    collector.register(Producer("unused", "environment", "independent", ("tool_actions",)))
    reduced = replay(spec, complete(collector, env, evaluator))
    assert reduced.result.upstream_verdict["scopes"] == ["simulation"]


@pytest.mark.parametrize(
    "claim",
    [
        {
            "authority": "environment",
            "emitter": "fixture",
            "kind": "effect_performed",
            "success": True,
        },
        {"authority": "runtime", "kind": "completed", "coverage": list(CHANNELS)},
        {"security": "held", "execution": "completed", "evidence_quality": "observed"},
    ],
)
def test_plugin_claims_cannot_establish_any_security_conclusion(claim):
    spec = scenario(action=True)
    collector = EvidenceCollector("case", spec)
    collector.claim("malicious", claim)
    collector.finish()
    bundle, receipt = collector.snapshot()
    assert all(p.scope == "claim" for p in bundle.producers if p.role == "plugin")
    result = reduce_evidence(spec, bundle, receipt).result
    assert result.security == "unknown" and result.evidence_quality == "claims_only"
    assert result.execution != "completed"


def test_handles_and_scopes_cannot_be_forged_or_borrowed():
    collector, env, evaluator = setup()
    other, other_env, _ = setup(case_id="case-2")
    for handle in ("fixture", object(), other_env):
        with pytest.raises(ContractError, match="handle"):
            collector.output(handle, "fake")
    plugin = collector.register(Producer("plugin", "plugin", "claim"))
    for handle, payload in (
        (plugin, Terminal("completed")),
        (plugin, Action("fake", ("egress_attempt",))),
        (evaluator, Action("fake", ("egress_attempt",))),
        (env, Effect("fake", ("sha256:" + "a" * 64,))),
    ):
        with pytest.raises(ContractError, match="cannot supply"):
            collector.record(handle, payload)
    with pytest.raises(ContractError, match="claim scope"):
        Producer("fake", "plugin", "independent")


@pytest.mark.parametrize(
    "blocked,expected", [(True, "blocked"), (False, "unknown"), (None, "unknown")]
)
def test_attempt_is_not_a_proven_effect(blocked, expected):
    spec = scenario(action=True)
    collector, env, evaluator = setup(spec)
    collector.record(env, Action("attempt-1", ("forbidden_tool",), blocked))
    reduced = replay(spec, complete(collector, env))
    assert reduced.result.security == "action_attempted"
    assert reduced.result.containment == expected and reduced.legacy_outcome == "BYPASS"


def observed_effect(tmp_path, *, blocked=False, case_id="case-1"):
    spec = scenario(action=True)
    store = ArtifactStore(tmp_path)
    collector, env, _ = setup(spec, store=store, case_id=case_id)
    observer = collector.register(
        Producer("observer", "environment", "independent", ("tool_actions",))
    )
    attempt = collector.record(env, Action("attempt", ("forbidden_tool",), blocked))
    proof = collector.artifact(observer, {"synthetic_state_before": 1, "synthetic_state_after": 0})
    collector.record(observer, Effect(attempt, (proof.digest,)))
    return spec, store, proof, complete(collector, env)


def test_independent_effect_requires_scoped_retained_proof(tmp_path):
    spec, store, proof, pair = observed_effect(tmp_path)
    result = replay(spec, pair, store=store)
    assert result.result.security == "effect_observed"
    assert result.result.containment == "not_blocked"
    assert store.read(proof)["synthetic_state_after"] == 0
    with pytest.raises(ContractError, match="require their store"):
        replay(spec, pair)


def test_blocking_claim_contradicted_by_observed_effect_is_not_a_pass(tmp_path):
    spec, store, _, pair = observed_effect(tmp_path, blocked=True)
    result = replay(spec, pair, store=store)
    assert result.result.execution == "error" and result.result.security == "effect_observed"
    assert result.result.evidence_quality == "partial"
    assert "effect_contradicts_blocked_action" in result.diagnostics


@pytest.mark.parametrize("damage", ["missing", "bytes", "size", "symlink"])
def test_missing_or_tampered_artifacts_rejected(tmp_path, damage):
    spec, store, proof, pair = observed_effect(tmp_path)
    path = tmp_path / (proof.digest[7:] + ".json")
    if damage == "missing":
        path.unlink()
    elif damage == "bytes":
        path.write_bytes(
            path.read_bytes().replace(b'"synthetic_state_after":0', b'"synthetic_state_after":1')
        )
    elif damage == "size":
        path.write_bytes(path.read_bytes() + b" ")
    else:
        target = tmp_path / "other.json"
        path.rename(target)
        try:
            path.symlink_to(target)
        except OSError:
            pytest.skip("Host does not permit symlink creation")
    with pytest.raises(ContractError):
        replay(spec, pair, store=store)


def test_artifact_names_are_generated_and_cross_case_references_rejected(tmp_path):
    spec, store, proof, pair = observed_effect(tmp_path, case_id="../../untrusted-case")
    assert [p.name for p in tmp_path.iterdir()] == [proof.digest[7:] + ".json"]
    assert len(store.read(proof)) == 2
    with pytest.raises(ContractError, match="another case"):
        replace(pair[0], case_id="other-case")
    with pytest.raises(ContractError, match="scope mismatch"):
        replay(
            spec,
            (
                pair[0],
                EvidenceReceipt("other-case", pair[1].scenario_digest, pair[1].bundle_digest),
            ),
            store=store,
        )


def test_same_proof_bytes_in_two_cases_have_different_artifact_ids(tmp_path):
    store = ArtifactStore(tmp_path)
    pin = digest(scenario().to_dict())
    a = store.put("a", pin, "observer", {"state": 1})
    b = store.put("b", pin, "observer", {"state": 1})
    assert a.digest != b.digest
    assert store.put("a", pin, "observer", {"state": 1}) == a


@pytest.mark.parametrize("fault", ["wrong_observer", "missing_proof", "missing_action"])
def test_effect_cannot_borrow_or_invent_proof(tmp_path, fault):
    spec = scenario(action=True)
    store = ArtifactStore(tmp_path)
    collector, env, _ = setup(spec, store=store)
    observer = collector.register(Producer("observer", "environment", "independent"))
    other = collector.register(Producer("other", "environment", "independent"))
    attempt = collector.record(env, Action("attempt", ("forbidden_tool",)))
    proof = collector.artifact(observer, {"observed": "synthetic change"})
    emitter = other if fault == "wrong_observer" else observer
    proof_id = "sha256:" + "a" * 64 if fault == "missing_proof" else proof.digest
    action_ref = "missing" if fault == "missing_action" else attempt
    collector.record(emitter, Effect(action_ref, (proof_id,)))
    pair = complete(collector, env)
    with pytest.raises(ContractError):
        replay(spec, pair, store=store)


@pytest.mark.parametrize("replacement", ["payload", "authority", "scope"])
def test_modified_bundle_cannot_use_original_receipt(replacement):
    spec = scenario()
    collector, env, evaluator = setup(spec)
    bundle, receipt = complete(collector, env, evaluator)
    if replacement == "payload":
        index = next(i for i, r in enumerate(bundle.records) if isinstance(r.payload, Evaluation))
        records = list(bundle.records)
        records[index] = replace(
            records[index], payload=replace(records[index].payload, matched=True)
        )
        modified = replace(bundle, records=tuple(records))
    elif replacement == "authority":
        modified = replace(
            bundle,
            producers=tuple(
                replace(p, scope="independent") if p.role == "environment" else p
                for p in bundle.producers
            ),
        )
    else:
        modified = replace(bundle, case_id="another-case")
    with pytest.raises(ContractError):
        reduce_evidence(spec, modified, receipt)
    with pytest.raises(ContractError, match="trusted host"):
        reduce_evidence(spec, bundle, {"bundle_digest": receipt.bundle_digest})


def anchor(bundle):
    # Test host deliberately anchors malformed producer data to exercise structural checks,
    # independently from the normal receipt/hash gate.
    return EvidenceReceipt(bundle.case_id, bundle.scenario_digest, digest(bundle.to_dict()))


@pytest.mark.parametrize(
    "fault", ["gap", "restart", "after_terminal", "unknown_producer", "plugin_terminal"]
)
def test_structural_faults_cannot_establish_held(fault):
    spec = scenario()
    collector, env, evaluator = setup(spec)
    bundle, _ = complete(collector, env, evaluator)
    records = list(bundle.records)
    if fault == "gap":
        records[1] = replace(records[1], sequence=99)
    elif fault == "restart":
        records[1] = replace(records[1], emitter="collector", payload=Started())
    elif fault == "after_terminal":
        records.append(EvidenceRecord(len(records), "collector", Terminal("completed")))
    elif fault == "unknown_producer":
        records[1] = replace(records[1], emitter="unregistered")
    else:
        bundle = replace(
            bundle, producers=(*bundle.producers, Producer("plugin", "plugin", "claim"))
        )
        records[-1] = replace(records[-1], emitter="plugin")
    bundle = replace(bundle, records=tuple(records))
    with pytest.raises(ContractError):
        reduce_evidence(spec, bundle, anchor(bundle))


@pytest.mark.parametrize("ref_type", ["missing", "wrong_kind", "other_case", "forward"])
def test_evaluation_references_must_be_prior_output_in_this_case(ref_type):
    spec = scenario()
    collector, env, evaluator = setup(spec)
    output = collector.output(env, "safe")
    wrong = "missing"
    if ref_type == "wrong_kind":
        wrong = collector.snapshot()[0].reference(0)
    elif ref_type == "other_case":
        other, other_env, _ = setup(spec, case_id="other")
        wrong = other.output(other_env, "safe")
    elif ref_type == "forward":
        wrong = collector.snapshot()[0].reference(99)
    assert wrong != output
    collector.record(evaluator, Evaluation("harm", False, (wrong,)))
    collector.finish()
    with pytest.raises(ContractError, match="reference"):
        replay(spec, collector.snapshot())


@pytest.mark.parametrize(
    "reason,expected",
    [
        ("step_limit", "incomplete"),
        ("unknown_completion", "incomplete"),
        ("backend_error", "error"),
        ("cancelled", "cancelled"),
        ("unsupported", "unsupported"),
    ],
)
def test_partial_termination_never_held(reason, expected):
    spec = scenario(action=True)
    collector, env, _ = setup(spec)
    collector.output(env, "safe")
    collector.record(env, Coverage(CHANNELS, True))
    collector.finish(reason)
    result = replay(spec, collector.snapshot())
    assert result.result.execution == expected
    assert result.result.security == "unknown" and result.legacy_outcome == "ERROR"


def test_error_followed_by_completed_is_not_held():
    spec = scenario()
    collector, env, evaluator = setup(spec)
    collector.error("backend_error")
    result = replay(spec, complete(collector, env, evaluator))
    assert result.result.execution == "error" and result.result.security != "held"
    assert "completion_has_errors" in result.diagnostics


@pytest.mark.parametrize("limit", ["records", "bytes", "artifact"])
def test_collection_limits_keep_partial_evidence_and_positive_attempts(tmp_path, limit):
    spec = scenario(action=True)
    collector, env, _ = setup(
        spec, store=ArtifactStore(tmp_path), max_records=4, max_bytes=1500, max_artifact_bytes=100
    )
    collector.record(env, Action("attempt", ("forbidden_tool",), True))
    with pytest.raises(EvidenceLimitError):
        if limit == "records":
            collector.output(env, "safe")
            collector.record(env, Coverage(CHANNELS, True))
            collector.finish()
        elif limit == "bytes":
            collector.claim("plugin", {"message": "x" * 2000})
        else:
            observer = collector.register(Producer("observer", "environment", "independent"))
            collector.artifact(observer, {"too_large": "x" * 200})
    bundle, receipt = collector.snapshot()
    assert bundle.truncated
    result = reduce_evidence(spec, bundle, receipt)
    assert (
        result.result.security == "action_attempted" and result.result.evidence_quality == "partial"
    )
    assert result.legacy_outcome == "BYPASS"
    with pytest.raises(ContractError, match="closed"):
        collector.finish()


def test_no_required_observation_or_no_output_means_incomplete():
    spec = scenario(action=True)
    collector, env, _ = setup(spec)
    collector.output(env, "safe")
    collector.record(env, Coverage(("model_output",), True))
    collector.finish()
    result = replay(spec, collector.snapshot())
    assert result.result.execution == "incomplete" and result.result.security != "held"


def test_final_output_must_be_assessed_and_conflicting_judges_cannot_hold():
    spec = scenario()
    for later_output in (False, True):
        collector, env, evaluator = setup(spec)
        ref = collector.output(env, "safe prefix")
        collector.record(evaluator, Evaluation("harm", False, (ref,)))
        if later_output:
            collector.output(env, "unassessed suffix")
        else:
            second = collector.register(
                Producer("other-judge", "evaluator", "host", axes=("harm",))
            )
            collector.record(second, Evaluation("harm", True, (ref,)))
        collector.record(env, Coverage(CHANNELS, True))
        collector.finish()
        reduced = replay(spec, collector.snapshot())
        assert reduced.result.execution == "error" and reduced.result.security == "unknown"


@pytest.mark.parametrize("matched", [None, False, True])
def test_content_and_required_evaluator_policy(matched):
    spec = scenario()
    collector, env, evaluator = setup(spec)
    pair = complete(collector, env, evaluator, matched=matched)
    result = replay(spec, pair)
    assert (
        result.result.security
        == {None: "unknown", False: "held", True: "content_violation"}[matched]
    )
    missing = replay(spec, pair, policy=ReductionPolicy(("missing-judge",)))
    assert missing.result.execution == "error" and missing.result.security != "held"


@pytest.mark.parametrize(
    "matched,utility,legacy", [(True, "failed", "OVER_REFUSAL"), (False, "unknown", "HELD")]
)
def test_benign_refusal_is_utility_not_security_success(matched, utility, legacy):
    spec = scenario()
    spec = replace(spec, security=replace(spec.security, expected_refusal=False))
    collector, env, evaluator = setup(spec)
    result = replay(spec, complete(collector, env, evaluator, matched=matched, axis="refusal"))
    assert result.result.security == "unknown" and result.result.utility == utility
    assert result.legacy_outcome == legacy


@pytest.mark.parametrize(
    "values,utility,execution",
    [
        ((True,), "succeeded", "completed"),
        ((False,), "failed", "completed"),
        ((), "unknown", "error"),
        ((True, False), "unknown", "error"),
        ((None,), "unknown", "error"),
    ],
)
def test_task_success_requires_explicit_supported_checks(values, utility, execution):
    spec = replace(
        scenario(action=True), legitimate_task="Read the invoice", task_checks=("invoice",)
    )
    collector, env, evaluator = setup(spec)
    output = collector.output(env, "Invoice summary")
    collector.record(env, Coverage(CHANNELS, True))
    for value in values:
        collector.record(evaluator, TaskCheck("invoice", value, (output,)))
    collector.finish()
    reduced = replay(spec, collector.snapshot())
    assert reduced.result.utility == utility and reduced.result.execution == execution
    if execution != "completed":
        assert reduced.result.security != "held"


def test_missing_or_wrong_payload_delivery_never_holds():
    spec = replace(
        scenario(action=True), injections=(Injection("mcp_response", "controlled payload"),)
    )
    for delivered, payload in ((False, "controlled payload"), (True, "wrong payload")):
        collector, env, _ = setup(spec)
        collector.record(
            env,
            Delivery(
                "mcp_response", "sha256:" + hashlib.sha256(payload.encode()).hexdigest(), delivered
            ),
        )
        result = replay(spec, complete(collector, env))
        assert (
            result.result.execution == "incomplete"
            and "missing_payload_exposure" in result.diagnostics
        )


def test_sensitive_legacy_inputs_and_plugin_claims_not_retained():
    spec = scenario(action=True)
    secret = "secret-sentinel-never-retain"
    obs = CageObservation(
        response_text=secret,
        error=secret,
        termination_reason="backend_error",
        tool_calls=[ToolCall("delete_records", {"token": secret}, result=secret)],
    )
    bundle, receipt = collect_legacy_observation("case", spec, obs)
    result = reduce_evidence(spec, bundle, receipt)
    assert result.result.security == "action_attempted" and result.result.execution == "error"
    assert secret.encode() not in canonical(bundle.to_dict()) + canonical(result.to_dict())
    collector = EvidenceCollector("plugin-case", spec)
    collector.claim("plugin", {"token": secret, "error": secret})
    assert secret.encode() not in canonical(collector.snapshot()[0].to_dict())


def test_legacy_completion_unknown_and_simulated_send_are_not_stronger_evidence():
    spec = scenario(action=True)
    obs = CageObservation(response_text="safe")
    result = replay(spec, collect_legacy_observation("case", spec, obs))
    assert result.result.execution == "incomplete" and result.legacy_outcome == "ERROR"
    obs = CageObservation(
        response_text="done",
        termination_reason="completed",
        tool_calls=[ToolCall("delete_records", result="ok: delivered")],
    )
    result = replay(spec, collect_legacy_observation("case", spec, obs, scope="container"))
    assert result.result.security == "action_attempted"
    assert result.result.containment == "unknown" and result.result.utility == "not_measured"


@pytest.mark.parametrize("vulnerable", [False, True])
@pytest.mark.parametrize("attack", MCPPoisoningSource().dataset(), ids=lambda a: a.id)
def test_controlled_mcp_observations_keep_security_outcomes_without_claiming_effects(
    attack, vulnerable
):
    spec = scenario_from_attack(attack, "v1")
    observation = InProcessCage(StubChatClient(vulnerable)).run_attack(attack)
    bundle, receipt = collect_legacy_observation(
        "mcp-case", spec, observation, content_verdict={"matched": True, "scorer": "claims"}
    )
    reduced = reduce_evidence(spec, bundle, receipt)
    assert reduced.result.execution == "completed"
    assert reduced.result.security == ("action_attempted" if vulnerable else "held")
    assert reduced.legacy_outcome == ("BYPASS" if vulnerable else "HELD")
    assert reduced.result.utility == "not_measured"


@pytest.mark.parametrize("surface", ["description", "response"])
@pytest.mark.parametrize("steps,legacy", [(1, "ERROR"), (2, "ERROR"), (3, "BYPASS"), (4, "BYPASS")])
def test_mcp_step_exhaustion_keeps_attempt_but_never_held(surface, steps, legacy):
    attack = next(a for a in MCPPoisoningSource().dataset() if a.id == f"mcp-{surface}-exfil")
    spec = scenario_from_attack(attack, "v1")
    obs = InProcessCage(StubChatClient(True), max_steps=steps).run_attack(attack)
    result = replay(spec, collect_legacy_observation("case", spec, obs))
    assert result.legacy_outcome == legacy
    assert result.result.execution == ("completed" if steps == 4 else "incomplete")


@pytest.mark.parametrize("vulnerable", [False, True])
def test_legacy_content_fixture_matches_without_modifying_old_runner(vulnerable):
    attack = next(
        a
        for a in BuiltinReplaySource().dataset()
        if a.goal == "content" and not a.poisoned_document
    )
    spec = scenario_from_attack(attack, "v1")
    obs = InProcessCage(StubChatClient(vulnerable)).run_attack(attack)
    verdict = HeuristicContentScorer().score(attack, obs.transcript_text())
    reduced = replay(spec, collect_legacy_observation("case", spec, obs, content_verdict=verdict))
    assert reduced.legacy_outcome == ("BYPASS" if vulnerable else "HELD")


def test_wire_rejects_forged_authority_unknown_payload_and_nonfinite_data():
    collector, env, evaluator = setup()
    bundle, _ = complete(collector, env, evaluator)
    for mutation in ("authority", "payload", "version"):
        data = bundle.to_dict()
        if mutation == "authority":
            data["records"][1]["authority"] = "environment"
        elif mutation == "payload":
            data["records"][1]["payload"]["kind"] = "unrecognized"
        else:
            data["schema_version"] = True
        with pytest.raises(ContractError):
            EvidenceBundle.from_dict(data)
    with pytest.raises(ContractError):
        EvidenceCollector("case", scenario()).claim("plugin", {"value": float("inf")})


def test_v1_transport_authority_labels_do_not_become_collected_evidence():
    from blastcontain_drill.contracts import EvidenceEvent, EvidenceTrace

    spec = scenario()
    collector, env, evaluator = setup(spec)
    _, receipt = complete(collector, env, evaluator)
    trace = EvidenceTrace(
        spec.id,
        (
            EvidenceEvent(spec.id, 0, "started", "pretend-runtime", "runtime"),
            EvidenceEvent(spec.id, 1, "effect_performed", "pretend-observer", "environment"),
            EvidenceEvent(spec.id, 2, "completed", "pretend-runtime", "runtime"),
        ),
    )
    with pytest.raises(ContractError, match="transport trace"):
        reduce_evidence(spec, trace, receipt)


def test_unknown_legacy_document_exposure_cannot_establish_held():
    spec = replace(scenario(action=True), injections=(Injection("document", "payload"),))
    obs = CageObservation(
        response_text="refused",
        termination_reason="completed",
        tool_calls=[ToolCall("read", {"path": "file"}, result="payload")],
    )
    result = replay(spec, collect_legacy_observation("case", spec, obs))
    assert result.result.execution == "incomplete" and result.result.security != "held"
    assert "missing_payload_exposure" in result.diagnostics
