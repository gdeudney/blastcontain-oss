"""The native/AGT two-front composition and its fail-closed contract (§8)."""
from blastcontain_guard.backends import AgtBackend, combine_with_agt
from blastcontain_guard.evaluator import evaluate
from blastcontain_guard.models import Action, Decision, EvalInput
from blastcontain_guard.policy import parse_ruleset

ALLOW_ALL = parse_ruleset({"default_action": "allow", "rules": []})
DENY_ALL = parse_ruleset({"default_action": "deny", "rules": []})
INP = EvalInput("t")


def test_agt_disabled_returns_native():
    native = evaluate(ALLOW_ALL, INP)
    decision, degraded = combine_with_agt(native, ALLOW_ALL, INP, AgtBackend(enabled=False))
    assert decision.action is Action.ALLOW
    assert not degraded


def test_agt_unreachable_fails_closed_on_allow():
    native = evaluate(ALLOW_ALL, INP)
    decision, degraded = combine_with_agt(
        native, ALLOW_ALL, INP, AgtBackend(enabled=True, reachable=False)
    )
    assert decision.action is Action.DENY   # no second-front confirmation -> deny
    assert degraded


def test_degrade_to_native_serves_native_but_flags():
    native = evaluate(ALLOW_ALL, INP)
    decision, degraded = combine_with_agt(
        native, ALLOW_ALL, INP,
        AgtBackend(enabled=True, reachable=False, degrade_to_native=True),
    )
    assert decision.action is Action.ALLOW
    assert degraded


def test_native_deny_stands_when_agt_unreachable():
    native = evaluate(DENY_ALL, INP)
    decision, degraded = combine_with_agt(
        native, DENY_ALL, INP, AgtBackend(enabled=True, reachable=False)
    )
    assert decision.action is Action.DENY
    assert degraded


def test_agt_available_can_only_tighten():
    native = evaluate(ALLOW_ALL, INP)
    agt = AgtBackend(
        enabled=True, reachable=True,
        evaluator_fn=lambda ruleset, inp: Decision(Action.DENY, "agt says no"),
    )
    decision, degraded = combine_with_agt(native, ALLOW_ALL, INP, agt)
    assert decision.action is Action.DENY
    assert not degraded
    assert "AGT" in decision.reason
