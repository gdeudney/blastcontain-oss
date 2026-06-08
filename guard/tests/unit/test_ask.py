"""Ask resolution: interactive vs autonomous, and the honesty line."""
from blastcontain_guard.ask import AskResolver
from blastcontain_guard.models import Action, AskChoice, AskResult, Decision, EvalInput

ASK_SELF = Decision(Action.ASK, "ask", rule="r", approvers=["self"])
ASK_CENTRAL = Decision(Action.ASK, "ask", rule="r", approvers=["central"])
INP = EvalInput("send_tool", action_type="send")


def test_interactive_allow_once():
    r = AskResolver(on_ask=lambda req: AskChoice.ALLOW_ONCE)
    allowed, result = r.resolve(ASK_SELF, INP)
    assert allowed and result.choice is AskChoice.ALLOW_ONCE


def test_interactive_allow_always():
    r = AskResolver(on_ask=lambda req: AskResult(AskChoice.ALLOW_ALWAYS))
    allowed, result = r.resolve(ASK_SELF, INP)
    assert allowed and result.choice is AskChoice.ALLOW_ALWAYS


def test_interactive_deny_via_string():
    r = AskResolver(on_ask=lambda req: "deny")
    allowed, result = r.resolve(ASK_SELF, INP)
    assert not allowed and result.choice is AskChoice.DENY


def test_no_handler_fails_closed():
    allowed, result = AskResolver().resolve(ASK_SELF, INP)
    assert not allowed and result.choice is AskChoice.DENY


def test_central_ask_never_user_approved():
    # Even with a permissive handler, a central Standard cannot be self-lifted.
    r = AskResolver(on_ask=lambda req: "allow always")
    allowed, result = r.resolve(ASK_CENTRAL, INP)
    assert not allowed
    assert "central" in (result.note or "").lower()


def test_central_ask_routes_to_central_approver_when_present():
    r = AskResolver(central_approver=lambda req: AskChoice.ALLOW_ONCE)
    allowed, _ = r.resolve(ASK_CENTRAL, INP)
    assert allowed


def test_autonomous_no_approver_denies():
    allowed, result = AskResolver(autonomy_mode="autonomous").resolve(ASK_SELF, INP)
    assert not allowed
    assert "compiles to deny" in (result.note or "")


def test_autonomous_async_approver_allows():
    r = AskResolver(
        autonomy_mode="autonomous",
        async_approver=lambda req, timeout: AskResult(AskChoice.ALLOW_ONCE),
    )
    allowed, _ = r.resolve(ASK_SELF, INP)
    assert allowed


def test_autonomous_timeout_denies():
    r = AskResolver(autonomy_mode="autonomous", async_approver=lambda req, timeout: None)
    allowed, result = r.resolve(ASK_SELF, INP)
    assert not allowed
    assert "timed out" in (result.note or "")


def test_unrecognised_response_denies():
    r = AskResolver(on_ask=lambda req: object())
    allowed, _ = r.resolve(ASK_SELF, INP)
    assert not allowed
