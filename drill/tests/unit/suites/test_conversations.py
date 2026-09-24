"""History integrity, isolation and cumulative limits for host-owned model sessions."""

import asyncio
from dataclasses import FrozenInstanceError, replace

import pytest

from blastcontain_drill.contracts import ContractError
from blastcontain_drill.suites.broker import ModelBroker, ModelError, ModelReply
from blastcontain_drill.suites.budgets import BudgetExceeded, Ledger
from blastcontain_drill.suites.conversations import ConversationLimits, ModelConversation
from blastcontain_drill.suites.schema import Limits, ModelSettings

CASE = "sha256:" + "b" * 64
SYSTEM = "Only produce controlled test prompts."
SECRET = "PRIVATE_CONVERSATION_SENTINEL"


def session(*, transport=None, limits=None, calls=20, channel="attacker", broker=None, ledger=None):
    if broker is None:

        async def reply(*args):
            return ModelReply("observed answer")

        broker = ModelBroker(
            (ModelSettings(channel, "http://127.0.0.1:1234/v1", "recording-model"),),
            transport=transport or reply,
        )
    if ledger is None:
        ledger = Ledger(Limits(model_calls=calls))
        ledger.begin(Limits(model_calls=calls))
    conversation = ModelConversation(
        broker,
        ledger,
        run_id="a" * 32,
        case_id=CASE,
        channel=channel,
        system_message=SYSTEM,
        limits=limits or ConversationLimits(),
    )
    return conversation, broker, ledger


def test_history_contains_only_host_system_users_and_observed_assistant_messages():
    requests = []

    async def transport(settings, messages, *args):
        requests.append([dict(m) for m in messages])
        messages[0]["content"] = "transport mutation must not change stored history"
        return ModelReply("answer " + str(len(requests)))

    conversation, broker, ledger = session(transport=transport)

    async def exercise():
        first = await conversation.send(conversation.root, SECRET)
        snapshot = conversation.events
        second = await conversation.send(first.checkpoint, "next question")
        assert conversation.head == second.checkpoint
        assert len(snapshot) == 1
        assert snapshot[0].checkpoint == first.checkpoint

    asyncio.run(exercise())
    assert requests[1] == [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": SECRET},
        {"role": "assistant", "content": "answer 1"},
        {"role": "user", "content": "next question"},
    ]
    assert len(broker.calls) == ledger.usage().model_calls == 2
    assert SECRET not in repr(conversation.events) and SYSTEM not in repr(conversation.events)
    with pytest.raises(FrozenInstanceError):
        conversation.events[0].status = "forged"


@pytest.mark.parametrize("branching", [False, True])
def test_branching_preserves_observed_attempts_and_never_refunds_usage(branching):
    requests = []

    async def transport(settings, messages, *args):
        requests.append(messages)
        return ModelReply("response " + str(len(requests)))

    conversation, broker, ledger = session(
        transport=transport,
        limits=ConversationLimits(allow_branching=branching),
        calls=2,
    )

    async def exercise():
        first = await conversation.send(conversation.root, "first branch")
        if not branching:
            with pytest.raises(ContractError, match="branching"):
                await conversation.send(conversation.root, "second branch")
            assert len(broker.calls) == 1
            return
        second = await conversation.send(conversation.root, "second branch")
        assert first.checkpoint != second.checkpoint
        assert requests[1] == [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": "second branch"},
        ]
        with pytest.raises(BudgetExceeded):
            await conversation.send(first.checkpoint, "fork again")
        assert [e.status for e in conversation.events] == ["completed", "completed", "limited"]
        assert conversation.events[0].response_digest is not None
        assert ledger.usage().model_calls == 2

    asyncio.run(exercise())


def test_foreign_checkpoint_and_changed_model_or_case_are_rejected_before_dispatch():
    conversation, broker, ledger = session()
    other, _, _ = session(broker=broker, ledger=ledger)

    async def exercise():
        with pytest.raises(ContractError, match="foreign"):
            await other.send(conversation.root, "cannot inherit another session")
        broker.settings["attacker"] = replace(broker.settings["attacker"], model_ref="different")
        with pytest.raises(ContractError, match="binding changed"):
            await conversation.send(conversation.root, "cannot change model")
        ledger.end()
        ledger.begin(Limits())
        with pytest.raises(ContractError, match="ledger changed"):
            await conversation.send(conversation.root, "cannot reuse a case")

    asyncio.run(exercise())
    assert not broker.calls


def test_failed_dispatch_remains_charged_and_uses_attempt_limit_without_storing_error_text():
    async def broken(*args):
        raise RuntimeError(SECRET)

    conversation, broker, ledger = session(
        transport=broken,
        limits=ConversationLimits(max_attempts=1),
    )

    async def exercise():
        with pytest.raises(ModelError):
            await conversation.send(conversation.root, "first")
        with pytest.raises(ContractError, match="attempt limit"):
            await conversation.send(conversation.root, "retry")

    asyncio.run(exercise())
    assert ledger.usage().model_calls == len(broker.calls) == 1
    assert conversation.events[0].status == "error"
    assert conversation.events[0].checkpoint is None
    assert SECRET not in repr(conversation.events)
    assert conversation.head == conversation.root


def test_active_cancellation_refuses_concurrent_send_and_close_then_revokes_history():
    async def exercise():
        entered = asyncio.Event()

        async def blocked(*args):
            entered.set()
            await asyncio.Future()

        conversation, broker, ledger = session(transport=blocked)
        task = asyncio.create_task(conversation.send(conversation.root, SECRET))
        await entered.wait()
        with pytest.raises(ContractError, match="dispatching"):
            await conversation.send(conversation.root, "concurrent")
        with pytest.raises(ContractError, match="active dispatch"):
            conversation.close()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert conversation.events[0].status == broker.calls[0].status == "cancelled"
        assert ledger.usage().model_calls == 1
        conversation.close()
        assert not conversation._nodes
        with pytest.raises(ContractError, match="closed"):
            await conversation.send(conversation.root, "cannot resurrect")

    asyncio.run(exercise())


@pytest.mark.parametrize("overflow", ["request", "response"])
def test_history_limit_does_not_publish_a_truncated_or_fabricated_checkpoint(overflow):
    async def reply(*args):
        return ModelReply(SECRET * 80)

    conversation, broker, ledger = session(
        transport=reply,
        limits=ConversationLimits(max_history_bytes=1024),
    )
    with pytest.raises(ContractError, match="history limit"):
        asyncio.run(
            conversation.send(conversation.root, "x" * 2000 if overflow == "request" else "x")
        )
    assert conversation.head == conversation.root
    if overflow == "request":
        assert not broker.calls and not conversation.events
        assert ledger.usage().model_calls == 0
    else:
        assert ledger.usage().model_calls == 1
        assert conversation.events[0].status == "error"
        assert conversation.events[0].response_digest is not None
        assert conversation.events[0].checkpoint is None


def test_channels_share_global_budget_and_target_checkpointing_is_not_implied():
    pool = Ledger(Limits(model_calls=1))
    first, _, _ = session(channel="attacker", ledger=pool.fork(Limits()))
    second, _, _ = session(channel="evaluator", ledger=pool.fork(Limits()))
    asyncio.run(first.send(first.root, "consume shared budget"))
    with pytest.raises(BudgetExceeded):
        asyncio.run(second.send(second.root, "no separate budget"))
    with pytest.raises(ContractError, match="target conversation"):
        session(channel="target")


def test_echoed_provider_credential_never_enters_followup_history_or_trace():
    requests, traces = [], []

    async def transport(settings, messages, secret, *args):
        assert secret == SECRET
        requests.append(messages)
        return ModelReply("echo: " + secret)

    broker = ModelBroker(
        (
            ModelSettings(
                "attacker", "http://127.0.0.1:1234/v1", "recording", credential_ref="local"
            ),
        ),
        credentials=lambda ref: SECRET,
        transport=transport,
        trace=traces.append,
    )
    conversation, _, _ = session(broker=broker)

    async def exercise():
        first = await conversation.send(conversation.root, "first")
        assert SECRET not in first.text
        await conversation.send(first.checkpoint, "continue")

    asyncio.run(exercise())
    assert requests[1][2] == {"role": "assistant", "content": "echo: [credential removed]"}
    assert SECRET not in repr(requests) + repr(traces) + repr(conversation.events)


@pytest.mark.parametrize(
    "changes",
    [
        {"max_attempts": 0},
        {"max_attempts": 65},
        {"max_attempts": True},
        {"max_history_bytes": 1023},
        {"max_history_bytes": 131073},
        {"allow_branching": 1},
    ],
)
def test_invalid_limits_fail_closed(changes):
    with pytest.raises(ContractError):
        ConversationLimits(**changes)
