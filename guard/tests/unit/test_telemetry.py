"""CloudEvents construction, sinks, and the off-hot-path async emitter."""
from blastcontain_guard.models import Action, Decision
from blastcontain_guard.telemetry import (
    AsyncEmitter,
    Emitter,
    JsonlSink,
    MemorySink,
    OtelSink,
    build_decision_event,
    build_learning_event,
)
from blastcontain_guard.models import LearningProposal


def _event():
    return build_decision_event(
        "agent", "prod", "delete_x", "delete",
        Decision(Action.DENY, "blocked", rule="r", approvers=["central"], concern="x"),
        allowed=False, latency_ms=1.25,
    )


def test_decision_event_shape():
    ev = _event()
    assert ev["specversion"] == "1.0"
    assert ev["type"] == "com.blastcontain.guard.decision"
    assert ev["subject"] == "delete_x"
    data = ev["data"]
    assert data["tool"] == "delete_x"
    assert data["decision"] == "deny"
    assert data["final"] == "deny"
    assert data["approver"] == "central"
    assert data["latency_ms"] == 1.25


def test_final_override_records_unresolved_ask():
    ev = build_decision_event(
        "a", "prod", "t", "read", Decision(Action.ASK, "ask"),
        allowed=False, final="ask",
    )
    assert ev["data"]["final"] == "ask"


def test_learning_event_shape():
    ev = build_learning_event("a", "prod", LearningProposal("a", "tool1", "send"))
    assert ev["type"] == "com.blastcontain.guard.learning_proposal"
    assert ev["data"]["tool_name"] == "tool1"


def test_memory_sink():
    s = MemorySink()
    s.emit(_event())
    assert len(s.events) == 1
    s.clear()
    assert not s.events


def test_jsonl_sink(tmp_path):
    p = tmp_path / "decisions.jsonl"
    s = JsonlSink(str(p))
    s.emit(_event())
    s.emit(_event())
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_sync_emitter_swallows_sink_errors():
    class Bad:
        def emit(self, event):
            raise RuntimeError("down")

    mem = MemorySink()
    Emitter([Bad(), mem]).emit(_event())  # must not raise
    assert len(mem.events) == 1           # the good sink still got it


def test_async_emitter_drains_on_flush():
    mem = MemorySink()
    emitter = AsyncEmitter([mem])
    try:
        for _ in range(5):
            emitter.emit(_event())
        emitter.flush(timeout=2.0)
        assert len(mem.events) == 5
    finally:
        emitter.close()


def test_otel_sink_noop_when_unavailable():
    sink = OtelSink()
    sink.emit(_event())
    if not sink.available:
        assert sink.dropped == 1
