"""The derive-then-ratify learning signal."""
import json

from blastcontain_guard.learning import LearningStore


def test_propose_and_dedup():
    captured = []
    store = LearningStore(sink=captured.append)
    p = store.propose_permitted_tool("agent", "send_email", "send", approver_id="alice")
    assert p is not None and p.tool_name == "send_email"
    assert captured and captured[0].tool_name == "send_email"

    # Same (tool, action) again -> no duplicate proposal.
    assert store.propose_permitted_tool("agent", "send_email", "send") is None
    assert len(store.pending()) == 1


def test_distinct_action_is_a_new_proposal():
    store = LearningStore()
    store.propose_permitted_tool("agent", "db", "read")
    store.propose_permitted_tool("agent", "db", "delete")
    assert len(store.pending()) == 2


def test_write(tmp_path):
    store = LearningStore()
    store.propose_permitted_tool("agent", "tool1", "send")
    out = tmp_path / "proposals.json"
    store.write(str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["proposals"][0]["tool_name"] == "tool1"
    assert "ratif" in data["_note"].lower()


def test_sink_failure_never_propagates():
    def boom(_):
        raise RuntimeError("sink down")

    store = LearningStore(sink=boom)
    # Must not raise — a learning signal can't break enforcement.
    assert store.propose_permitted_tool("a", "t", "read") is not None
