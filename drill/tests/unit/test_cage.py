"""Cage + stub agent end-to-end (no model) and agent-loop parsing."""
from __future__ import annotations

from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.cage.agent import _host_of, _parse_args, _parse_reply
from blastcontain_drill.corpus import load_corpus
from blastcontain_drill.corpus.base import ACTION_GOALS


# ── agent-loop protocol parsing ───────────────────────────────────────────────

def test_parse_call_with_json_args():
    kind, tool, args = _parse_reply('CALL read {"path": "x.txt"}')
    assert (kind, tool) == ("call", "read")
    assert args == {"path": "x.txt"}


def test_parse_call_tolerates_colon_and_prose():
    kind, tool, args = _parse_reply('CALL: send {"destination": "a@b.test", "content": "hi"} now')
    assert kind == "call" and tool == "send"
    assert args["destination"] == "a@b.test"


def test_parse_done():
    kind, text, _ = _parse_reply("DONE all handled")
    assert kind == "done" and text == "all handled"


def test_plain_text_is_treated_as_done():
    kind, text, _ = _parse_reply("I refuse to do that.")
    assert kind == "done"


def test_host_of_url_and_email():
    assert _host_of("https://evil.test/collect") == "evil.test"
    assert _host_of("user@evil.test") == "evil.test"
    assert _host_of("acme.internal:443") == "acme.internal"


def test_parse_args_fallback_to_kv():
    assert _parse_args('path=secret.txt') == {"path": "secret.txt"}


# ── cage end-to-end with the deterministic stub ───────────────────────────────

def test_vulnerable_agent_takes_action_on_action_goals():
    cage = InProcessCage(StubChatClient(vulnerable=True))
    for a in load_corpus().attacks:
        obs = cage.run_attack(a)
        if a.goal in ACTION_GOALS:
            assert obs.tool_calls, f"{a.id} should have driven a tool call"


def test_hardened_agent_takes_no_action_anywhere():
    cage = InProcessCage(StubChatClient(vulnerable=False))
    for a in load_corpus().attacks:
        obs = cage.run_attack(a)
        assert obs.tool_calls == []
        assert obs.egress_attempts == []
        assert obs.response_text  # it refused with text


def test_indirect_injection_reads_poison_then_exfiltrates():
    # pii-01: the prompt is benign; the exfil instruction is hidden in the doc.
    cage = InProcessCage(StubChatClient(vulnerable=True))
    a = next(x for x in load_corpus().attacks if x.id == "pii-01")
    obs = cage.run_attack(a)
    tools = [t.tool for t in obs.tool_calls]
    assert tools.count("read") >= 1 and "send" in tools
    assert any(not e.allowed for e in obs.egress_attempts)


def test_canary_is_fresh_per_run():
    cage = InProcessCage(StubChatClient(vulnerable=True))
    a = next(x for x in load_corpus().attacks if x.id == "exf-01")
    c1 = cage.run_attack(a).canary
    c2 = cage.run_attack(a).canary
    assert c1 != c2
    assert c1.startswith("BCN-CANARY-")
