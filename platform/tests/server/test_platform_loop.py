"""Closed loop: the platform issues a signed Charter over real HTTP and the OSS
Guard fetches, verifies, and enforces it — the graduation path (guard-spec §1.1).
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

uvicorn = pytest.importorskip("uvicorn")
pytest.importorskip("blastcontain_guard")
pytest.importorskip("httpx")

import httpx  # noqa: E402
from blastcontain_guard.errors import GuardError  # noqa: E402
from blastcontain_guard.guard import Guard  # noqa: E402
from blastcontain_guard.models import Action, EvalInput  # noqa: E402
from conftest import CHARTER_BODY  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(app):
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start in time")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _author_and_sign(base: str) -> None:
    import copy

    body = copy.deepcopy(CHARTER_BODY)
    assert httpx.post(f"{base}/v1/charters", json=body).status_code == 201
    signed = httpx.post(f"{base}/v1/charters/invoice-bot/sign?env=prod",
                        json={"actor": "alice@example.com"})
    assert signed.status_code == 200, signed.text


def test_guard_enforces_a_platform_issued_charter(live_server):
    _author_and_sign(live_server)

    guard = Guard.from_charter("invoice-bot", env="prod", base_url=live_server)

    assert guard.agent_id == "invoice-bot"
    assert guard.autonomy_mode == "interactive"
    # the allowlist holds…
    allowed = guard.evaluate(EvalInput("query_invoice", action_type="read"))
    assert allowed.action is Action.ALLOW
    # …destructive actions gate on the human (interactive copilot)…
    gated = guard.evaluate(EvalInput("update_ledger", action_type="delete"))
    assert gated.action is Action.ASK
    # …and everything outside the Charter is, by definition, a violation.
    denied = guard.evaluate(EvalInput("exfiltrate", action_type="exec"))
    assert denied.action is Action.DENY


def test_pause_on_the_platform_becomes_deny_all_at_the_edge(live_server):
    _author_and_sign(live_server)
    httpx.post(f"{live_server}/v1/agents/invoice-bot/pause?env=prod",
               json={"actor": "ops", "mode": "deny-all"})

    guard = Guard.from_charter("invoice-bot", env="prod", base_url=live_server)
    # even the previously permitted tool is denied while paused
    decision = guard.evaluate(EvalInput("query_invoice", action_type="read"))
    assert decision.action is Action.DENY


def test_unsigned_platform_is_rejected(live_server, signing_env):
    _author_and_sign(live_server)
    # The serving platform signed with the test key; a Guard whose environment
    # lacks that key cannot verify the HMAC signature and must refuse.
    signing_env.setenv("BLASTCONTAIN_SIGNING_KEY", "some-other-key")
    with pytest.raises(GuardError, match="verification FAILED"):
        Guard.from_charter("invoice-bot", env="prod", base_url=live_server)


def test_stream_pushes_ledger_events(live_server):
    """/stream (SSE): a finding ingested after connect arrives as an event."""
    _author_and_sign(live_server)
    timeout = httpx.Timeout(10.0, read=10.0)
    with httpx.stream("GET", f"{live_server}/stream", timeout=timeout) as response:
        assert response.status_code == 200
        lines = response.iter_lines()
        assert next(lines).startswith(": connected")
        httpx.post(f"{live_server}/v1/agents/invoice-bot/findings",
                   json={"environment": "prod", "status": "PASSED",
                         "summary": {"critical": 0}, "findings": []})
        seen = []
        for line in lines:
            seen.append(line)
            if line.startswith("data:") and '"finding"' in line:
                break
            assert len(seen) < 50, f"no finding event in stream: {seen}"
        payload = [ln for ln in seen if ln.startswith("data:")][-1]
        assert '"agent_id": "invoice-bot"' in payload


def test_guard_decisions_flow_back_to_the_ledger(live_server):
    _author_and_sign(live_server)
    from blastcontain_guard.telemetry import LedgerSink

    sink = LedgerSink(live_server, "invoice-bot")
    sink.emit({
        "specversion": "1.0", "type": "com.blastcontain.guard.decision",
        "source": "blastcontain-guard/invoice-bot", "id": "evt-loop-1",
        "subject": "query_invoice",
        "data": {"agent_id": "invoice-bot", "environment": "prod",
                 "tool": "query_invoice", "decision": "allow", "final": "allow"},
    })
    assert sink.dropped == 0
    decisions = httpx.get(
        f"{live_server}/v1/agents/invoice-bot/decisions?env=prod"
    ).json()["decisions"]
    assert decisions and decisions[0]["data"]["tool"] == "query_invoice"
