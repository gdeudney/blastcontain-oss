"""
blastcontain_guard.telemetry — every decision as a CloudEvent (guard-spec §10).

Each allow/ask/deny is emitted as a CloudEvents 1.0 envelope over one or more
pluggable sinks. This *is* the audit trail and the HITL-quality feed (latency,
override rate) — there is no separate logging path. The decision payload carries
exactly what the Ledger needs: ``{agent_id, tool, action, decision, approver,
latency_ms, ts}`` plus the rule, risk tag, and resolution.

Sinks ship for the common cases:
  * ``MemorySink``  — in-process buffer (what the signed decision log is built
    from; also what tests assert against);
  * ``JsonlSink``   — one JSON line per event, append-only, local and free;
  * ``LedgerSink``  — POST to the BlastContain Ledger;
  * ``OtelSink``    — export to OpenTelemetry *if it is installed* (availability
    flag); otherwise a counted no-op.

Network sinks run off the hot path: wrap them in ``AsyncEmitter`` and the
tool-call thread only enqueues; a daemon thread drains. Emission never raises —
a telemetry failure must not break enforcement.
"""
from __future__ import annotations

import datetime
import json
import os
import queue
import threading
import time
import uuid
from typing import Optional, Protocol

from .augmentation import OTEL_AVAILABLE
from .models import Decision, LearningProposal

DECISION_EVENT_TYPE = "com.blastcontain.guard.decision"
LEARNING_EVENT_TYPE = "com.blastcontain.guard.learning_proposal"


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


# ── event construction ─────────────────────────────────────────────────────────

def build_decision_event(
    agent_id: str,
    environment: str,
    tool_name: str,
    action_type: str,
    decision: Decision,
    *,
    allowed: bool,
    latency_ms: float = 0.0,
    ask_choice: Optional[str] = None,
    approver_id: Optional[str] = None,
    degraded: bool = False,
    final: Optional[str] = None,
    event_id: Optional[str] = None,
    ts: Optional[str] = None,
) -> dict:
    """Build the CloudEvents envelope for one decision.

    ``final`` is the post-resolution outcome (``allow``/``deny``); pass it
    explicitly for the pass-through case where the host renders the *ask* itself
    (the Claude Code hook), so the event can record an unresolved ``ask``.
    """
    when = ts or _utc_now_iso()
    data = {
        "agent_id": agent_id,
        "environment": environment,
        "tool": tool_name,
        "action_type": action_type,
        "decision": decision.action.value,           # allow | ask | deny (evaluated)
        "final": final or ("allow" if allowed else "deny"),   # outcome after resolution
        "rule": decision.rule,
        "matched": decision.matched,
        "approver": decision.approvers[0] if decision.approvers else None,
        "approvers": list(decision.approvers),
        "approver_id": approver_id,
        "ask_choice": ask_choice,
        "risk_tag": decision.risk_tag,
        "concern": decision.concern,
        "reason": decision.reason,
        "latency_ms": round(latency_ms, 3),
        "degraded": degraded,
        "ts": when,
    }
    return _envelope(DECISION_EVENT_TYPE, agent_id, tool_name, data, event_id, when)


def build_learning_event(
    agent_id: str, environment: str, proposal: LearningProposal,
    event_id: Optional[str] = None, ts: Optional[str] = None,
) -> dict:
    when = ts or _utc_now_iso()
    data = {"environment": environment, **proposal.as_dict()}
    return _envelope(LEARNING_EVENT_TYPE, agent_id, proposal.tool_name, data, event_id, when)


def _envelope(
    event_type: str, agent_id: str, subject: str, data: dict,
    event_id: Optional[str], when: str,
) -> dict:
    return {
        "specversion": "1.0",
        "type": event_type,
        "source": f"blastcontain-guard/{agent_id or 'unknown'}",
        "id": event_id or str(uuid.uuid4()),
        "time": when,
        "subject": subject,
        "datacontenttype": "application/json",
        "data": data,
    }


# ── sinks ──────────────────────────────────────────────────────────────────────

class Sink(Protocol):
    def emit(self, event: dict) -> None: ...


class MemorySink:
    """Keeps events in a list — the buffer the signed decision log is built from."""

    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()


class NullSink:
    def emit(self, event: dict) -> None:  # noqa: D401 - intentional no-op
        return


class JsonlSink:
    """Append one JSON line per event. Local, free, air-gap friendly."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def emit(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":"))
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


class LedgerSink:
    """POST each decision to the BlastContain Ledger (mirrors Drill's path)."""

    def __init__(self, blastcontain_url: str, agent_id: str, timeout: float = 5.0) -> None:
        self.url = f"{blastcontain_url.rstrip('/')}/v1/agents/{agent_id}/decisions"
        self.timeout = timeout
        self.dropped = 0

    def emit(self, event: dict) -> None:
        try:
            import httpx

            httpx.post(self.url, json=event, timeout=self.timeout)
        except Exception:
            self.dropped += 1


class OtelSink:
    """Export decisions to OpenTelemetry — used only if it is installed (§ flag).

    A counted no-op when ``opentelemetry`` is absent. Wiring an exporter/provider
    is the integrator's job; this records the decision as a span event on
    whatever tracer the host has configured.
    """

    def __init__(self) -> None:
        self.available = OTEL_AVAILABLE
        self.dropped = 0
        self._tracer = None

    def emit(self, event: dict) -> None:
        if not self.available:
            self.dropped += 1
            return
        try:
            from opentelemetry import trace

            if self._tracer is None:
                self._tracer = trace.get_tracer("blastcontain-guard")
            data = event.get("data", {})
            with self._tracer.start_as_current_span("guard.decision") as span:
                for key in ("agent_id", "tool", "action_type", "decision", "final", "rule"):
                    value = data.get(key)
                    if value is not None:
                        span.set_attribute(f"guard.{key}", value)
        except Exception:
            self.dropped += 1


# ── emitters ───────────────────────────────────────────────────────────────────

class Emitter:
    """Synchronous best-effort fan-out. Suitable for local sinks (memory/jsonl)."""

    def __init__(self, sinks: list[Sink]):
        self.sinks: list[Sink] = list(sinks)

    def emit(self, event: dict) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception:
                pass

    def flush(self, timeout: float = 2.0) -> None:
        return

    def close(self) -> None:
        for sink in self.sinks:
            closer = getattr(sink, "close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass


class AsyncEmitter(Emitter):
    """Off-hot-path emitter: enqueue on emit, drain on a daemon thread.

    Honours guard-spec §5/§10 — "no network on the hot path (decisions emit
    async)". Under backpressure events are dropped rather than blocking the
    tool call.
    """

    def __init__(self, sinks: list[Sink], max_queue: int = 2048):
        super().__init__(sinks)
        self._q: queue.Queue = queue.Queue(maxsize=max_queue)
        self._stop = threading.Event()
        self.dropped = 0
        self._thread = threading.Thread(
            target=self._run, name="guard-telemetry", daemon=True
        )
        self._thread.start()

    def emit(self, event: dict) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while not self._stop.is_set() or not self._q.empty():
            try:
                event = self._q.get(timeout=0.1)
            except queue.Empty:
                continue
            for sink in self.sinks:
                try:
                    sink.emit(event)
                except Exception:
                    pass
            self._q.task_done()

    def flush(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while not self._q.empty() and time.monotonic() < deadline:
            time.sleep(0.01)

    def close(self) -> None:
        self.flush()
        self._stop.set()
        self._thread.join(timeout=2.0)
        super().close()
