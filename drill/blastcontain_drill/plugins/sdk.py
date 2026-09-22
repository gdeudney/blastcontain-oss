"""Small container-side SDK. Import and run this inside the selected plugin image."""

from __future__ import annotations

import sys
from typing import Protocol

from ..contracts import Injection, ScenarioSpec
from .protocol import MAX_FRAME, ProtocolError, decode, encode


class Plugin(Protocol):
    def prepare(self, config: dict) -> None: ...
    def reset(self, scenario: ScenarioSpec) -> None: ...
    def execute(self, broker: Broker) -> dict: ...
    def close(self) -> None: ...


class Broker:
    def __init__(self, reader, writer, *, protocol=1):
        self.reader, self.writer = reader, writer
        self.protocol = protocol
        self.request_id = 0
        self.call_id = 0

    def call(self, channel: str, injection: Injection) -> dict:
        return self._call("call", channel, injection.to_dict())

    def conversation(self, channel: str, payload: dict) -> dict:
        """API 2 open/send/close; histories and credentials remain in the host."""
        if self.protocol != 2:
            raise ProtocolError("Conversations require worker protocol 2")
        return self._call("conversation", channel, payload)

    def environment(self, payload: dict) -> dict:
        """API 3 reviewed simulation observer, never an attack-strategy grant."""
        if self.protocol != 3:
            raise ProtocolError("Environment exchange requires worker protocol 3")
        return self._call("environment", "environment", payload)

    def _call(self, kind, channel, payload):
        self.call_id += 1
        self.writer.write(
            encode(
                {
                    "protocol": self.protocol,
                    "type": kind,
                    "id": self.request_id,
                    "call_id": self.call_id,
                    "channel": channel,
                    "payload": payload,
                }
            )
        )
        self.writer.flush()
        reply = decode(self.reader.readline(MAX_FRAME + 1))
        if (
            reply["protocol"] != self.protocol
            or reply["type"] != "reply"
            or reply["id"] != self.request_id
            or reply["call_id"] != self.call_id
        ):
            raise ProtocolError("Broker reply mismatch")
        return reply["result"]


def serve(plugin: Plugin, reader=None, writer=None, *, protocol=1):
    """A well-behaved plugin helper, not the security boundary; the host rechecks everything."""
    reader = reader or sys.stdin.buffer
    writer = writer or sys.stdout.buffer
    broker = Broker(reader, writer, protocol=protocol)
    last_id = 0
    prepared = reset = False
    while True:
        line = reader.readline(MAX_FRAME + 1)
        if not line:
            return
        request = decode(line)
        if (
            request["protocol"] != protocol
            or request["type"] != "request"
            or request["id"] != last_id + 1
        ):
            raise ProtocolError("Lifecycle request out of order")
        last_id = broker.request_id = request["id"]
        method, params = request["method"], request["params"]
        try:
            result = {}
            if method == "prepare" and not prepared:
                plugin.prepare(params)
                prepared = True
            elif method == "reset" and prepared:
                plugin.reset(ScenarioSpec.from_dict(params))
                reset = True
            elif method == "execute" and reset:
                result = plugin.execute(broker)
            elif method == "close":
                plugin.close()
            else:
                raise ProtocolError("Invalid lifecycle transition")
            response = {"protocol": protocol, "type": "result", "id": last_id, "result": result}
        except Exception as exc:
            response = {
                "protocol": protocol,
                "type": "error",
                "id": last_id,
                "error": str(exc)[:500] or type(exc).__name__,
            }
        writer.write(encode(response))
        writer.flush()
        if method == "close" or response["type"] == "error":
            return
