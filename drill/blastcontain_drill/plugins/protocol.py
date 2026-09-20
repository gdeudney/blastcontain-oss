"""Bounded JSON-lines wire protocol; plugin results are always untrusted claims."""

from __future__ import annotations

import json

from ..contracts.wire import ContractError, _json_data
from .catalog import parse_json

PROTOCOL = 1
MAX_FRAME = 65536
METHODS = frozenset({"prepare", "reset", "execute", "close"})
CHANNELS = frozenset({"target", "attacker", "evaluator"})
_FIELDS = {
    "request": {"protocol", "type", "id", "method", "params"},
    "result": {"protocol", "type", "id", "result"},
    "error": {"protocol", "type", "id", "error"},
    "call": {"protocol", "type", "id", "call_id", "channel", "payload"},
    "reply": {"protocol", "type", "id", "call_id", "result"},
}


class ProtocolError(ContractError):
    pass


def validate(message):
    if (
        type(message) is not dict
        or type(message.get("type")) is not str
        or message["type"] not in _FIELDS
    ):
        raise ProtocolError("Unknown message type")
    if set(message) != _FIELDS[message["type"]]:
        raise ProtocolError("Missing or unknown message fields")
    if type(message["protocol"]) is not int or message["protocol"] != PROTOCOL:
        raise ProtocolError("Unsupported worker protocol")
    for key in ("id", "call_id"):
        if key in message and (type(message[key]) is not int or message[key] < 1):
            raise ProtocolError("Message IDs must be positive integers")
    if message["type"] == "request" and (
        type(message["method"]) is not str or message["method"] not in METHODS
    ):
        raise ProtocolError("Unsupported method")
    if message["type"] == "call" and (
        type(message["channel"]) is not str or message["channel"] not in CHANNELS
    ):
        raise ProtocolError("Unsupported broker channel")
    for key in ("params", "result", "payload"):
        if key in message and type(message[key]) is not dict:
            raise ProtocolError(f"{key} must be an object")
    if "error" in message and (type(message["error"]) is not str or not message["error"]):
        raise ProtocolError("Error must be nonempty text")
    try:
        _json_data(message, "message")
    except (ContractError, RecursionError) as exc:
        raise ProtocolError("Message contains invalid JSON data") from exc
    return message


def encode(message, max_bytes=MAX_FRAME):
    validate(message)
    data = json.dumps(message, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    if len(data) > max_bytes:
        raise ProtocolError("Worker frame exceeds byte limit")
    return data


def decode(data: bytes, max_bytes=MAX_FRAME):
    if len(data) > max_bytes or not data.endswith(b"\n"):
        raise ProtocolError("Oversized or unterminated worker frame")
    try:
        return validate(parse_json(data))
    except ContractError as exc:
        raise ProtocolError(str(exc)) from exc
