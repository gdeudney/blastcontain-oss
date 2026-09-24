"""Host-owned model routing. Credentials/destinations never come from a worker."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import hashlib
from typing import Callable

import httpx

from ..contracts import ContractError
from ..plugins.catalog import parse_json
from .artifacts import canonical, digest
from .budgets import BudgetExceeded, Ledger

MAX_INPUT = 131_072
MAX_OUTPUT = 32_768
MAX_RESPONSE = 1_048_576


class ModelError(RuntimeError):
    """Deliberately excludes provider error text, headers and credentials."""


@dataclass(frozen=True)
class ModelReply:
    text: str
    input_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True)
class ModelCall:
    case_id: str
    channel: str
    request_digest: str
    response_digest: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    status: str = "pending"
    conversation_scope: str | None = None
    conversation_sequence: int | None = None


async def http_completion(settings, messages, secret, timeout, max_tokens):
    """Single bounded request: no redirects, proxy inheritance or transport retries."""
    headers = {"Accept-Encoding": "identity"}
    if secret is not None:
        headers["Authorization"] = "Bearer " + secret
    payload = {
        "model": settings.model_ref,
        "messages": messages,
        "temperature": settings.temperature,
        "max_tokens": max_tokens,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    async with httpx.AsyncClient(
        transport=httpx.AsyncHTTPTransport(retries=0),
        trust_env=False,
        follow_redirects=False,
        timeout=timeout,
    ) as client:
        async with client.stream(
            "POST",
            settings.endpoint_url.rstrip("/") + "/chat/completions",
            headers=headers,
            json=payload,
        ) as response:
            if (
                response.status_code != 200
                or response.headers.get("content-encoding", "identity") != "identity"
            ):
                raise ModelError("provider_response_rejected")
            raw = bytearray()
            async for chunk in response.aiter_raw():
                raw.extend(chunk)
                if len(raw) > MAX_RESPONSE:
                    raise ModelError("provider_response_too_large")
    data = parse_json(bytes(raw))
    try:
        text = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ModelError("provider_response_invalid") from exc
    usage = data.get("usage") or {}

    def count(name):
        value = usage.get(name) if type(usage) is dict else None
        return value if type(value) is int and 0 <= value <= 10**12 else None

    return ModelReply(text, count("prompt_tokens"), count("completion_tokens"))


class ModelBroker:
    def __init__(
        self,
        settings,
        *,
        credentials: Callable[[str], str] | None = None,
        transport=None,
        authorize=None,
        trace=None,
    ):
        self.settings = {m.channel: m for m in settings}
        self.credentials = credentials
        self.transport = transport or http_completion
        self.authorize = authorize
        self.trace = trace
        self.calls: list[ModelCall] = []

    async def chat(
        self,
        case_id: str,
        ledger: Ledger,
        channel: str,
        messages,
        *,
        max_tokens: int,
        conversation_scope=None,
        conversation_sequence=None,
    ):
        settings = self.settings.get(channel)
        if settings is None:
            raise ModelError("model_channel_unconfigured")
        if (
            type(messages) is not list
            or not messages
            or type(max_tokens) is not int
            or max_tokens < 1
        ):
            raise ContractError("Invalid model request")
        for message in messages:
            if (
                type(message) is not dict
                or set(message) != {"role", "content"}
                or message["role"] not in ("system", "user", "assistant")
                or type(message["content"]) is not str
            ):
                raise ContractError("Invalid model message")
        encoded = canonical(messages)
        if len(encoded) > MAX_INPUT:
            raise ModelError("model_input_too_large")
        # Detach mutable input before any await; settings/call routing are host-owned.
        messages = parse_json(encoded)
        if self.authorize is not None:
            self.authorize()
        ledger.reserve("model_calls")
        index = len(self.calls)
        self.calls.append(
            ModelCall(
                case_id,
                channel,
                digest(
                    {
                        "settings": settings.to_dict(),
                        "messages": messages,
                        "max_tokens": min(max_tokens, settings.max_output_tokens),
                    }
                ),
                conversation_scope=conversation_scope,
                conversation_sequence=conversation_sequence,
            )
        )
        try:
            secret = None
            if settings.credential_ref is not None:
                if self.credentials is None:
                    raise ModelError("credential_unavailable")
                secret = self.credentials(settings.credential_ref)
                if type(secret) is not str or not secret or any(c in secret for c in "\r\n"):
                    raise ModelError("credential_unavailable")
            async with asyncio.timeout(ledger.remaining()):
                reply = await self.transport(
                    settings,
                    messages,
                    secret,
                    ledger.remaining(),
                    min(max_tokens, settings.max_output_tokens),
                )
            ledger.check_time()
            if (
                type(reply) is not ModelReply
                or type(reply.text) is not str
                or not reply.text.strip()
                or len(reply.text.encode()) > MAX_OUTPUT
            ):
                raise ModelError("model_output_invalid")
            # A provider may echo its Authorization value in content. Never pass
            # the resolved credential to a fixture/worker or a retained trace.
            if secret:
                reply = replace(reply, text=reply.text.replace(secret, "[credential removed]"))
                if len(reply.text.encode()) > MAX_OUTPUT:
                    raise ModelError("model_output_invalid")
            counts = [
                v if type(v) is int and 0 <= v <= 10**12 else None
                for v in (reply.input_tokens, reply.output_tokens)
            ]
            self.calls[index] = replace(
                self.calls[index],
                response_digest="sha256:" + hashlib.sha256(reply.text.encode()).hexdigest(),
                input_tokens=counts[0],
                output_tokens=counts[1],
                status="completed",
            )
            if self.trace is not None:
                self.trace(
                    {
                        "case_id": case_id,
                        "channel": channel,
                        "request_digest": self.calls[index].request_digest,
                        "response_digest": self.calls[index].response_digest,
                        "messages": [
                            {
                                **m,
                                "content": m["content"].replace(secret, "[credential removed]")
                                if secret
                                else m["content"],
                            }
                            for m in messages
                        ],
                        "response": reply.text,
                    }
                )
            return reply.text
        except asyncio.CancelledError:
            self.calls[index] = replace(self.calls[index], status="cancelled")
            raise
        except (TimeoutError, BudgetExceeded):
            self.calls[index] = replace(self.calls[index], status="timeout")
            raise
        except Exception:
            self.calls[index] = replace(self.calls[index], status="error")
            raise ModelError("model_call_failed") from None
