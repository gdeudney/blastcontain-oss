"""
Minimal OpenAI-compatible chat client.

Works with any server that speaks the OpenAI `/v1/chat/completions` API —
LM Studio (the local default, http://localhost:1234/v1), vLLM, Ollama's
OpenAI shim, etc. Both the in-cage *target* agent and the content-plane
*judge*/*guard* scorers drive models through this one client, so a fake
client (see cage/stub.py) can stand in for any of them in tests.
"""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class ChatBackend(Protocol):
    """The single method the cage and scorers depend on."""

    def chat(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        max_tokens: int = 512,
        stop: Optional[list[str]] = None,
    ) -> str: ...


class ChatClient:
    """An OpenAI-compatible chat client backed by httpx."""

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "lm-studio",
        timeout: float = 120.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    def is_available(self) -> bool:
        """True if the server answers a /models request."""
        try:
            import httpx

            r = httpx.get(f"{self.base_url}/models", headers=self._headers(), timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> list[str]:
        try:
            import httpx

            r = httpx.get(f"{self.base_url}/models", headers=self._headers(), timeout=5)
            r.raise_for_status()
            return [m.get("id", "") for m in r.json().get("data", [])]
        except Exception:
            return []

    def chat(
        self,
        messages: list[dict],
        temperature: float = 0.7,
        max_tokens: int = 512,
        stop: Optional[list[str]] = None,
    ) -> str:
        import httpx

        payload: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            # Ask reasoning models (Qwen3 etc.) to skip extended thinking so the
            # answer lands in `content` instead of burning the whole token budget
            # on `reasoning_content`. Harmlessly ignored by non-reasoning models.
            "chat_template_kwargs": {"enable_thinking": False},
        }
        if stop:
            payload["stop"] = stop
        r = httpx.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        data = r.json()
        choice = (data.get("choices") or [{}])[0]
        return (choice.get("message") or {}).get("content") or ""
