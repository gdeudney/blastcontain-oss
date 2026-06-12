"""
Minimal OpenAI-compatible chat client (LM Studio on :1234 by default).

Self-contained so the scout has no runtime dependency on Drill. Carries the same
reasoning-model fix Drill learned: send `chat_template_kwargs.enable_thinking=false`
so reasoning models don't burn the whole token budget on hidden thinking and
return empty content.
"""
from __future__ import annotations

from typing import Optional


class ChatClient:
    def __init__(
        self,
        base_url: str = "http://localhost:1234/v1",
        model: str = "",
        timeout: float = 120.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        if not self.model:
            return False
        try:
            import httpx

            r = httpx.get(f"{self.base_url}/models", timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False

    def chat(self, messages, temperature: float = 0.0, max_tokens: int = 400) -> str:
        import httpx

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        r = httpx.post(f"{self.base_url}/chat/completions", json=payload, timeout=self.timeout)
        r.raise_for_status()
        data = r.json()
        return (data["choices"][0]["message"].get("content") or "").strip()


def make_backend(base_url: str, model: Optional[str]) -> Optional[ChatClient]:
    """Return a ChatClient if a model is configured and reachable, else None."""
    if not model:
        return None
    client = ChatClient(base_url=base_url, model=model)
    return client if client.is_available() else None
