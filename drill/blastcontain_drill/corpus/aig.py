"""
AI-Infra-Guard attack-source adapter (drill-spec §4.3) — availability-flagged.

AI-Infra-Guard (Tencent, Apache-2.0) is a heavy service (Docker, ~4 GB), so it
runs as a service, not a pip dependency. The whole integration is a
submit -> poll -> fetch loop against its task API:

    POST /api/v1/app/taskapi/tasks   {type, content}  -> data.session_id
    GET  /api/v1/app/taskapi/status/{id}              -> data.status
    GET  /api/v1/app/taskapi/result/{id}              -> data {...}

`type` discriminates: `model_redteam_report` (jailbreak) · `mcp_scan` · `ai_infra_scan`.

This adapter implements the loop and the availability flag. When the service is
absent (the common local case), `is_available()` is False and the corpus loader
silently falls back to the built-in Replay seed set.

NOTE: the per-prompt verdict/score fields in the `result` JSON are undocumented
upstream — confirm them empirically against a live scan before relying on the
mapping in `_attacks_from_result` (this mirrors the caveat in drill-spec §4.3).
"""
from __future__ import annotations

import os
import time
from typing import Optional

from .base import Attack, AttackSource

_DEFAULT_URL = "http://localhost:8088"


class AIGAttackSource(AttackSource):
    name = "ai-infra-guard"
    layer = "replay"

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = (base_url or os.environ.get("BLASTCONTAIN_AIG_URL", _DEFAULT_URL)).rstrip("/")
        self.token = token or os.environ.get("BLASTCONTAIN_AIG_TOKEN", "")
        self.timeout = timeout

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def is_available(self) -> bool:
        try:
            import httpx

            r = httpx.get(f"{self.base_url}/", headers=self._headers(), timeout=3)
            return r.status_code < 500
        except Exception:
            return False

    # ── task-API primitives (submit -> poll -> fetch) ─────────────────────────
    def _submit(self, task_type: str, content: dict) -> Optional[str]:
        import httpx

        r = httpx.post(
            f"{self.base_url}/api/v1/app/taskapi/tasks",
            json={"type": task_type, "content": content},
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return (r.json().get("data") or {}).get("session_id")

    def _poll(self, session_id: str, max_wait: float = 120.0) -> str:
        import httpx

        deadline = max_wait
        waited = 0.0
        while waited < deadline:
            r = httpx.get(
                f"{self.base_url}/api/v1/app/taskapi/status/{session_id}",
                headers=self._headers(),
                timeout=self.timeout,
            )
            status = (r.json().get("data") or {}).get("status", "")
            if status in ("completed", "failed"):
                return status
            time.sleep(2.0)
            waited += 2.0
        return "timeout"

    def _result(self, session_id: str) -> dict:
        import httpx

        r = httpx.get(
            f"{self.base_url}/api/v1/app/taskapi/result/{session_id}",
            headers=self._headers(),
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json().get("data") or {}

    @staticmethod
    def _attacks_from_result(result: dict) -> list[Attack]:
        """
        Best-effort mapping of AIG result prompts to Attack objects. The exact
        field names are unverified upstream — adjust once confirmed empirically.
        """
        attacks: list[Attack] = []
        prompts = result.get("prompts") or result.get("cases") or []
        for i, p in enumerate(prompts):
            text = p.get("prompt") if isinstance(p, dict) else str(p)
            if not text:
                continue
            attacks.append(
                Attack(
                    id=f"aig-{i:04d}",
                    category="jailbreak",
                    technique=(p.get("technique") if isinstance(p, dict) else None) or "aig",
                    prompt=text,
                    layer="replay",
                    source="ai-infra-guard",
                )
            )
        return attacks

    def dataset(
        self,
        categories: Optional[list[str]] = None,
        limit: Optional[int] = None,
    ) -> list[Attack]:
        if not self.is_available():
            return []
        try:
            session = self._submit(
                "model_redteam_report",
                {"dataset": {"dataFile": ["JailBench-Tiny"], "numPrompts": limit or 50}},
            )
            if not session:
                return []
            if self._poll(session) != "completed":
                return []
            return self._attacks_from_result(self._result(session))
        except Exception:
            return []
