"""
AI-Infra-Guard attack-source adapter (drill-spec §4.3) — availability-flagged.

AI-Infra-Guard (Tencent, Apache-2.0) runs as a service, not a pip dependency.
Stand it up (no auth — keep it on localhost only):

    git clone https://github.com/Tencent/AI-Infra-Guard && cd AI-Infra-Guard
    docker compose -f docker-compose.images.yml up -d     # WebUI + API on :8088

The whole integration is a submit -> poll -> fetch loop against its task API
(endpoints + request body verified against api.md, June 2026):

    POST /api/v1/app/taskapi/tasks        {type, content}  -> data.session_id
    GET  /api/v1/app/taskapi/status/{id}                   -> data.status
    GET  /api/v1/app/taskapi/result/{id}                   -> data {...}
    POST /api/v1/app/taskapi/upload   (multipart)          -> fileUrl   (MCP archives)

`type` discriminates: `model_redteam_report` (jailbreak) · `mcp_scan` · `ai_infra_scan`.
A `model_redteam_report` *runs* the datasets against a target model and scores with
`eval_model`, so the body needs both plus the dataset (these default to the local
LM Studio endpoint). The discovered prompts come back in the result; Drill re-runs
them in the cage for action ground truth (drill-spec §4.3 — "fuse the two").

When the service is absent (the common local case) `is_available()` is False and
the corpus loader silently falls back to the built-in Replay seed set.

NOTE: api.md documents the *request* shape but not the per-prompt *result* fields,
so `_attacks_from_result` stays best-effort — confirm field names against one live
scan before relying on it (the half-day the spec budgets).
"""
from __future__ import annotations

import os
import time
from typing import Optional

from .base import Attack, AttackSource

_DEFAULT_URL = "http://localhost:8088"
# AIG's built-in datasets (api.md): the Replay layer, no HF wiring needed.
_DEFAULT_DATASETS = ["JailBench-Tiny"]


class AIGAttackSource(AttackSource):
    name = "ai-infra-guard"
    layer = "replay"

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 10.0,
        target_model: Optional[str] = None,
        target_base_url: Optional[str] = None,
        eval_model: Optional[str] = None,
        eval_base_url: Optional[str] = None,
        datasets: Optional[list[str]] = None,
    ):
        self.base_url = (base_url or os.environ.get("BLASTCONTAIN_AIG_URL", _DEFAULT_URL)).rstrip("/")
        self.token = token or os.environ.get("BLASTCONTAIN_AIG_TOKEN", "")
        self.timeout = timeout
        # AIG runs the redteam against a target model + scores with eval_model;
        # default both to the local OpenAI-compatible endpoint (LM Studio).
        self.target_model = target_model or os.environ.get("BLASTCONTAIN_AIG_MODEL", "qwen3")
        self.target_base_url = target_base_url or "http://localhost:1234/v1"
        self.eval_model = eval_model or self.target_model
        self.eval_base_url = eval_base_url or self.target_base_url
        self.datasets = datasets or _DEFAULT_DATASETS

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

    def _poll(self, session_id: str, max_wait: float = 600.0) -> str:
        import httpx

        waited = 0.0
        while waited < max_wait:
            r = httpx.get(
                f"{self.base_url}/api/v1/app/taskapi/status/{session_id}",
                headers=self._headers(),
                timeout=self.timeout,
            )
            status = (r.json().get("data") or {}).get("status", "")
            if status in ("completed", "failed"):
                return status
            time.sleep(3.0)
            waited += 3.0
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

    def _redteam_body(self, datasets: list[str], num_prompts: int) -> dict:
        """A complete `model_redteam_report` content body (verified vs api.md)."""
        tok = self.token or "lm-studio"
        return {
            "model": [{"model": self.target_model, "base_url": self.target_base_url, "token": tok}],
            "eval_model": {"model": self.eval_model, "base_url": self.eval_base_url, "token": tok},
            "dataset": {"dataFile": datasets, "numPrompts": num_prompts, "randomSeed": 42},
        }

    @staticmethod
    def _attacks_from_result(result: dict) -> list[Attack]:
        """
        Best-effort mapping of AIG result prompts to Attack objects. api.md does
        not pin the per-prompt field names, so we probe the likely shapes —
        adjust once confirmed against a live scan.
        """
        attacks: list[Attack] = []
        prompts = (
            result.get("prompts")
            or result.get("cases")
            or result.get("vulnerabilities")
            or result.get("results")
            or []
        )
        for i, p in enumerate(prompts):
            if isinstance(p, dict):
                text = p.get("prompt") or p.get("input") or p.get("query") or ""
                technique = p.get("technique") or p.get("method") or "aig"
            else:
                text, technique = str(p), "aig"
            if not text:
                continue
            attacks.append(
                Attack(
                    id=f"aig-{i:04d}",
                    category="jailbreak",
                    technique=technique,
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
            body = self._redteam_body(self.datasets, limit or 50)
            session = self._submit("model_redteam_report", body)
            if not session:
                return []
            if self._poll(session) != "completed":
                return []
            return self._attacks_from_result(self._result(session))
        except Exception:
            return []
