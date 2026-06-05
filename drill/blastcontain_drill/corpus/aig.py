"""
AI-Infra-Guard attack-source adapter (drill-spec §4.3) — availability-flagged.

AI-Infra-Guard (Tencent, Apache-2.0) runs as a service, not a pip dependency.
Stand it up (no auth — keep it on localhost only):

    git clone https://github.com/Tencent/AI-Infra-Guard && cd AI-Infra-Guard
    docker compose -f docker-compose.images.yml up -d     # WebUI + API on :8088
    # No Docker (Podman-only box)? podman-compose -f docker-compose.images.yml up -d

The whole integration is a submit -> poll -> fetch loop against its task API
(endpoints + request body verified against api.md, June 2026):

    POST /api/v1/app/taskapi/tasks        {type, content}  -> data.session_id
    GET  /api/v1/app/taskapi/status/{id}                   -> data.status
    GET  /api/v1/app/taskapi/result/{id}                   -> data {...}
    POST /api/v1/app/taskapi/upload   (multipart)          -> fileUrl   (MCP archives)

`type` discriminates: `model_redteam_report` (jailbreak) · `mcp_scan` · `ai_infra_scan`.
A `model_redteam_report` *runs* the datasets against a target model and scores with
`eval_model`, so the body needs both plus the dataset (the model URL defaults to the
container->host gateway — see the agent-networking note below). The discovered prompts
come back in the result; Drill re-runs them in the cage for action ground truth
(drill-spec §4.3 — "fuse the two").

When the service is absent (the common local case) `is_available()` is False and
the corpus loader silently falls back to the built-in Replay seed set.

NOTE: api.md documents the *request* shape but not the per-prompt *result* fields —
those are served at runtime at http://localhost:8088/docs/index.html. So
`_attacks_from_result` probes the likely container keys + field names (unit-fixtured);
confirm them against one live scan before relying on it (the half-day the spec budgets).

NOTE (agent networking): AIG executes the redteam in a privileged **agent** container
(separate from the :8088 webserver), and *that container* makes the model calls — so the
model `base_url` must be reachable FROM THE AGENT'S CONTAINER, not from the host. It
defaults to the container->host gateway `http://host.containers.internal:1234/v1`
(override with BLASTCONTAIN_AIG_MODEL_URL), the host model server must bind 0.0.0.0
(`lms server start --bind 0.0.0.0`), and the host firewall must allow inbound on that
port (Windows: `New-NetFirewallRule -DisplayName LMStudio -Direction Inbound
-LocalPort 1234 -Protocol TCP -Action Allow`). This is a *different* address than where
Drill's own cage reaches the model (the host's localhost) — only the model *name* is
shared. Confirmed live (2026-06): with no route to the model, a scan goes
status `doing` -> `error` with an empty result.
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
        # AIG runs the redteam against a target model + scores with eval_model. The model
        # URL must be reachable from AIG's *agent container*, so it defaults to the
        # container->host gateway (NOT Drill's localhost) — override via
        # BLASTCONTAIN_AIG_MODEL_URL. Only the model *name* is shared with Drill.
        self.target_model = target_model or os.environ.get("BLASTCONTAIN_AIG_MODEL", "qwen3")
        self.target_base_url = (
            target_base_url
            or os.environ.get("BLASTCONTAIN_AIG_MODEL_URL")
            or "http://host.containers.internal:1234/v1"
        )
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

    # Status values confirmed against the live service (2026-06): "doing" = running,
    # "error" = terminal failure; success is "completed"/"done". Treat anything not
    # clearly running as terminal, else an errored scan polls until max_wait.
    _RUNNING_STATES = ("doing", "running", "pending", "queued", "processing", "")

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
            if status not in self._RUNNING_STATES:
                return status                 # terminal: completed / done / error / failed / …
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
        Map an AIG redteam result to Attack objects. api.md pins the *request* but
        not the per-prompt *result* fields (served at :8088/docs at runtime), so we
        probe the likely container keys + field names and recurse one level. The unit
        fixtures pin the current mapping; confirm against one live scan.
        """
        # Locate the list of per-prompt cases — AIG nests it differently by task/version.
        case_keys = ("prompts", "cases", "results", "vulnerabilities", "items", "details")
        cases: list = []
        for key in case_keys:                             # top-level list
            v = result.get(key)
            if isinstance(v, list) and v:
                cases = v
                break
        if not cases:                                     # one level under any wrapper (report/data/…)
            for v in result.values():
                if not isinstance(v, dict):
                    continue
                for k2 in case_keys:
                    if isinstance(v.get(k2), list) and v[k2]:
                        cases = v[k2]
                        break
                if cases:
                    break

        attacks: list[Attack] = []
        for i, p in enumerate(cases):
            if isinstance(p, dict):
                text = (
                    p.get("prompt") or p.get("input") or p.get("query")
                    or p.get("attack") or p.get("question") or p.get("content") or ""
                )
                technique = str(
                    p.get("technique") or p.get("method") or p.get("type")
                    or p.get("category") or "aig"
                )[:48]
                jb = p.get("success", p.get("jailbreak", p.get("is_jailbreak", p.get("passed"))))
                if jb is True or str(jb).strip().lower() in ("true", "yes", "1", "success"):
                    technique = f"{technique}+jailbroke"   # high-signal: it broke the eval target
            else:
                text, technique = str(p), "aig"
            text = (text or "").strip()
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
            status = self._poll(session)
            if status == "timeout" or "error" in status.lower() or "fail" in status.lower():
                return []                     # accept completed/done/success; reject error/fail
            return self._attacks_from_result(self._result(session))
        except Exception:
            return []
