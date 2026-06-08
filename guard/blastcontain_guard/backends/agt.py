"""
blastcontain_guard.backends.agt — the optional out-of-process AGT front (§8).

The Microsoft Agent Governance Toolkit is the deeper, tamper-resistant line behind
native: kernel isolation, the MCP gateway, the trust mesh. The same Charter
compiles to Guard rules *and* AGT ``governance.toolkit/v1``, so the two agree by
construction.

This backend is configured, not coded: point it at an AGT decision ``endpoint``
and it consults AGT over HTTP per call (the real out-of-process PolicyEvaluator);
tests and embedders may inject an ``evaluator_fn`` instead. Two modes:

  * **dual** (default) — AGT *backs* native; ``backends.combine`` takes the
    stricter of the two verdicts (AGT can only tighten).
  * **sole** — AGT is the *only* decider; native is pass-through. This is the
    "thin shim to AGT's PolicyEvaluator" config (§8).

Availability: with an endpoint set, the backend is optimistically available and
the per-call HTTP attempt is the real probe — if AGT is unreachable, ``evaluate``
raises ``AgtUnavailable`` and ``backends.combine`` **fails closed**.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..augmentation import AGT_AVAILABLE
from ..models import Action, Decision, EvalInput
from ..policy import Ruleset

AgtEvaluatorFn = Callable[[Ruleset, EvalInput], Decision]

_AGT_ACTION = {
    "allow": Action.ALLOW,
    "deny": Action.DENY,
    "require_approval": Action.ASK,
    "ask": Action.ASK,
}


class AgtUnavailable(Exception):
    """Raised when the AGT backend cannot serve a decision."""


def decision_from_agt_response(data: dict) -> Decision:
    """Map an AGT decision response (``{action, reason, rule, approvers}``) to a Decision."""
    action = _AGT_ACTION.get(str(data.get("action", "deny")).lower(), Action.DENY)
    return Decision(
        action,
        str(data.get("reason", "AGT decision")),
        rule=data.get("rule"),
        approvers=list(data.get("approvers", []) or []),
    )


class AgtBackend:
    name = "agt"

    def __init__(
        self,
        enabled: bool = True,
        reachable: bool = False,
        degrade_to_native: bool = False,
        sole: bool = False,
        evaluator_fn: Optional[AgtEvaluatorFn] = None,
        endpoint: Optional[str] = None,
        token: Optional[str] = None,
        timeout: float = 5.0,
    ):
        self.enabled = enabled
        self.degrade_to_native = degrade_to_native
        self.sole = sole
        self.endpoint = endpoint
        self.installed = AGT_AVAILABLE
        self._reachable = reachable
        self._evaluator_fn = evaluator_fn
        self._token = token
        self._timeout = timeout

    def available(self) -> bool:
        """True if a usable AGT evaluator is present (an endpoint is optimistic)."""
        if self.endpoint is not None:
            return True
        if self._evaluator_fn is not None:
            return self._reachable
        return self.installed and self._reachable

    def evaluate(self, ruleset: Ruleset, inp: EvalInput) -> Decision:
        if not self.available():
            raise AgtUnavailable("AGT backend not available")
        if self._evaluator_fn is not None:
            return self._evaluator_fn(ruleset, inp)
        if self.endpoint:
            return self._http_evaluate(inp)
        raise AgtUnavailable(
            "live AGT integration needs an endpoint or evaluator_fn (guard-spec §8)"
        )

    def _http_evaluate(self, inp: EvalInput) -> Decision:
        try:
            import httpx

            body = {
                "tool_name": inp.tool_name,
                "action_type": inp.action_type,
                "args": inp.args,
                "agent_id": inp.agent_id,
                "identity": inp.identity,
            }
            headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
            resp = httpx.post(self.endpoint, json=body, headers=headers, timeout=self._timeout)
        except Exception as exc:  # connection refused, DNS, timeout, ...
            raise AgtUnavailable(f"AGT endpoint {self.endpoint} unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise AgtUnavailable(f"AGT endpoint {self.endpoint} -> HTTP {resp.status_code}")
        return decision_from_agt_response(resp.json())
