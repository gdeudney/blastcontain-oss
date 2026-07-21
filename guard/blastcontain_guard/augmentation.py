"""
blastcontain_guard.augmentation — optional-dependency availability flags.

The platform's house pattern (used by Verify and Drill): probe optional
integrations at import time, never hard-require them, and let the rest of the
code branch on a flag. Guard's two optional integrations are OpenTelemetry (an
export backend for decisions) and AGT (the optional out-of-process enforcement
backend). Neither is needed for the open, standalone wedge — Guard + a local
YAML works with nothing else installed.
"""
from __future__ import annotations

try:
    import opentelemetry  # noqa: F401
    OTEL_AVAILABLE = True
except Exception:
    OTEL_AVAILABLE = False

# SystemExit is caught alongside Exception (the Verify precedent): a bad
# version can abort its own import, which must downgrade the augmentation to
# "unavailable", never crash Guard.
try:
    # The Microsoft Agent Governance Toolkit, if the team has it installed.
    # PyPI dist: agent-governance-toolkit>=4.1 (the `[agt]` extra); the import
    # name is `agent_compliance` (verified against the 4.1.0 wheel — Verify
    # pins the same dist). The pre-rename dist agentmesh-platform (imports as
    # `agentmesh`, frozen at 3.7.0) is not supported.
    import agent_compliance  # type: ignore  # noqa: F401
    AGT_AVAILABLE = True
except (Exception, SystemExit):
    AGT_AVAILABLE = False


AVAILABILITY_FLAGS: dict[str, bool] = {
    "otel": OTEL_AVAILABLE,
    "agt": AGT_AVAILABLE,
}
