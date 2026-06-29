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

try:
    # The Microsoft Agent Governance Toolkit, if the team has it installed.
    import agent_governance_toolkit  # noqa: F401
    AGT_AVAILABLE = True
except Exception:
    AGT_AVAILABLE = False


AVAILABILITY_FLAGS: dict[str, bool] = {
    "otel": OTEL_AVAILABLE,
    "agt": AGT_AVAILABLE,
}
