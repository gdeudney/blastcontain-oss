"""
BlastContain Verify — optional dependency management.

All third-party augmentation libraries are imported here with try/except.
The rest of the codebase checks availability flags; it never imports
augmentation packages directly.
"""
from __future__ import annotations

# ── Presidio ──────────────────────────────────────────────────────────────────
# Presidio availability is split into two flags:
#   PRESIDIO_INSTALLED — the package imports cleanly
#   PRESIDIO_AVAILABLE — the AnalyzerEngine has been successfully constructed
#                       (requires the spaCy model). Determined lazily on first
#                       call to presidio_analyze() to avoid the multi-second
#                       model load on every invocation, including runs that
#                       never touch MEM-01.
# Optional dependencies are imported defensively. We catch SystemExit as well
# as Exception: these are heavy, unpinned ML libraries, and a bad version can
# abort its own import (e.g. sys.exit() on a failed model/native-lib probe) —
# which must downgrade the augmentation to "unavailable", never crash Verify.
try:
    from presidio_analyzer import AnalyzerEngine as _AnalyzerEngine  # type: ignore
    PRESIDIO_INSTALLED = True
except (Exception, SystemExit):
    _AnalyzerEngine = None  # type: ignore
    PRESIDIO_INSTALLED = False

# Optimistic default: if the package is installed, advertise availability and
# only flip to False if the lazy init fails. This keeps the augmentation banner
# accurate before MEM-01 has been invoked.
PRESIDIO_AVAILABLE: bool = PRESIDIO_INSTALLED
_presidio_engine = None  # populated on first analyze() call
_presidio_init_attempted = False


def _ensure_presidio_engine():
    """Lazily construct the AnalyzerEngine on first use."""
    global _presidio_engine, _presidio_init_attempted, PRESIDIO_AVAILABLE
    if _presidio_engine is not None or _presidio_init_attempted:
        return _presidio_engine
    _presidio_init_attempted = True
    if not PRESIDIO_INSTALLED or _AnalyzerEngine is None:
        PRESIDIO_AVAILABLE = False
        return None
    try:
        _presidio_engine = _AnalyzerEngine()
        PRESIDIO_AVAILABLE = True
    except (Exception, SystemExit):
        _presidio_engine = None
        PRESIDIO_AVAILABLE = False
    return _presidio_engine


def presidio_analyze(text: str, language: str = "en") -> list:
    """Run Presidio NER analysis. Returns empty list if not available."""
    engine = _ensure_presidio_engine()
    if engine is None:
        return []
    try:
        return engine.analyze(text=text, language=language)
    except (Exception, SystemExit):
        return []



# ── Cisco MCP Scanner ─────────────────────────────────────────────────────────
try:
    from mcpscanner import Config as _McpConfig, Scanner as _McpScanner  # type: ignore
    from mcpscanner.core.models import AnalyzerEnum  # type: ignore  # noqa: F401
    CISCO_MCP_AVAILABLE = True
    _mcp_config_cls = _McpConfig
    _mcp_scanner_cls = _McpScanner
except (Exception, SystemExit):
    CISCO_MCP_AVAILABLE = False
    AnalyzerEnum = None       # type: ignore
    _mcp_config_cls = None
    _mcp_scanner_cls = None


def get_mcp_scanner(api_key: str = ""):
    """Return a configured Cisco MCP Scanner instance, or None if unavailable."""
    if not CISCO_MCP_AVAILABLE:
        return None
    config = _mcp_config_cls(api_key=api_key)
    return _mcp_scanner_cls(config)


# ── Cisco Skill Scanner ───────────────────────────────────────────────────────
try:
    from skill_scanner import SkillScanner as _SkillScanner  # type: ignore
    CISCO_SKILL_AVAILABLE = True
    _skill_scanner_cls = _SkillScanner
except (Exception, SystemExit):
    CISCO_SKILL_AVAILABLE = False
    _skill_scanner_cls = None


def get_skill_scanner():
    """Return a Cisco SkillScanner instance, or None if unavailable."""
    if not CISCO_SKILL_AVAILABLE:
        return None
    return _skill_scanner_cls()


# ── AGT ───────────────────────────────────────────────────────────────────────
try:
    from agent_compliance import PromptDefenseEvaluator, SupplyChainGuard  # type: ignore  # noqa: F401
    AGT_AVAILABLE = True
except (Exception, SystemExit):
    AGT_AVAILABLE = False
    PromptDefenseEvaluator = None # type: ignore
    SupplyChainGuard = None       # type: ignore


# ── Summary flags ──────────────────────────────────────────────────────────────
AUGMENTATION_FLAGS: dict[str, bool] = {
    "presidio":    PRESIDIO_AVAILABLE,
    "cisco_mcp":   CISCO_MCP_AVAILABLE,
    "cisco_skill": CISCO_SKILL_AVAILABLE,
    "agt":         AGT_AVAILABLE,
}
