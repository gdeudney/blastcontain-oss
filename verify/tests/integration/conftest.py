"""
Integration test fixtures for blastcontain-verify.

Manages:
  - Compose service lifecycle (mcp-server, api-server)
  - run_verify() helper: builds podman/docker run command, returns parsed audit.json
  - Helper assertions: failed_checks(), passed_checks(), skipped_checks()

Environment variables:
  COMPOSE_CMD     Override compose command  (default: auto-detected)
  CONTAINER_CMD   Override container runtime (default: auto-detected)
  VERIFY_IMAGE    Override verify image tag  (default: blastcontain-verify:0.1.0)
  SKIP_COMPOSE    Set to "1" to skip service startup (if already running)
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Paths and constants
# ---------------------------------------------------------------------------

INTEGRATION_DIR = Path(__file__).parent
FIXTURES_DIR = INTEGRATION_DIR / "fixtures"
COMPOSE_FILE = INTEGRATION_DIR / "compose.yml"

VERIFY_IMAGE = os.environ.get("VERIFY_IMAGE", "blastcontain-verify:0.1.0")
TESTNET = "blastcontain-testnet"


# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------

def _container_cmd() -> str:
    override = os.environ.get("CONTAINER_CMD")
    if override:
        return override
    return "podman" if shutil.which("podman") else "docker"


def _compose_cmd() -> list[str]:
    override = os.environ.get("COMPOSE_CMD")
    if override:
        return override.split()
    if shutil.which("podman"):
        return ["podman", "compose"]
    return ["docker", "compose"]


# ---------------------------------------------------------------------------
# Path helpers (Windows/MSYS2 compatibility)
# ---------------------------------------------------------------------------

def _vol_src(path: Path) -> str:
    """
    Convert a path to a volume source string suitable for -v flag.
    On Windows, convert backslashes to forward slashes.
    """
    return str(path).replace("\\", "/")


def _container_arg(path: str) -> str:
    """
    Add an extra leading slash on Windows so MSYS2/Git Bash does not
    translate  /reports/audit.json  →  C:/Program Files/Git/reports/audit.json.
    Already double-slashed paths are returned unchanged.
    """
    if sys.platform == "win32" and path.startswith("/") and not path.startswith("//"):
        return "/" + path
    return path


# ---------------------------------------------------------------------------
# Service health helpers
# ---------------------------------------------------------------------------

def _wait_for_url(url: str, timeout: int = 60) -> None:
    """Poll url until HTTP 200 or timeout."""
    deadline = time.time() + timeout
    last_exc: Optional[Exception] = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return
        except Exception as exc:
            last_exc = exc
            time.sleep(2)
    raise TimeoutError(
        f"Service at {url} did not become ready within {timeout}s. "
        f"Last error: {last_exc}"
    )


# ---------------------------------------------------------------------------
# Session fixture: compose services
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def compose_services():
    """Start MCP and API test servers for the session."""
    if os.environ.get("SKIP_COMPOSE") == "1":
        yield
        return

    compose = _compose_cmd()
    subprocess.run(
        [*compose, "-f", str(COMPOSE_FILE), "up", "-d", "--build"],
        check=True,
    )

    # Wait for both services to be healthy
    _wait_for_url("http://localhost:18080/health", timeout=90)
    _wait_for_url("http://localhost:18081/health", timeout=90)

    yield

    subprocess.run(
        [*compose, "-f", str(COMPOSE_FILE), "down", "--volumes"],
        check=False,
    )


# ---------------------------------------------------------------------------
# run_verify fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def run_verify(tmp_path):
    """
    Returns a callable that runs blastcontain-verify in a container and
    returns a result dict:

        {
            "exit_code":  int,
            "audit":      dict,   # parsed audit.json (or {} on failure)
            "stdout":     str,
            "stderr":     str,
        }

    Parameters
    ----------
    fixture : str
        "dirty" or "clean" — which fixture directory to mount at /scan
    extra_args : list[str]
        Additional CLI flags passed to blastcontain-verify, e.g.
        ["--context-file", "//scan/context.txt"]
    extra_env : dict[str, str]
        Additional environment variables injected into the container.
    network : bool
        If True, join blastcontain-testnet instead of --network none.
        Required for MCP-01 (Cisco scanner), ENV-02 FAIL, NET-01 FAIL.
    as_root : bool
        If True, omit --user flag (run as root) — for PRIV-01 FAIL tests.
    no_read_only : bool
        If True, omit --read-only — for DISK-02 FAIL and PERM-01 FAIL tests.
    extra_caps : list[str]
        Additional capabilities to grant, e.g. ["SYS_ADMIN"] — for CAP-01 FAIL.
    writable_model_dir : bool
        If True, create a writable /models volume with a weights.bin file
        (no attestation). Used for ENV-03 FAIL.
    """

    def _run(
        fixture: str = "dirty",
        extra_args: Optional[list[str]] = None,
        extra_env: Optional[dict[str, str]] = None,
        network: bool = False,
        as_root: bool = False,
        no_read_only: bool = False,
        extra_caps: Optional[list[str]] = None,
        writable_model_dir: bool = False,
    ) -> dict:
        scan_dir = FIXTURES_DIR / fixture
        audit_file = tmp_path / "audit.json"

        container = _container_cmd()
        args: list[str] = [container, "run", "--rm"]

        # User
        #
        # The hardened image sets `USER verify` (uid 10001) by default, so merely
        # *omitting* --user does NOT run the container as root — the image default
        # wins and PRIV-01/DISK-01/DISK-02 never fire. To genuinely run as root we
        # must override the image USER explicitly.
        if as_root:
            args += ["--user", "0:0"]
        else:
            args += ["--user", "10001:10001"]

        # Filesystem
        if not no_read_only:
            args += ["--read-only"]
        args += ["--cap-drop", "ALL"]
        for cap in (extra_caps or []):
            args += ["--cap-add", cap]
        args += ["--security-opt", "no-new-privileges"]
        args += ["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"]

        # Network
        if network:
            args += ["--network", TESTNET]
        else:
            args += ["--network", "none"]

        # Volume: scan fixtures (read-only)
        args += ["-v", f"{_vol_src(scan_dir)}:/scan:ro,z"]

        # Volume: reports output (writable). Make the host dir world-writable so
        # the container's non-root scan UID (10001) can create audit.json. In
        # CI's rootless podman the host tmp_path is owned by the runner UID and
        # mode-restricted, so uid 10001 otherwise cannot write there — and the
        # scan crashes on the audit-packet write (OSError). No-op on Windows,
        # which lacks POSIX modes.
        try:
            os.chmod(tmp_path, 0o777)
        except OSError:
            pass
        args += ["-v", f"{_vol_src(tmp_path)}:/reports:rw,z"]

        # Writable model dir for ENV-03 FAIL
        if writable_model_dir:
            model_tmp = tmp_path / "writable-models"
            model_tmp.mkdir(exist_ok=True)
            try:
                os.chmod(model_tmp, 0o777)  # writable by uid 10001 (see /reports note)
            except OSError:
                pass
            (model_tmp / "weights.bin").write_bytes(b"\x00" * 64)
            args += ["-v", f"{_vol_src(model_tmp)}:/models:rw,z"]

        # Extra environment variables
        for k, v in (extra_env or {}).items():
            args += ["-e", f"{k}={v}"]

        # Image
        args += [VERIFY_IMAGE]

        # blastcontain-verify CLI args
        verify_args = [
            "--agent-id", "test-agent",
            "--env", "staging",
            "--search-path", "//scan",
            "--output", "//reports/audit.json",
            "--acknowledge-risk",
        ]
        if writable_model_dir:
            verify_args += ["--model-dir", "//models"]

        verify_args += list(extra_args or [])
        args += verify_args

        result = subprocess.run(args, capture_output=True, text=True)

        audit: dict = {}
        if audit_file.exists():
            try:
                audit = json.loads(audit_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass

        return {
            "exit_code": result.returncode,
            "audit":     audit,
            "stdout":    result.stdout,
            "stderr":    result.stderr,
        }

    return _run


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def _packet(result: dict) -> dict:
    return result.get("audit", {}).get("packet", {})


def failed_checks(result: dict) -> set[str]:
    """Check IDs that produced findings (FAIL)."""
    return {f["check_id"] for f in _packet(result).get("findings", [])}


def passed_checks(result: dict) -> set[str]:
    """Check IDs that passed."""
    return set(_packet(result).get("passed", []))


def skipped_checks(result: dict) -> set[str]:
    """Check IDs that were skipped."""
    return {s["check_id"] for s in _packet(result).get("skipped", [])}


def status(result: dict) -> str:
    """Overall scan status string: APPROVED / REJECTED / QUARANTINED."""
    return _packet(result).get("status", "")


def augmentation(result: dict) -> dict:
    """Augmentation availability flags recorded in the packet (presidio, cisco_mcp,
    cisco_skill, agt). Lets tests adapt to whether an optional scanner is installed
    in the image under test — e.g. the Cisco scanners are opt-in (not in [full])."""
    return _packet(result).get("augmentation", {})


def findings_for(result: dict, check_id: str) -> list[dict]:
    """Return all findings for a specific check ID."""
    return [f for f in _packet(result).get("findings", []) if f["check_id"] == check_id]
