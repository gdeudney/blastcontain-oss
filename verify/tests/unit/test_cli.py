"""CLI robustness — status-emoji output must never crash the scan.

The results table and summary print status glyphs (✅ ❌ ⏭ ⚠️). On Windows a
non-UTF-8 stdout (redirect to a file, a pipe, or a legacy cp1252 console) cannot
encode them, so ``click.echo`` raised ``UnicodeEncodeError`` mid-run — and, since
the table prints before the audit packet is written, the packet was silently
lost. ``cli._force_utf8_output`` reconfigures the streams to UTF-8 to prevent it.
"""
from __future__ import annotations

import io
import os
import subprocess
import sys

import pytest

from blastcontain_verify.cli import _force_utf8_output


def test_status_emoji_are_unencodable_in_cp1252():
    """Documents the root cause: the glyphs genuinely can't map to cp1252."""
    with pytest.raises(UnicodeEncodeError):
        "⏭".encode("cp1252")


def test_force_utf8_output_makes_legacy_stream_emoji_safe():
    """A cp1252 stdout/stderr is switched to UTF-8 so the emoji write cleanly."""
    saved_out, saved_err = sys.stdout, sys.stderr
    try:
        sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        sys.stderr = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        assert sys.stdout.encoding.lower() == "cp1252"

        _force_utf8_output()

        assert sys.stdout.encoding.lower() == "utf-8"
        assert sys.stderr.encoding.lower() == "utf-8"
        sys.stdout.write("✅❌⏭⚠️")  # must not raise
        sys.stdout.flush()
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err


def test_force_utf8_output_is_a_noop_without_reconfigure():
    """Streams that don't support reconfigure (e.g. plain buffers) are left alone."""
    saved_out, saved_err = sys.stdout, sys.stderr
    try:
        sys.stdout = io.StringIO()  # no .reconfigure
        sys.stderr = io.StringIO()
        _force_utf8_output()  # must not raise
        sys.stdout.write("✅")  # StringIO holds any str fine
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err


def test_cli_survives_legacy_stdout_and_writes_packet(tmp_path):
    """End-to-end regression: the CLI completes (exit 0) and writes the audit
    packet even when stdout uses a codec that can't encode the status emoji."""
    target = tmp_path / "target"
    target.mkdir()
    out = tmp_path / "audit.json"

    # PYTHONIOENCODING forces the child's stdout to a legacy codec, reproducing
    # the Windows cp1252 / redirected-output case on any platform.
    env = {**os.environ, "PYTHONIOENCODING": "cp1252"}
    proc = subprocess.run(
        [
            sys.executable, "-c", "from blastcontain_verify.cli import main; main()",
            "--agent-id", "enc-test", "--env", "dev",
            "--search-path", str(target), "--output", str(out),
            "--acknowledge-risk",
        ],
        env=env,
        capture_output=True,
        timeout=120,
    )

    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")[-2000:]
    assert out.exists(), "audit packet was not written under a legacy stdout encoding"
