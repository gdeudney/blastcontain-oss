"""Installed-wheel smoke test. Uses only controlled fixtures and loopback HTTP.

Run with the clean wheel environment's Python from any directory. No pytest needed.
"""

import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from blastcontain_drill.suites.catalog import builtin_catalog

CLI = [sys.executable, "-m", "blastcontain_drill.suites.cli"]


def command(*args, code=0):
    result = subprocess.run(
        [*CLI, *(str(a) for a in args)], capture_output=True, text=True, timeout=60, check=False
    )
    if result.returncode != code:
        raise AssertionError(
            f"Command {args[0]} failed: {result.returncode}\n{result.stdout}\n{result.stderr}"
        )
    return [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]


def prepare(root, target, model=None):
    spec = {
        "schema_version": 1,
        "id": root.name,
        "target": {"kind": "agent", "binding": target},
        "environment": "builtin.environment.fixture",
        "evaluators": ["builtin.evaluator.heuristic"],
        "selections": [{"id": "poisoning", "source": "mcp-poisoning", "scenarios": ["*"]}],
    }
    if model:
        spec["models"] = [model]
    root.mkdir()
    suite, plan, decisions, lock = (
        root / n for n in ("suite.json", "plan.json", "decisions.json", "lock.json")
    )
    suite.write_text(json.dumps(spec), encoding="utf-8")
    command("plan", suite, "--output", plan)
    digest = json.loads(plan.read_text(encoding="utf-8"))["content_digest"]
    command(
        "accept",
        plan,
        "--expected-digest",
        digest,
        "--reviewer",
        "release-fixture",
        "--reason",
        "Synthetic package validation only",
        "--output",
        decisions,
    )
    command("plan", suite, "--acceptances", decisions, "--lock", lock)
    return decisions, lock


def main():
    assert sum(len(s.scenarios) for s in builtin_catalog().sources) == 501
    with tempfile.TemporaryDirectory(prefix="drill-release-") as temporary:
        root = Path(temporary)
        keys = root / "keys"
        command("keygen", keys)
        decisions, lock = prepare(root / "resistant", "builtin.target.resistant")
        created, _ = command(
            "run",
            lock,
            "--acceptances",
            decisions,
            "--run-root",
            root / "runs",
            "--signing-key",
            keys / "signing-key.pem",
            "--require-signing",
        )
        directory = Path(created["directory"])
        assert command("inspect", directory)[0]["reported_security_passed"]
        verified = command(
            "verify", directory, "--lock", lock, "--trusted-key", keys / "verification-key.pub"
        )[0]
        assert verified["attested_pass"]
        assert not command("cancel", directory)[0]["requested"]
        command(
            "export-legacy",
            directory,
            "--lock",
            lock,
            "--trusted-key",
            keys / "verification-key.pub",
            "--output",
            root / "legacy.json",
        )
        rerun, _ = command(
            "rerun",
            directory,
            lock,
            "--acceptances",
            decisions,
            "--run-root",
            root / "runs",
            "--trusted-key",
            keys / "verification-key.pub",
        )
        assert rerun["run_id"] != created["run_id"]
        decisions, lock = prepare(root / "vulnerable", "builtin.target.vulnerable")
        created, _ = command(
            "run", lock, "--acceptances", decisions, "--run-root", root / "runs", code=2
        )
        result = command(
            "verify", created["directory"], "--lock", lock, "--allow-advisory", code=2
        )[0]
        assert result["replayed"] and not result["security_passed"]
        cancel_roundtrip(root)
    # Verify existing command entry points without executing a live scan.
    for module in ("cli", "diff", "plugins.cli", "suites.cli"):
        subprocess.run(
            [sys.executable, "-m", "blastcontain_drill." + module, "--help"],
            capture_output=True,
            check=True,
            timeout=15,
        )
    print(
        "Installed-wheel validation passed: 501 definitions, signed lifecycle, failing security gate, active cancellation, four CLIs."
    )


def cancel_roundtrip(root):
    started, stop = threading.Event(), threading.Event()

    class BlockingHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            started.set()
            stop.wait(30)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), BlockingHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    process = None
    try:
        decisions, lock = prepare(
            root / "cancel",
            "builtin.target.llm",
            {
                "channel": "target",
                "endpoint_url": f"http://127.0.0.1:{server.server_port}/v1",
                "model_ref": "recording-fixture",
            },
        )
        process = subprocess.Popen(
            [
                *CLI,
                "run",
                str(lock),
                "--acceptances",
                str(decisions),
                "--run-root",
                str(root / "runs"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        lines = queue.Queue()
        reader = threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True)
        reader.start()
        created = json.loads(lines.get(timeout=20))
        assert started.wait(15), "No target request received"
        directory = created["directory"]
        assert command("cancel", directory)[0]["requested"]
        output, error = process.communicate(timeout=20)
        assert process.returncode == 2, (output, error)
        summary = command("inspect", directory)[0]
        assert summary["status"] == "cancelled" and len(summary["cases"]) == 4
        result = command("verify", directory, "--lock", lock, "--allow-advisory", code=2)[0]
        assert result["replayed"] and not result["security_passed"]
    finally:
        stop.set()
        if process and process.poll() is None:
            process.kill()
            process.communicate(timeout=10)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    main()
