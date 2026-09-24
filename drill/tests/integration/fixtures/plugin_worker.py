"""Deliberately hostile container fixture. Never imported by host discovery."""

import os
from pathlib import Path
import socket
import sys
import time
import threading

from blastcontain_drill.contracts import Injection
from blastcontain_drill.plugins.protocol import encode
from blastcontain_drill.plugins.sdk import serve


class HostileFixture:
    def prepare(self, config):
        self.scenario = None

    def reset(self, scenario):
        self.scenario = scenario

    def execute(self, broker):
        mode = self.scenario.technique
        if mode == "agent-conversation":
            opened = broker.conversation("target", {"operation": "open", "branching": True})
            request = {
                "operation": "send",
                "conversation": opened["conversation"],
                "parent": opened["checkpoint"],
                "prompt": "read canary",
            }
            first = broker.conversation("target", request)
            broker.conversation(
                "target", {**request, "parent": first["checkpoint"], "prompt": "attempt deletion"}
            )
            broker.conversation("target", {**request, "prompt": "safe alternative"})
            return {"security": "held", "discarded_branch_safe": True}
        if mode.startswith("conversation"):
            opened = broker.conversation(
                "attacker",
                {
                    "operation": "open",
                    "system_message": "Controlled attacker instructions",
                    "branching": mode != "conversation-cancel",
                },
            )
            request = {
                "operation": "send",
                "conversation": opened["conversation"],
                "parent": opened["checkpoint"],
                "prompt": "first",
                "max_tokens": 128,
            }
            first = broker.conversation("attacker", request)
            broker.conversation("attacker", {**request, "prompt": "alternate"})
            broker.conversation(
                "attacker", {**request, "parent": first["checkpoint"], "prompt": "continuation"}
            )
            broker.conversation(
                "attacker", {"operation": "close", "conversation": opened["conversation"]}
            )
            return broker.call("target", Injection("user", self.scenario.entry_prompt))
        if mode == "claims-only":
            return {
                "security": "held",
                "execution": "completed",
                "effects": "independently verified",
            }
        if mode in (
            "stdout-flood",
            "stderr-sustained",
            "stdout-broker-flood",
            "stderr-broker-flood",
        ):
            fd = 2 if mode.startswith("stderr") else 1

            def flood():
                # Cross the pipe pause threshold many times, not just one frame.
                for _ in range(256):
                    os.write(fd, b"x" * 65536)
                time.sleep(60)

            if "broker" in mode:
                # Start output after the broker call has reached the host binding.
                threading.Timer(0.2, flood).start()
                return broker.call("target", Injection("user", self.scenario.entry_prompt))
            flood()
        if mode == "hang":
            time.sleep(60)
        if mode == "exit":
            sys.exit(7)
        if mode in ("oversize", "malformed", "stderr-flood", "wrong-id"):
            stream = sys.stderr.buffer if mode == "stderr-flood" else sys.stdout.buffer
            data = b"x" * 100000 + b"\n"
            if mode == "malformed":
                data = b"{not-json}\n"
            elif mode == "wrong-id":
                data = encode(
                    {"protocol": 1, "type": "result", "id": broker.request_id + 1, "result": {}}
                )
            stream.write(data)
            stream.flush()
            time.sleep(60)
        if mode == "probe":
            try:
                Path("/opt/plugin/forbidden-write").write_text("no")
                writable_root = True
            except OSError:
                writable_root = False
            try:
                with socket.create_connection(
                    ("127.0.0.1", int(self.scenario.attack_objective)), timeout=0.3
                ):
                    network = True
            except OSError:
                network = False
            status = dict(
                line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
            )
            return {
                "host_file_visible": Path(self.scenario.entry_prompt).exists(),
                "uid": os.getuid(),
                "network": network,
                "writable_root": writable_root,
                "secret": os.environ.get("BLASTCONTAIN_TEST_SECRET"),
                "caps": status["CapEff"].strip(),
                "no_new_privs": status["NoNewPrivs"].strip(),
                "seccomp": status["Seccomp"].strip(),
                "memory_limit": Path("/sys/fs/cgroup/memory.max").read_text().strip(),
                "pids_limit": Path("/sys/fs/cgroup/pids.max").read_text().strip(),
                "engine_socket": any(
                    Path(p).exists()
                    for p in [
                        "/run/podman/podman.sock",
                        "/run/user/1000/podman/podman.sock",
                        "/var/run/docker.sock",
                    ]
                ),
                "broker_result": broker.call("target", Injection("user", "controlled request")),
            }
        injection = Injection("user", self.scenario.entry_prompt)
        if mode == "unauthorized":
            return broker.call("attacker", injection)
        if mode == "budget":
            for _ in range(1000):
                broker.call("target", injection)
        if mode == "replay":
            broker.call("target", injection)
            broker.call_id -= 1
            return broker.call("target", injection)
        return {"observed": broker.call("target", injection)}

    def close(self):
        pass


serve(HostileFixture(), protocol=int(sys.argv[1]) if len(sys.argv) > 1 else 1)
