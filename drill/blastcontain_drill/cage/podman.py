"""
PodmanCage — the containment backend.

Runs the agent inside a hardened, deny-all-egress container (`--network none`,
`--cap-drop ALL`, read-only-ish, no new privileges). This is the structural
proof of containment: even if the agent is driven to exfiltrate, no packet can
leave the box. It emits the same CageObservation as InProcessCage, so the action
probes score it identically.

This release runs the deterministic stub agent in the container (no GPU needed),
proving the containment path end-to-end. Driving a served model from inside the
cage is a configuration step (allow only the model endpoint through the egress
policy) left for the deployment that has the bench.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import tempfile

from .base import Cage, CageObservation, EgressAttempt, ToolCall
from .inprocess import new_canary

_DEFAULT_IMAGE = "python:3.12-slim"


def _obs_from_json(d: dict) -> CageObservation:
    obs = CageObservation(
        canary=d.get("canary", ""),
        response_text=d.get("response_text", ""),
        steps=d.get("steps", 0),
        error=d.get("error"),
    )
    obs.tool_calls = [ToolCall(**tc) for tc in d.get("tool_calls", [])]
    obs.egress_attempts = [EgressAttempt(**e) for e in d.get("egress_attempts", [])]
    return obs


class PodmanCage(Cage):
    name = "podman"

    def __init__(
        self,
        vulnerable: bool = True,
        max_steps: int = 4,
        image: str | None = None,
        podman: str = "podman",
        timeout: float = 180.0,
    ):
        self.vulnerable = vulnerable
        self.max_steps = max_steps
        self.image = image or _DEFAULT_IMAGE
        self.podman = podman
        self.timeout = timeout

    @staticmethod
    def available(podman: str = "podman") -> bool:
        return shutil.which(podman) is not None

    def _source_dirs(self) -> tuple[str, str]:
        """Host dirs to mount so the container can import the real packages."""
        import blastcontain_core
        import blastcontain_drill

        core = os.path.dirname(os.path.dirname(os.path.abspath(blastcontain_core.__file__)))
        drill = os.path.dirname(os.path.dirname(os.path.abspath(blastcontain_drill.__file__)))
        return core, drill

    def run_attack(self, attack) -> CageObservation:
        canary = new_canary()
        core_src, drill_src = self._source_dirs()
        job_dir = tempfile.mkdtemp(prefix="bc-drill-")
        try:
            spec = {
                "attack": dataclasses.asdict(attack),
                "canary": canary,
                "vulnerable": self.vulnerable,
                "max_steps": self.max_steps,
            }
            with open(os.path.join(job_dir, "attack.json"), "w", encoding="utf-8") as f:
                json.dump(spec, f)

            cmd = [
                self.podman, "run", "--rm",
                "--network", "none",                       # deny-all egress
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "-e", "PYTHONDONTWRITEBYTECODE=1",
                "-e", "PYTHONPATH=/work/core:/work/drill",
                "-e", "BLASTCONTAIN_DRILL_JOB=/work/job/attack.json",
                "-v", f"{core_src}:/work/core:ro",
                "-v", f"{drill_src}:/work/drill:ro",
                "-v", f"{job_dir}:/work/job:ro",
                self.image,
                "python", "-m", "blastcontain_drill.cage._podman_runner",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if proc.returncode != 0:
                return CageObservation(
                    canary=canary,
                    error=f"podman exited {proc.returncode}: {proc.stderr.strip()[:400]}",
                )
            payload = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "{}"
            return _obs_from_json(json.loads(payload))
        except Exception as exc:  # noqa: BLE001
            return CageObservation(canary=canary, error=f"podman cage error: {exc}")
        finally:
            shutil.rmtree(job_dir, ignore_errors=True)
