"""
In-container entrypoint for PodmanCage.

Runs inside the deny-all-egress container: reconstructs one Attack from the
mounted job file, drives it through the *real* agent loop with the deterministic
stub agent, and prints the CageObservation as JSON on stdout. The host
(PodmanCage) reads that back. Reuses the package's own agent/toolbox code — the
container just supplies the containment (`--network none`, dropped caps).
"""
from __future__ import annotations

import json
import os
import sys


def main() -> None:
    job = os.environ.get("BLASTCONTAIN_DRILL_JOB", "/work/job/attack.json")
    with open(job, encoding="utf-8") as f:
        spec = json.load(f)

    from ..corpus.base import Attack
    from .agent import run_agent
    from .stub import StubChatClient

    attack = Attack(**spec["attack"])
    backend = StubChatClient(vulnerable=spec.get("vulnerable", True))
    obs = run_agent(
        backend,
        attack,
        canary=spec["canary"],
        max_steps=spec.get("max_steps", 4),
    )
    out = obs.as_dict()
    out["canary"] = obs.canary
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
