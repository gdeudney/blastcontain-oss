"""Verify installed AgentDojo source/data against the reviewed release commit."""

import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path


def verify():
    record = json.loads(Path(__file__).with_name("upstream.json").read_text())
    if importlib.metadata.version("agentdojo") != record["version"]:
        raise ValueError("Unexpected AgentDojo version")
    root = Path(importlib.util.find_spec("agentdojo").origin).parent
    for relative, expected in record["files"].items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError("AgentDojo source/data differs from reviewed release: " + relative)
    print("Verified AgentDojo release source/data: " + str(len(record["files"])) + " files")


if __name__ == "__main__":
    verify()
