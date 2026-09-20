"""Run with the clean wheel installation Python, passing the wheel directory.

Use python -I so the repository cannot satisfy product imports accidentally.
This check includes controlled localhost MCP fixtures, with no model calls.
"""

import importlib.resources as resources
import json
from pathlib import Path
import subprocess
import sys
from zipfile import ZipFile

from blastcontain_drill.contracts import ScenarioSpec, EvidenceEvent, ContractError
from blastcontain_drill.contracts.legacy import LegacySourceAdapter, attack_from_scenario
from blastcontain_drill.corpus import (
    BuiltinReplaySource,
    JailbreakBenchSource,
    MultiTurnSource,
    OperatorsSource,
    SystemCardSource,
    MCPPoisoningSource,
)
from blastcontain_drill.cage import InProcessCage, StubChatClient
from blastcontain_drill.corpus.base import Corpus
from blastcontain_drill.runner import run_corpus
from blastcontain_drill.scoring import HeuristicContentScorer

wheels = list(Path(sys.argv[1]).glob("blastcontain_*.whl"))
assert len(wheels) == 3, "Expected exactly one Core, Drill and Scout wheel"
for wheel in wheels:
    with ZipFile(wheel) as archive:
        names = archive.namelist()
        assert any(n.endswith("/licenses/LICENSE") for n in names), wheel
        assert any(n.endswith("/licenses/NOTICE") for n in names), wheel
        assert not any("/contrib/" in n for n in names), wheel
        if "drill-" in wheel.name:
            for name in [
                "contracts/wire.py",
                "corpus/arxiv/registry.json",
                "corpus/data/jbb/harmful-behaviors.csv",
                "corpus/data/jbb/benign-behaviors.csv",
                "corpus/data/jbb/SOURCE.md",
            ]:
                assert "blastcontain_drill/" + name in names
    print("Wheel data and notices OK:", wheel.name)

count = 0
for source in [
    BuiltinReplaySource(),
    JailbreakBenchSource(),
    MultiTurnSource(),
    OperatorsSource(),
    SystemCardSource(),
    MCPPoisoningSource(),
]:
    scenarios = LegacySourceAdapter(source).scenarios()
    for scenario in scenarios:
        restored = ScenarioSpec.from_dict(json.loads(json.dumps(scenario.to_dict())))
        assert attack_from_scenario(restored).id == scenario.id
    count += len(scenarios)
assert count == 501
print("Installed attack round trips:", count)

# Distinguish the final strict JSON implementation from the earlier prototype.
try:
    EvidenceEvent("test", 0, "started", "runtime", "runtime", {"bad": {1: "key"}})
except ContractError:
    pass
else:
    raise AssertionError("Nested JSON keys were coerced")

registry = resources.files("blastcontain_drill").joinpath("corpus/arxiv/registry.json")
assert json.loads(registry.read_text())["schema_version"] == 1
for command in [
    "blastcontain-drill",
    "blastcontain-drill-diff",
    "blastcontain-scout",
    "blastcontain-scout-track",
]:
    result = subprocess.run(
        [str(Path(sys.executable).parent / command), "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Usage:" in result.stdout
    print("Installed entry point OK:", command)

findings = run_corpus(
    InProcessCage(StubChatClient(True)),
    Corpus("packaging", MCPPoisoningSource().dataset()),
    [HeuristicContentScorer()],
)
assert len(findings) == 4 and all(f.outcome.value == "BYPASS" for f in findings)
print("Installed MCP controlled scenarios:", len(findings), "expected BYPASS with containment")
