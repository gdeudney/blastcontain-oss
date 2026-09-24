"""Optional AGT imports must detect the real module without breaking native Guard."""
import builtins
from pathlib import Path
import runpy
from types import ModuleType

import pytest


@pytest.mark.parametrize("failure", [None, ModuleNotFoundError, RuntimeError, SystemExit])
def test_agt_probe_uses_distribution_import_and_contains_failures(monkeypatch, failure):
    original = builtins.__import__
    seen = []

    def importing(name, *args, **kwargs):
        if name == "agent_governance_toolkit":
            pytest.fail("The distribution name is not its Python import name")
        if name == "agent_compliance":
            seen.append(name)
            if failure is not None:
                raise failure("controlled optional dependency failure")
            return ModuleType(name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", importing)
    namespace = runpy.run_path(str(
        Path(__file__).resolve().parents[2] / "blastcontain_guard" / "augmentation.py"
    ))
    assert seen == ["agent_compliance"]
    assert namespace["AGT_AVAILABLE"] is (failure is None)
    assert namespace["AVAILABILITY_FLAGS"]["agt"] is (failure is None)
