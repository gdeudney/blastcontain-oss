"""Exercise the installed Cisco scanner contract against inert skill fixtures."""
from importlib.util import find_spec
from pathlib import Path

import pytest

from blastcontain_verify.checks.skills import check_skill02_cisco_scan


pytestmark = pytest.mark.skipif(
    find_spec("skill_scanner") is None,
    reason="optional Cisco Skill Scanner is not installed",
)
FIXTURES = Path(__file__).resolve().parents[2] / "integration" / "fixtures"


@pytest.mark.parametrize("fixture, expected", [("clean", "PASS"), ("dirty", "FAIL")])
def test_installed_cisco_scanner(fixture, expected):
    findings, status, reason = check_skill02_cisco_scan(str(FIXTURES / fixture / "skills"))
    # An installed but incompatible scanner must not silently degrade to SKIP.
    assert status == expected, reason
    if expected == "FAIL":
        assert any(f.check_id == "SKILL-02" for f in findings)
    else:
        assert findings == []
