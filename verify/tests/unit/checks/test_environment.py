"""Tests for blastcontain_verify.checks.environment."""
from __future__ import annotations

import sys
import pytest

from blastcontain_verify.checks.environment import (
    check_env02_egress_restriction,
    check_env03_model_weights_writable,
)
from blastcontain_verify.models import Severity


class TestEnv02EgressRestriction:
    def test_returns_finding_or_pass(self):
        # We can't control network in tests, just verify it doesn't crash
        findings, status = check_env02_egress_restriction()
        assert status in ("PASS", "FAIL")
        if status == "FAIL":
            assert findings[0].check_id == "ENV-02"
            assert findings[0].severity == Severity.HIGH


class TestEnv03ModelWeightsWritable:
    def test_skip_when_dir_missing(self):
        findings, status = check_env03_model_weights_writable("/nonexistent/path/models")
        assert status == "SKIP"

    def test_skip_when_no_model_dir(self):
        findings, status = check_env03_model_weights_writable("")
        assert status == "SKIP"

    def test_writable_dir_is_critical(self, tmp_path):
        findings, status = check_env03_model_weights_writable(str(tmp_path))
        assert status == "FAIL"
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].check_id == "ENV-03"

    def test_readonly_dir_passes(self, tmp_path):
        if sys.platform == "win32":
            pytest.skip("Read-only directory test not reliable on Windows")
        import stat
        tmp_path.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            findings, status = check_env03_model_weights_writable(str(tmp_path))
            assert status == "PASS"
        finally:
            tmp_path.chmod(stat.S_IRWXU)
