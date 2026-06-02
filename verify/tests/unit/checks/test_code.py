"""Tests for blastcontain_verify.checks.code."""
from __future__ import annotations

from blastcontain_verify.checks.code import check_code01_dangerous_patterns
from blastcontain_verify.models import Severity


class TestCode01DangerousPatterns:
    def test_clean_code_passes(self, tmp_path):
        (tmp_path / "agent.py").write_text(
            "import json\n\ndef process(data):\n    return json.loads(data)\n"
        )
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "PASS"

    def test_eval_is_critical(self, tmp_path):
        (tmp_path / "agent.py").write_text("result = eval(user_input)\n")
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "FAIL"
        assert findings[0].severity == Severity.CRITICAL

    def test_exec_is_critical(self, tmp_path):
        (tmp_path / "agent.py").write_text("exec(compiled_code)\n")
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "FAIL"
        assert findings[0].severity == Severity.CRITICAL

    def test_shell_true_is_critical(self, tmp_path):
        (tmp_path / "agent.py").write_text(
            "import subprocess\nsubprocess.run(cmd, shell=True)\n"
        )
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "FAIL"

    def test_pickle_loads_is_high(self, tmp_path):
        (tmp_path / "agent.py").write_text("import pickle\ndata = pickle.loads(raw)\n")
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "FAIL"
        # Could be CRITICAL (if other patterns match) or HIGH
        assert findings[0].severity in (Severity.CRITICAL, Severity.HIGH)

    def test_yaml_safe_load_passes(self, tmp_path):
        (tmp_path / "agent.py").write_text(
            "import yaml\ndata = yaml.safe_load(content)\n"
        )
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "PASS"

    def test_skips_venv_directory(self, tmp_path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "dangerous.py").write_text("eval(x)\n")
        # Root dir has clean code
        (tmp_path / "agent.py").write_text("print('hello')\n")
        findings, status = check_code01_dangerous_patterns(str(tmp_path))
        assert status == "PASS"
