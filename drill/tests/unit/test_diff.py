"""drill diff — regression delta between two signed DrillReports (robustness #4)."""
from __future__ import annotations

import json

from click.testing import CliRunner

from blastcontain_drill.diff import (
    diff_reports,
    load_report,
    main,
    render_markdown,
    should_fail,
)


def _finding(sid, outcome, severity=None, technique="t"):
    return {"scenario_id": sid, "scenario_name": sid, "outcome": outcome,
            "severity": severity, "technique": technique}


def _report(findings, **meta):
    base = {
        "agent_id": "a", "status": "PARTIAL", "corpus_version": "v1",
        "bench": {"target_model": "m"},
        "summary": {"bypasses": 0, "critical_bypasses": 0},
        "findings": findings,
    }
    base.update(meta)
    return base


def test_classifies_regression_fix_severity_and_other():
    a = _report([
        _finding("s1", "HELD"),
        _finding("s2", "BYPASS", "HIGH"),
        _finding("s3", "BYPASS", "HIGH"),
        _finding("s4", "HELD"),
    ])
    b = _report([
        _finding("s1", "BYPASS", "CRITICAL"),   # regression (held -> bypass)
        _finding("s2", "HELD"),                  # fix (bypass -> held)
        _finding("s3", "BYPASS", "CRITICAL"),    # severity escalation (bypass both)
        _finding("s4", "OVER_REFUSAL"),          # other change (neither bypass)
    ])
    d = diff_reports(a, b)
    assert [r["scenario_id"] for r in d["regressions"]] == ["s1"]
    assert [r["scenario_id"] for r in d["fixes"]] == ["s2"]
    assert [r["scenario_id"] for r in d["severity_changes"]] == ["s3"]
    assert [r["scenario_id"] for r in d["other_changes"]] == ["s4"]


def test_added_and_removed_scenarios():
    a = _report([_finding("s1", "HELD"), _finding("old", "BYPASS", "HIGH")])
    b = _report([_finding("s1", "HELD"), _finding("new", "BYPASS", "HIGH"), _finding("new2", "HELD")])
    d = diff_reports(a, b)
    assert {r["scenario_id"] for r in d["added"]} == {"new", "new2"}
    assert {r["scenario_id"] for r in d["removed"]} == {"old"}
    assert [r["scenario_id"] for r in d["added_bypassing"]] == ["new"]


def test_no_diff_when_identical():
    d = diff_reports(_report([_finding("s1", "HELD"), _finding("s2", "BYPASS", "HIGH")]),
                     _report([_finding("s1", "HELD"), _finding("s2", "BYPASS", "HIGH")]))
    assert not any(d["counts"].values())
    assert "_No differences._" in render_markdown(d)


def test_gate_policies():
    d = diff_reports(_report([_finding("s1", "HELD")]),
                     _report([_finding("s1", "BYPASS", "HIGH")]))
    assert should_fail(d, "regression") is True            # shared scenario flipped to bypass

    d2 = diff_reports(_report([_finding("s1", "HELD")]),
                      _report([_finding("s1", "HELD"), _finding("added", "BYPASS", "HIGH")]))
    assert should_fail(d2, "regression") is False          # only a NEW scenario bypassed
    assert should_fail(d2, "any-bypass") is True
    assert should_fail(d2, "none") is False


def test_load_report_unwraps_signed_envelope_or_bare(tmp_path):
    bare = _report([_finding("s1", "HELD")])
    env = {"schema_version": "1.1", "packet": bare, "signature": {"sig": "x"}}
    pe = tmp_path / "env.json"
    pe.write_text(json.dumps(env), encoding="utf-8")
    pb = tmp_path / "bare.json"
    pb.write_text(json.dumps(bare), encoding="utf-8")
    assert load_report(str(pe))["findings"][0]["scenario_id"] == "s1"
    assert load_report(str(pb))["agent_id"] == "a"


def test_cli_exit_codes(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps(_report([_finding("s1", "HELD")])), encoding="utf-8")
    b.write_text(json.dumps(_report([_finding("s1", "BYPASS", "CRITICAL")])), encoding="utf-8")
    runner = CliRunner()
    regressed = runner.invoke(main, [str(a), str(b)])
    assert regressed.exit_code == 1 and "Regressions" in regressed.output
    clean = runner.invoke(main, [str(a), str(a)])
    assert clean.exit_code == 0
    bad = runner.invoke(main, ["nope.json", "nope2.json"])
    assert bad.exit_code == 2


def test_bypass_to_error_is_not_a_fix_but_a_real_defence_is():
    a = _report([_finding("s1", "BYPASS", "HIGH")])
    # bypass -> ERROR is inconclusive (the run crashed) — it must NOT count as a green fix
    d = diff_reports(a, _report([_finding("s1", "ERROR")]))
    assert d["counts"]["fixes"] == 0
    assert [r["scenario_id"] for r in d["other_changes"]] == ["s1"]
    # a genuine defence outcome still counts as a fix
    assert diff_reports(a, _report([_finding("s1", "HELD")]))["counts"]["fixes"] == 1
    assert diff_reports(a, _report([_finding("s1", "OVER_REFUSAL")]))["counts"]["fixes"] == 1


def test_malformed_findings_do_not_crash():
    # non-dict entries, non-string outcome/severity, and mixed-type ids must not raise
    a = {"findings": [{"scenario_id": "s1", "outcome": "BYPASS", "severity": "HIGH"},
                      {"scenario_id": "s2", "outcome": "HELD"}, "junk", 7]}
    b = {"findings": [{"scenario_id": "s1", "outcome": "BYPASS", "severity": 9},   # non-str severity
                      {"scenario_id": "s2", "outcome": 5},                          # non-str outcome
                      {"scenario_id": 9, "outcome": "HELD"}]}                       # int id (mixed sort)
    d = diff_reports(a, b)
    assert d["counts"]["added"] == 1            # id 9 only in b; junk entries skipped, no crash


def test_cli_exit_2_on_nondict_null_and_write_failure(tmp_path):
    runner = CliRunner()
    nul = tmp_path / "null.json"
    nul.write_text("null", encoding="utf-8")
    lst = tmp_path / "list.json"
    lst.write_text("[1, 2, 3]", encoding="utf-8")
    assert runner.invoke(main, [str(nul), str(lst)]).exit_code == 2   # non-dict reports -> read error

    good = tmp_path / "good.json"
    good.write_text(json.dumps(_report([_finding("s1", "HELD")])), encoding="utf-8")
    bad_out = str(tmp_path / "no-such-dir" / "out.json")
    res = runner.invoke(main, [str(good), str(good), "--json", bad_out])
    assert res.exit_code == 2                                          # write failure != regression
