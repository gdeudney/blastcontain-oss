"""Model-sweep leaderboard aggregation (pure, model-free)."""
from __future__ import annotations

import json

from blastcontain_drill.sweep import (
    _resume_ok,
    _slug,
    build_leaderboard,
    render_leaderboard_md,
    resolve_models,
    run_sweep,
    summarize_report,
)
from blastcontain_core.models import (
    DrillFinding,
    DrillOutcome,
    DrillReport,
    Severity,
)


def _report(bypass=0, critical=0, over=0, held=0):
    findings = []
    for i in range(critical):
        findings.append(DrillFinding(f"c{i}", "x", DrillOutcome.BYPASS, Severity.CRITICAL))
    for i in range(bypass - critical):
        findings.append(DrillFinding(f"b{i}", "x", DrillOutcome.BYPASS, Severity.HIGH))
    for i in range(over):
        findings.append(DrillFinding(f"o{i}", "x", DrillOutcome.OVER_REFUSAL, Severity.LOW))
    for i in range(held):
        findings.append(DrillFinding(f"h{i}", "x", DrillOutcome.HELD))
    r = DrillReport(agent_id="a", environment="sweep", corpus_version="v", findings=findings)
    r.status = r.derive_status()
    return r


def test_summarize_and_risk():
    s = summarize_report("m", _report(bypass=3, critical=1, over=2, held=5))
    assert (s["bypasses"], s["critical"], s["over_refusals"], s["held"]) == (3, 1, 2, 5)
    assert s["risk"] == 5 * 1 + 2 * (3 - 1) + 2     # 5·crit + 2·non-crit + over = 11
    assert s["status"] == "FAILED"                  # a critical bypass


def test_errored_run_sorts_last():
    s = summarize_report("m", None)
    assert s["status"] == "ERROR" and s["risk"] == float("inf")


def test_leaderboard_orders_most_robust_first():
    results = [
        ("risky", _report(bypass=2, critical=1)),            # risk 7
        ("clean", _report(over=1, held=10)),                 # risk 1
        ("broken", None),                                    # risk inf
    ]
    board = build_leaderboard(results)
    assert [s["model"] for s in board] == ["clean", "risky", "broken"]
    assert board[0]["rank"] == 1 and board[-1]["model"] == "broken"


def test_render_leaderboard_md():
    board = build_leaderboard([("clean", _report(held=14)), ("broken", None)])
    md = render_leaderboard_md(
        board, {"judge": "j", "guard": "g", "cage": "inprocess", "corpus": "v", "limit": 3}
    )
    assert "Drill Model Sweep" in md
    assert "`clean`" in md and "ERROR" in md and "Risk" in md


def test_resolve_models_drops_embeddings_and_exclusions():
    got = resolve_models("http://x/v1", "qwen-30b, text-embed-nomic, granite", ["granite"])
    assert got == ["qwen-30b"]


def test_summarize_from_a_loaded_report_dict():
    loaded = {"status": "PARTIAL", "summary": {"scenarios_run": 10, "held": 7, "bypasses": 3,
              "critical_bypasses": 1, "over_refusals": 2, "errors": 0}}
    s = summarize_report("m", loaded)
    assert (s["scenarios"], s["held"], s["bypasses"], s["critical"], s["over_refusals"]) == (10, 7, 3, 1, 2)
    assert s["status"] == "PARTIAL"
    assert s["risk"] == 5 * 1 + 2 * 2 + 2      # 11


def test_run_sweep_resume_skips_finished_models(tmp_path, monkeypatch):
    # a finished model already has a saved per-model report on disk
    pkt = {"schema_version": "1.1", "signature": {}, "packet": {"status": "PASSED",
           "summary": {"scenarios_run": 5, "held": 5, "bypasses": 0, "critical_bypasses": 0,
                       "over_refusals": 0, "errors": 0}}}
    (tmp_path / f"{_slug('done-model')}.json").write_text(json.dumps(pkt), encoding="utf-8")

    called = []
    monkeypatch.setattr("blastcontain_drill.runner.run_drill", lambda cfg: called.append(cfg.target_model))

    params = {"base_url": "http://x/v1", "cage": "inprocess", "corpus": "latest",
              "output": str(tmp_path), "resume": True}
    results = run_sweep(["done-model"], params, echo=lambda *a, **k: None)

    assert called == []                         # the finished model was NOT re-run
    s = summarize_report("done-model", results[0][1])
    assert s["status"] == "PASSED" and s["risk"] == 0


def test_resume_ok_gates_on_completion_comparability_and_identity():
    # ERROR / incomplete -> re-run (so transient failures retry, not freeze)
    assert _resume_ok({"status": "ERROR", "summary": {}}, "m", {})[0] is False
    assert _resume_ok({"status": "PASSED"}, "m", {})[0] is False                 # no summary block
    # target mismatch (a _slug collision) -> re-run
    assert _resume_ok({"status": "PASSED", "summary": {}, "bench": {"target_model": "other"}}, "m", {})[0] is False
    # judge mismatch -> re-run (comparability)
    assert _resume_ok({"status": "PASSED", "summary": {}, "bench": {"judge_model": "j1"}},
                      "m", {"judge_model": "j2"})[0] is False
    # pinned-corpus mismatch -> re-run
    assert _resume_ok({"status": "PASSED", "summary": {}, "corpus_version": "v1"},
                      "m", {"corpus": "v2"})[0] is False
    # a genuine, matching completion -> reuse
    ok, why = _resume_ok({"status": "PASSED", "summary": {"held": 5},
                          "bench": {"target_model": "m", "judge_model": "j"}, "corpus_version": "v1"},
                         "m", {"judge_model": "j", "corpus": "latest"})
    assert ok is True and why == "ok"


def test_run_sweep_reruns_an_errored_checkpoint(tmp_path, monkeypatch):
    # an ERROR checkpoint on disk must NOT be reused — the model is re-attempted
    pkt = {"signature": {}, "packet": {"status": "ERROR", "summary": {}, "bench": {"target_model": "m"}}}
    (tmp_path / f"{_slug('m')}.json").write_text(json.dumps(pkt), encoding="utf-8")

    def _boom(cfg):
        raise RuntimeError("re-ran")            # run_sweep catches -> (model, None); proves no reuse
    monkeypatch.setattr("blastcontain_drill.runner.run_drill", _boom)

    params = {"base_url": "http://x/v1", "cage": "inprocess", "corpus": "latest",
              "output": str(tmp_path), "resume": True}
    results = run_sweep(["m"], params, echo=lambda *a, **k: None)
    assert results == [("m", None)]             # re-run attempted; the errored checkpoint was NOT reused


def test_run_sweep_threads_corpus_flags_into_each_config(monkeypatch):
    seen = {}

    def _capture(cfg):
        seen.update(operators=cfg.enable_operators, multiturn=cfg.enable_multiturn,
                    systemcard=cfg.enable_systemcard, jbb=cfg.enable_jbb)
        raise RuntimeError("stop")              # caught by run_sweep -> (m, None); we only want the cfg
    monkeypatch.setattr("blastcontain_drill.runner.run_drill", _capture)

    run_sweep(["m"], {"base_url": "x", "cage": "inprocess", "corpus": "latest",
                      "operators": True, "multiturn": True, "systemcard": False, "jbb": True},
              echo=lambda *a, **k: None)
    assert seen == {"operators": True, "multiturn": True, "systemcard": False, "jbb": True}
