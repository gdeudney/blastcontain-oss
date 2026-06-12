"""Model-sweep leaderboard aggregation (pure, model-free)."""
from __future__ import annotations

from blastcontain_drill.sweep import (
    build_leaderboard,
    render_leaderboard_md,
    resolve_models,
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
