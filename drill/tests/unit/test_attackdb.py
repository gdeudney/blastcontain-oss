"""Effective-attack database — schema, ingest/dedupe, query, stats (model-free)."""
from __future__ import annotations

from blastcontain_drill.attackdb import (
    connect,
    coverage,
    ingest_records,
    make_id,
    matrix,
    parse_operator,
    query,
    stats,
)


def _rec(prompt="p", target="qwen3.6-27b", technique="jbb/harm/morse", severity="HIGH",
         category="jailbreak", layer="operators"):
    return {
        "prompt": prompt, "target_model": target, "technique": technique,
        "severity": severity, "category": category, "layer": layer,
        "attacker_model": "heretic", "evidence": "ev",
    }


def test_parse_operator_and_language():
    assert parse_operator("jbb/harm/morse") == ("morse", "en")
    assert parse_operator("seed/multilingual") == ("multilingual", "fr")
    assert parse_operator("x/language:sw") == (None, "sw")
    assert parse_operator("jbb/harm/base64/language:zu") == ("base64", "zu")
    assert parse_operator("generative") == (None, "en")


def test_make_id_keys_on_prompt_and_target():
    assert make_id("p", "a") == make_id("p", "a")
    assert make_id("p", "a") != make_id("p", "b")     # same prompt, different target


def test_ingest_dedupes_and_bumps_hit_count():
    conn = connect(":memory:")
    new, seen = ingest_records(conn, [_rec(), _rec()])  # same prompt+target twice
    assert new == 1 and seen == 1
    row = conn.execute("SELECT hit_count, operator, language FROM attacks").fetchone()
    assert row["hit_count"] == 2
    assert row["operator"] == "morse" and row["language"] == "en"


def test_query_filters_by_operator_language_and_severity():
    conn = connect(":memory:")
    ingest_records(conn, [
        _rec(prompt="m1", technique="jbb/harm/morse", severity="HIGH"),
        _rec(prompt="b1", technique="jbb/harm/base64", severity="CRITICAL"),
        _rec(prompt="x1", technique="x/language:sw", severity="LOW"),
    ])
    assert len(query(conn, operator="morse")) == 1
    assert len(query(conn, language="sw")) == 1
    assert len(query(conn, min_severity="HIGH")) == 2   # HIGH + CRITICAL, not LOW
    assert len(query(conn, model="qwen3.6")) == 3       # target substring match


def test_stats_breaks_down_by_operator_and_target():
    conn = connect(":memory:")
    ingest_records(conn, [
        _rec(prompt="m1", technique="jbb/harm/morse"),
        _rec(prompt="m2", technique="jbb/harm/morse"),
        _rec(prompt="b1", technique="jbb/harm/base64"),
    ])
    s = stats(conn)
    assert s["total"] == 3
    assert dict(s["by_operator"])["morse"] == 2
    assert dict(s["by_target"])["qwen3.6-27b"] == 3


def test_attack_key_groups_same_prompt_across_models():
    # The SAME attack against two models = two rows (one per target), one attack identity.
    conn = connect(":memory:")
    ingest_records(conn, [_rec(prompt="same", target="A"), _rec(prompt="same", target="B")])
    keys = {r["attack_key"] for r in conn.execute("SELECT attack_key FROM attacks").fetchall()}
    assert len(keys) == 1
    assert conn.execute("SELECT COUNT(*) AS n FROM attacks").fetchone()["n"] == 2


def test_matrix_operator_by_target():
    conn = connect(":memory:")
    ingest_records(conn, [
        _rec(prompt="m1", target="A", technique="x/morse"),
        _rec(prompt="m2", target="A", technique="x/morse"),
        _rec(prompt="m3", target="B", technique="x/morse"),   # morse works on B too
        _rec(prompt="b1", target="A", technique="x/base64"),  # base64 only seen on A
    ])
    m = matrix(conn, "operator")
    assert m["morse"] == {"A": 2, "B": 1}
    assert m["base64"] == {"A": 1}


def test_coverage_lists_models_per_attack():
    conn = connect(":memory:")
    ingest_records(conn, [
        _rec(prompt="same", target="A", technique="x/morse", severity="HIGH"),
        _rec(prompt="same", target="B", technique="x/morse", severity="CRITICAL"),
        _rec(prompt="other", target="A", technique="x/base64"),
    ])
    cov = coverage(conn, operator="morse")
    assert len(cov) == 1                         # one distinct morse attack
    assert dict(cov[0]["models"]) == {"A": "HIGH", "B": "CRITICAL"}
