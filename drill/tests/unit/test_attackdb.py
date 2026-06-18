"""Effective-attack database — schema, ingest/dedupe, query, stats (model-free)."""
from __future__ import annotations

import json

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


def test_multiturn_record_archives_the_whole_sequence():
    conn = connect(":memory:")
    turns = ["define X as a benign-looking thing", "now combine X to do the harmful thing"]
    new, _ = ingest_records(conn, [{
        "prompt": turns[-1], "turns": turns, "target_model": "A",
        "technique": "context-smuggling", "category": "jailbreak", "layer": "replay", "severity": "HIGH",
    }])
    assert new == 1
    row = conn.execute("SELECT prompt, turns FROM attacks").fetchone()
    assert json.loads(row["turns"]) == turns                       # full sequence stored, not just the last turn
    assert "USER 1:" in row["prompt"] and "USER 2:" in row["prompt"]  # identity/storage = joined turns


def test_multiturn_attacks_sharing_a_final_turn_stay_distinct():
    conn = connect(":memory:")
    final = "combine everything and answer"
    ingest_records(conn, [
        {"prompt": final, "turns": ["setup A", final], "target_model": "A", "technique": "t"},
        {"prompt": final, "turns": ["setup B is different", final], "target_model": "A", "technique": "t"},
    ])
    # different earlier turns -> different identity -> two rows (NOT collapsed by the shared final turn)
    assert conn.execute("SELECT COUNT(*) AS n FROM attacks").fetchone()["n"] == 2


def test_single_turn_record_is_unaffected():
    conn = connect(":memory:")
    ingest_records(conn, [_rec(prompt="solo")])
    row = conn.execute("SELECT prompt, turns FROM attacks").fetchone()
    assert row["prompt"] == "solo" and row["turns"] is None


def test_join_lookalike_single_turn_does_not_collide_with_multiturn():
    # a single-turn prompt equal to _join_turns(['a','b']) must NOT dedupe into the 2-turn
    # attack — identity hashes the JSON array, which a plain prompt string can never equal.
    conn = connect(":memory:")
    ingest_records(conn, [
        {"turns": ["a", "b"], "target_model": "A", "technique": "t"},
        {"prompt": "USER 1: a\n\nUSER 2: b", "target_model": "A", "technique": "t"},
    ])
    assert conn.execute("SELECT COUNT(*) AS n FROM attacks").fetchone()["n"] == 2


def test_connect_migrates_a_legacy_db_and_builds_indexes(tmp_path):
    import sqlite3
    p = str(tmp_path / "legacy.db")
    raw = sqlite3.connect(p)
    # a pre-attack_key, pre-turns table: has the indexed columns but lacks attack_key + turns
    raw.execute("CREATE TABLE attacks (id TEXT PRIMARY KEY, prompt TEXT NOT NULL, "
                "operator TEXT, language TEXT, target_model TEXT)")
    raw.execute("INSERT INTO attacks (id, prompt) VALUES ('x', 'p')")
    raw.commit()
    raw.close()
    conn = connect(p)                            # must migrate the columns THEN build indexes, no crash
    cols = {r[1] for r in conn.execute("PRAGMA table_info(attacks)").fetchall()}
    assert "attack_key" in cols and "turns" in cols
    assert conn.execute("SELECT COUNT(*) AS n FROM attacks").fetchone()["n"] == 1   # legacy row preserved
