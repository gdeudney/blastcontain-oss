"""Seen-ledger dedupe round-trip."""
from __future__ import annotations

import os

from blastcontain_scout.arxiv import Paper
from blastcontain_scout.ledger import Ledger


def _p(pid):
    return Paper(arxiv_id=pid, title="t", summary="s", published="", updated="")


def test_missing_ledger_loads_empty(tmp_path):
    led = Ledger.load(str(tmp_path / "nope.json"))
    assert led.seen == {}


def test_mark_filter_and_persist(tmp_path):
    path = str(tmp_path / "state" / "seen.json")
    led = Ledger.load(path)
    papers = [_p("2401.1"), _p("2401.2")]

    assert led.filter_new(papers, "2026-06-02") == papers   # all new
    assert led.mark(papers, "2026-06-02") == 2
    assert led.mark(papers, "2026-06-02") == 0              # idempotent
    led.save()
    assert os.path.exists(path)

    reloaded = Ledger.load(path)
    assert reloaded.is_new("2401.1") is False
    assert reloaded.filter_new([_p("2401.1"), _p("2403.9")], "2026-06-02") == [_p("2403.9")]
