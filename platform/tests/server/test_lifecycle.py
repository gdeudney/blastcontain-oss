"""The agent lifecycle state machine (charter-spec §7)."""
from __future__ import annotations

import pytest
from blastcontain.charter.lifecycle import LifecycleError, transition

NOW = "2026-06-11T12:00:00Z"


def _t(op, state, **kwargs):
    return transition(op, state, "bot", "prod", actor="alice", at=NOW, **kwargs)


def test_register_draft_to_active():
    op = _t("register", "draft")
    assert (op.from_state, op.to_state) == ("draft", "active")


def test_pause_resume_round_trip():
    paused = _t("pause", "active", params={"mode": "drain"})
    assert paused.to_state == "paused"
    assert paused.params["mode"] == "drain"
    resumed = _t("resume", "paused")
    assert resumed.to_state == "active"


def test_pause_validates_mode():
    with pytest.raises(LifecycleError, match="pause mode"):
        _t("pause", "active", params={"mode": "yeet"})


def test_cannot_resume_a_quarantined_agent():
    # Quarantine exits only via recertification (§7.4).
    with pytest.raises(LifecycleError, match="cannot resume"):
        _t("resume", "quarantined")


def test_quarantine_requires_finding_type():
    with pytest.raises(LifecycleError, match="finding_type"):
        _t("quarantine", "active")
    op = _t("quarantine", "active", params={"finding_type": "blastcontain.env.x"})
    assert op.to_state == "quarantined"


def test_recertify_only_from_quarantined():
    assert _t("recertify", "quarantined").to_state == "active"
    with pytest.raises(LifecycleError):
        _t("recertify", "active")


def test_kill_is_break_glass_and_lands_in_paused():
    op = _t("kill", "active")
    assert op.to_state == "paused"
    assert op.params["break_glass"] is True


def test_decommission_archive_recommission():
    assert _t("decommission", "active").to_state == "decommissioned"
    assert _t("archive", "decommissioned").to_state == "archived"
    assert _t("recommission", "archived").to_state == "draft"


def test_decommissioned_is_not_silently_reactivatable():
    for op in ("register", "pause", "resume"):
        with pytest.raises(LifecycleError):
            _t(op, "decommissioned")


def test_state_preserving_operations():
    op = _t("transfer_owner", "active", params={"owner": "bob"})
    assert op.from_state == op.to_state == "active"


def test_unknown_operation():
    with pytest.raises(LifecycleError, match="unknown"):
        _t("explode", "active")
