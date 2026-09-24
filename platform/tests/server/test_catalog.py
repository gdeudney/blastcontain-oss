"""The objective catalog (charter-spec §4) — shape and defaults."""
from __future__ import annotations

from blastcontain.charter.catalog import CATALOG, defaults_for

VALID_ACTIONS = {"allow", "deny", "require_approval"}


def test_catalog_keys_match_ids():
    for obj_id, entry in CATALOG.items():
        assert entry.id == obj_id


def test_every_entry_has_risk_and_evidence():
    for entry in CATALOG.values():
        assert entry.risk, entry.id
        assert entry.proven_by, entry.id
        assert entry.kind in ("rule", "constraint", "runtime"), entry.id


def test_rule_templates_use_valid_actions():
    for entry in CATALOG.values():
        for rule in entry.rules:
            assert rule.interactive in VALID_ACTIONS
            assert rule.autonomous in VALID_ACTIONS


def test_autonomous_is_never_looser_than_interactive():
    order = {"deny": 0, "require_approval": 1, "allow": 2}
    for entry in CATALOG.values():
        for rule in entry.rules:
            assert order[rule.autonomous] <= order[rule.interactive], entry.id


def test_strictness_defaults_nest():
    locked = set(defaults_for("locked"))
    balanced = set(defaults_for("balanced"))
    permissive = set(defaults_for("permissive"))
    assert permissive <= balanced <= locked
    assert "approved-tools-only" in permissive          # the floor (tenet 3)
    assert "no-pii-egress" in balanced                  # roadmap P3 interactive set


def test_conditional_objectives_are_not_defaults():
    # model-weights attestation is gated behind the self-hosted param (§4 ⑤)
    entry = CATALOG["model-weights-attested"]
    assert entry.requires_param == "self_hosted"
    assert not entry.default_in
