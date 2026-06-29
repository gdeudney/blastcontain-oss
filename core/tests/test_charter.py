"""Unit tests for blastcontain_core.charter."""
from __future__ import annotations

import pytest

from blastcontain_core.charter import (
    CharterSchema,
    DelegationRules,
    EnvironmentConstraints,
    HitlConfig,
    RemediationProof,
    charter_from_mapping,
    load_charter,
)

MINIMAL = {
    "agent_id": "invoice-bot",
    "environment": "prod",
    "version": "1.0.0",
    "trust_tier": 1,
}


def test_from_mapping_minimal():
    charter = charter_from_mapping(dict(MINIMAL))
    assert charter.agent_id == "invoice-bot"
    assert charter.environment == "prod"
    assert charter.draft is False
    assert isinstance(charter.environment_constraints, EnvironmentConstraints)


def test_from_mapping_builds_nested_dataclasses():
    raw = dict(
        MINIMAL,
        environment_constraints={"egress_blocked": False, "max_trust_tier": 2},
        delegation_rules={"max_chain_depth": 1, "allowed_tiers": [0, 1]},
        hitl_config={"required_for": ["destructive_apis"], "timeout_sec": 60},
        remediation_proofs=[{"finding_type": "blastcontain.env.x", "evidence_uri": "pr://1"}],
    )
    charter = charter_from_mapping(raw)
    assert isinstance(charter.environment_constraints, EnvironmentConstraints)
    assert charter.environment_constraints.egress_blocked is False
    assert isinstance(charter.delegation_rules, DelegationRules)
    assert charter.delegation_rules.max_chain_depth == 1
    assert isinstance(charter.hitl_config, HitlConfig)
    assert charter.hitl_config.required_for == ["destructive_apis"]
    assert isinstance(charter.remediation_proofs[0], RemediationProof)


def test_from_mapping_strict_rejects_unknown_keys():
    raw = dict(MINIMAL, permited_tools=["typo"])
    with pytest.raises(ValueError, match="permited_tools"):
        charter_from_mapping(raw, strict=True)


def test_from_mapping_lenient_ignores_platform_fields():
    # A Platform Charter packet carries Intent-layer / lifecycle fields the
    # control-layer schema doesn't model; lenient mode must tolerate them.
    raw = dict(
        MINIMAL,
        autonomy_mode="interactive",
        objectives=[{"id": "no-pii-egress"}],
        state="active",
        compiled_policy={"apiVersion": "governance.toolkit/v1"},
        permitted_tools=["query_db"],
    )
    charter = charter_from_mapping(raw, strict=False)
    assert charter.permitted_tools == ["query_db"]
    assert not hasattr(charter, "compiled_policy")


def test_from_mapping_missing_required_field_raises_value_error():
    with pytest.raises(ValueError, match="CharterSchema"):
        charter_from_mapping({"agent_id": "x"})


def test_from_mapping_non_mapping_raises():
    with pytest.raises(ValueError, match="not a mapping"):
        charter_from_mapping(["not", "a", "dict"])  # type: ignore[arg-type]


def test_load_charter_round_trip(tmp_path):
    path = tmp_path / "charter.yaml"
    path.write_text(
        "agent_id: invoice-bot\n"
        "environment: staging\n"
        "version: 1.0.0\n"
        "trust_tier: 1\n"
        "permitted_tools: [query_db, send_notification]\n",
        encoding="utf-8",
    )
    charter = load_charter(str(path))
    assert isinstance(charter, CharterSchema)
    assert charter.permitted_tools == ["query_db", "send_notification"]


def test_load_charter_strict_on_typos(tmp_path):
    path = tmp_path / "charter.yaml"
    path.write_text(
        "agent_id: bot\nenvironment: prod\nversion: '1'\ntrust_tier: 0\nbogus_field: 1\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="bogus_field"):
        load_charter(str(path))
