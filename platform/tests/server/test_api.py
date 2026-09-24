"""The platform API — authoring, signing, serving, lifecycle, ledger."""
from __future__ import annotations

from blastcontain_core.signing import verify_packet


def _sign(client, charter_body, env="prod", actor="alice@example.com"):
    assert client.post("/v1/charters", json=charter_body).status_code == 201
    response = client.post(
        f"/v1/charters/{charter_body['agent_id']}/sign?env={env}", json={"actor": actor}
    )
    assert response.status_code == 200, response.text
    return response.json()


# ── authoring + signing ──────────────────────────────────────────────────────────


def test_create_draft(client, charter_body):
    response = client.post("/v1/charters", json=charter_body)
    assert response.status_code == 201
    body = response.json()
    assert body["state"] == "draft"
    assert body["charter_id"] == "invoice-bot:prod"


def test_create_rejects_malformed(client):
    assert client.post("/v1/charters", json={"agent_id": "x"}).status_code == 400
    assert client.post(
        "/v1/charters",
        json={"agent_id": "x", "environment": "prod", "version": "1", "trust_tier": 0,
              "autonomy_mode": "yolo"},
    ).status_code == 400


def test_sign_issues_verifiable_bundle(client, charter_body):
    signed = _sign(client, charter_body)
    assert signed["state"] == "active"
    assert signed["advisory_signature"] is False
    bundle = signed["bundle"]
    assert verify_packet(bundle) is True
    packet = bundle["packet"]
    assert packet["state"] == "active"
    assert packet["draft"] is False
    assert packet["compiled_policy"]["apiVersion"] == "governance.toolkit/v1"
    assert packet["signed_by"] == "did:key:local-platform"


def test_sign_without_draft_404(client):
    assert client.post("/v1/charters/nobody/sign", json={"actor": "a"}).status_code == 404


def test_sign_blocks_on_unknown_objective(client, charter_body):
    charter_body["objectives"].append({"id": "not-a-real-concern"})
    client.post("/v1/charters", json=charter_body)
    response = client.post("/v1/charters/invoice-bot/sign?env=prod", json={"actor": "a"})
    assert response.status_code == 409
    assert "not-a-real-concern" in str(response.json())


def test_get_charter_serves_signed_bundle(client, charter_body):
    _sign(client, charter_body)
    response = client.get("/v1/charters/invoice-bot?env=prod")
    assert response.status_code == 200
    assert verify_packet(response.json()) is True


def test_get_charter_404(client):
    assert client.get("/v1/charters/ghost?env=prod").status_code == 404


def test_policy_endpoint_yaml(client, charter_body):
    _sign(client, charter_body)
    response = client.get("/v1/charters/invoice-bot/policy?env=prod&fmt=yaml")
    assert response.status_code == 200
    assert "governance.toolkit/v1" in response.text
    assert "allow-permitted-tools" in response.text


def test_diff_surfaces_capability_creep(client, charter_body):
    _sign(client, charter_body)
    charter_body["version"] = "2.0.0"
    charter_body["permitted_tools"].append("delete_invoice")
    _sign(client, charter_body)
    response = client.get(
        "/v1/charters/invoice-bot/diff?env=prod&from_version=1.0.0&to_version=2.0.0"
    )
    assert response.status_code == 200
    diff = response.json()
    assert diff["permitted_tools"]["added"] == ["delete_invoice"]
    assert diff["capability_creep"] is True


# ── standards + exceptions ───────────────────────────────────────────────────────


def test_mandatory_standard_is_inherited(client, charter_body):
    client.post("/v1/standards", json={
        "id": "org-baseline", "name": "Org baseline", "version": "1",
        "objectives": [{"id": "no-dangerous-code-exec", "enforcement_level": "mandatory"}],
    })
    signed = _sign(client, charter_body)
    rules = signed["bundle"]["packet"]["compiled_policy"]["rules"]
    exec_rules = [r for r in rules if r["concern"] == "no-dangerous-code-exec"]
    assert exec_rules and exec_rules[0]["action"] == "deny"
    objectives = signed["bundle"]["packet"]["objectives"]
    inherited = [o for o in objectives if o["id"] == "no-dangerous-code-exec"]
    assert inherited[0]["inherited_from"] == "org-baseline"


def test_owner_cannot_approve_own_exception(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/charters/invoice-bot/exceptions?env=prod", json={
        "objective_id": "no-pii-egress", "justification": "I said so",
        "granted_by": "alice@example.com", "expires_at": "2027-01-01T00:00:00Z",
    })
    assert response.status_code == 403


def test_exception_lifts_mandatory_on_next_sign(client, charter_body):
    client.post("/v1/standards", json={
        "id": "org-baseline", "name": "x", "version": "1",
        "objectives": [{"id": "block-exfiltration", "enforcement_level": "mandatory"}],
    })
    # the control layer has egress open -> mandatory constraint mismatch blocks signing
    client.post("/v1/charters", json=charter_body)
    blocked = client.post("/v1/charters/invoice-bot/sign?env=prod", json={"actor": "alice"})
    assert blocked.status_code == 409

    granted = client.post("/v1/charters/invoice-bot/exceptions?env=prod", json={
        "objective_id": "block-exfiltration", "justification": "migration window",
        "granted_by": "ciso@example.com", "expires_at": "2027-01-01T00:00:00Z",
    })
    assert granted.status_code == 201

    client.post("/v1/charters", json=charter_body)
    signed = client.post("/v1/charters/invoice-bot/sign?env=prod", json={"actor": "alice"})
    assert signed.status_code == 200


# ── lifecycle ────────────────────────────────────────────────────────────────────


def test_pause_restamps_served_state(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/pause?env=prod",
                           json={"actor": "ops", "mode": "deny-all"})
    assert response.status_code == 200
    assert response.json()["state"] == "paused"

    bundle = client.get("/v1/charters/invoice-bot?env=prod").json()
    assert bundle["packet"]["state"] == "paused"
    assert verify_packet(bundle) is True      # the re-stamped envelope still verifies

    client.post("/v1/agents/invoice-bot/resume?env=prod", json={"actor": "ops"})
    assert client.get("/v1/charters/invoice-bot?env=prod").json()["packet"]["state"] == "active"


def test_lifecycle_rejects_invalid_transitions(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/resume?env=prod", json={"actor": "ops"})
    assert response.status_code == 409


def test_operations_log_records_actor_and_reason(client, charter_body):
    _sign(client, charter_body)
    client.post("/v1/agents/invoice-bot/pause?env=prod",
                json={"actor": "ops", "reason": "maintenance", "mode": "drain"})
    ops = client.get("/v1/agents/invoice-bot/operations").json()["operations"]
    assert [o["op"] for o in ops] == ["register", "pause"]
    assert ops[1]["actor"] == "ops"
    assert ops[1]["reason"] == "maintenance"
    assert ops[1]["params"]["mode"] == "drain"


def test_owner_transfer(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/owner?env=prod",
                           json={"actor": "admin", "owner": "bob@example.com"})
    assert response.status_code == 200
    bundle = client.get("/v1/charters/invoice-bot?env=prod").json()
    assert bundle["packet"]["owner"] == "bob@example.com"
    assert verify_packet(bundle) is True


# ── findings, quarantine, recertify ──────────────────────────────────────────────


CRITICAL_PACKET = {
    "environment": "prod",
    "status": "REJECTED",
    "summary": {"critical": 1, "high": 0},
    "findings": [{
        "check_id": "ENV-03",
        "finding_type": "blastcontain.env.model_weights_writable",
        "severity": "CRITICAL",
        "title": "Model Weight Directory Is Writable",
    }],
}


def test_critical_finding_auto_quarantines_prod(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/findings", json=CRITICAL_PACKET)
    assert response.status_code == 201
    assert response.json()["quarantined"] is True
    assert client.get("/v1/charters/invoice-bot?env=prod").json()["packet"]["state"] == \
        "quarantined"
    # resume is not an exit from quarantine (§7.4)
    assert client.post("/v1/agents/invoice-bot/resume?env=prod",
                       json={"actor": "ops"}).status_code == 409


def test_recertify_requires_matching_proof(client, charter_body):
    _sign(client, charter_body)
    client.post("/v1/agents/invoice-bot/findings", json=CRITICAL_PACKET)

    wrong = client.post("/v1/charters/invoice-bot/recertify?env=prod", json={
        "actor": "alice",
        "proof": {"finding_type": "something.else", "evidence_uri": "pr://42"},
    })
    assert wrong.status_code == 409

    right = client.post("/v1/charters/invoice-bot/recertify?env=prod", json={
        "actor": "alice",
        "proof": {"finding_type": "blastcontain.env.model_weights_writable",
                  "evidence_uri": "pr://42", "verified_by": "did:key:auditor"},
    })
    assert right.status_code == 200
    body = right.json()
    assert body["state"] == "active"
    assert body["version"] == "1.0.1"           # recertification is a new signed version
    bundle = client.get("/v1/charters/invoice-bot?env=prod").json()
    proofs = bundle["packet"]["remediation_proofs"]
    assert proofs[0]["finding_type"] == "blastcontain.env.model_weights_writable"


def test_signed_finding_packet_is_verified(client, charter_body, signing_env):
    from blastcontain_core.signing import sign_packet

    _sign(client, charter_body)
    packet = {"environment": "staging", "findings": [], "summary": {"critical": 0}}
    bundle = {"packet": packet, "signature": sign_packet(packet, signed_at="2026-06-11T00:00:00Z")}
    response = client.post("/v1/agents/invoice-bot/findings", json=bundle)
    assert response.json()["signature_verified"] is True


# ── promotion + rollback ─────────────────────────────────────────────────────────


def test_promotion_gate_blocks_unaddressed_criticals(client, charter_body):
    charter_body["environment"] = "staging"
    _sign(client, charter_body, env="staging")
    staging_critical = dict(CRITICAL_PACKET, environment="staging")
    client.post("/v1/agents/invoice-bot/findings", json=staging_critical)

    blocked = client.post("/v1/charters/invoice-bot/promote", json={
        "from_env": "staging", "to_env": "prod", "actor": "alice",
    })
    assert blocked.status_code == 409
    assert "blastcontain.env.model_weights_writable" in str(blocked.json())


def test_promotion_creates_target_draft(client, charter_body):
    charter_body["environment"] = "staging"
    _sign(client, charter_body, env="staging")
    response = client.post("/v1/charters/invoice-bot/promote", json={
        "from_env": "staging", "to_env": "prod", "actor": "alice",
    })
    assert response.status_code == 200
    draft = client.get("/v1/charters/invoice-bot?env=prod&include_draft=true").json()
    assert draft["draft"] is True
    assert draft["document"]["environment"] == "prod"
    # promotion is a gate, not a deploy: prod still has no signed Charter
    assert client.get("/v1/charters/invoice-bot?env=prod").status_code == 404


def test_rollback_reissues_prior_version(client, charter_body):
    _sign(client, charter_body)
    charter_body["version"] = "2.0.0"
    charter_body["permitted_tools"].append("new_tool")
    _sign(client, charter_body)

    response = client.post("/v1/charters/invoice-bot/rollback?env=prod",
                           json={"actor": "alice", "reason": "v2 misbehaves"})
    assert response.status_code == 200
    assert response.json()["version"] == "1.0.0"
    bundle = client.get("/v1/charters/invoice-bot?env=prod").json()
    assert bundle["packet"]["version"] == "1.0.0"
    assert "new_tool" not in bundle["packet"]["permitted_tools"]
    assert verify_packet(bundle) is True


# ── decisions + tombstone ────────────────────────────────────────────────────────


CLOUD_EVENT = {
    "specversion": "1.0",
    "type": "com.blastcontain.guard.decision",
    "source": "blastcontain-guard/invoice-bot",
    "id": "evt-1",
    "subject": "query_invoice",
    "data": {
        "agent_id": "invoice-bot", "environment": "prod", "tool": "query_invoice",
        "action_type": "read", "decision": "allow", "final": "allow",
        "latency_ms": 0.4,
    },
}


def test_decision_ingest_and_query(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/decisions", json=CLOUD_EVENT)
    assert response.status_code == 202
    decisions = client.get("/v1/agents/invoice-bot/decisions?env=prod").json()["decisions"]
    assert decisions[0]["data"]["decision"] == "allow"


def test_tombstone_traffic_raises_a_finding(client, charter_body):
    _sign(client, charter_body)
    client.post("/v1/agents/invoice-bot/decommission?env=prod", json={"actor": "alice"})
    response = client.post("/v1/agents/invoice-bot/decisions", json=CLOUD_EVENT)
    assert response.json().get("tombstone_alert") is True
    violations = client.get("/violations").json()["violations"]
    assert any(v["finding_type"] == "blastcontain.lifecycle.tombstone_traffic"
               for v in violations)


# ── fleet + mpl + auth ───────────────────────────────────────────────────────────


def test_fleet_merges_charters_and_scans(client, charter_body):
    _sign(client, charter_body)
    client.post("/v1/agents/invoice-bot/findings",
                json={"environment": "prod", "status": "PASSED",
                      "scanned_at": "2026-06-11T00:00:00Z",
                      "summary": {"critical": 0}, "findings": []})
    fleet = client.get("/fleet").json()
    assert fleet["total"] == 1
    agent = fleet["agents"][0]
    assert agent["charters"] == {"prod": "active"}
    assert agent["status"] == "PASSED"


def test_fleet_draft_never_masks_signed_state(client, charter_body):
    _sign(client, charter_body)
    # A new working draft for the same (agent, env) must not mask the active
    # charter — an operator reading "draft" would think enforcement lapsed.
    client.post("/v1/charters", json=charter_body)
    fleet = client.get("/fleet").json()
    assert fleet["agents"][0]["charters"] == {"prod": "active"}
    # The draft is still there and served when asked for explicitly.
    draft = client.get("/v1/charters/invoice-bot?env=prod&include_draft=true").json()
    assert draft["draft"] is True


def test_mpl_endpoint(client, charter_body):
    _sign(client, charter_body)
    response = client.get(
        "/v1/agents/invoice-bot/mpl?env=prod&classification=PII&volume=10000"
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mpl_usd"] > 0
    assert "exposure index" in body["methodology"]


def test_bearer_auth_when_token_set(client, charter_body, signing_env):
    signing_env.setenv("BLASTCONTAIN_API_TOKEN", "sekrit")
    assert client.get("/v1/agents").status_code == 401
    assert client.get("/v1/agents",
                      headers={"Authorization": "Bearer sekrit"}).status_code == 200
    assert client.get("/health").status_code == 200    # health stays open
