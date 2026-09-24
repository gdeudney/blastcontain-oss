"""The Ledger (roadmap P2): MPL v2, HITL quality, drift, scrubbing, Audit Packet."""
from __future__ import annotations

from blastcontain.ledger.audit_packet import compliance_grade
from blastcontain.ledger.drift import compute_drift
from blastcontain.ledger.hitl import compute_hitl_metrics
from blastcontain.ledger.mpl import (
    MPLCalibration,
    MPLInput,
    calculate_mpl,
    exposure_band,
    mpl_report,
    oversight_level,
)
from blastcontain.ledger.scrub import scrub_packet, scrub_text
from blastcontain_core.signing import verify_packet

# ── MPL v2 ───────────────────────────────────────────────────────────────────────


def test_oversight_factor_discounts_gated_risk():
    base = MPLInput(classification_label="PII", volume_records=1000, oversight="none")
    gated = MPLInput(classification_label="PII", volume_records=1000, oversight="gated")
    stamped = MPLInput(classification_label="PII", volume_records=1000,
                       oversight="gated_low_quality")
    assert calculate_mpl(gated) < calculate_mpl(stamped) < calculate_mpl(base)


def test_calibration_overrides_base_values_and_scale():
    inp = MPLInput(classification_label="PII")
    default = calculate_mpl(inp)
    calibrated = calculate_mpl(inp, MPLCalibration(base_values={"PII": 2000.0}))
    assert calibrated == default * 2
    scaled = calculate_mpl(inp, MPLCalibration(global_scale=0.5))
    assert scaled == default / 2


def test_exposure_bands():
    assert exposure_band(500) == "LOW"
    assert exposure_band(50_000) == "MODERATE"
    assert exposure_band(500_000) == "HIGH"
    assert exposure_band(5_000_000) == "SEVERE"


def test_mpl_report_is_an_index_not_a_prophecy():
    report = mpl_report(MPLInput(), MPLCalibration(global_scale=2.0))
    assert report["band"] in ("LOW", "MODERATE", "HIGH", "SEVERE")
    assert report["calibrated"] is True
    assert "not a loss prediction" in report["methodology"]


def test_oversight_level_selection():
    healthy = {"asks_total": 30, "rubber_stamp_risk": False}
    stamped = {"asks_total": 30, "rubber_stamp_risk": True}
    assert oversight_level("autonomous", healthy) == "none"
    assert oversight_level("interactive", None) == "none"
    assert oversight_level("interactive", {"asks_total": 0}) == "none"
    assert oversight_level("interactive", healthy) == "gated"
    assert oversight_level("interactive", stamped) == "gated_low_quality"


# ── HITL quality ─────────────────────────────────────────────────────────────────


def _ask(final="allow", latency=5000.0, ask_choice=None, concern=None):
    return {"data": {"decision": "ask", "final": final, "latency_ms": latency,
                     "ask_choice": ask_choice, "concern": concern}}


def test_hitl_metrics_rates_and_latency():
    events = [_ask("allow", 4000), _ask("allow", 6000), _ask("deny", 8000),
              {"data": {"decision": "allow", "final": "allow"}},
              {"data": {"decision": "deny", "final": "deny", "concern": "no-pii-egress"}}]
    metrics = compute_hitl_metrics(events)
    assert metrics["events_total"] == 5
    assert metrics["asks_total"] == 3
    assert metrics["approval_rate"] == round(2 / 3, 4)
    assert metrics["override_rate"] == round(1 / 3, 4)
    assert metrics["approval_latency_ms"]["median"] == 6000
    assert metrics["rubber_stamp_risk"] is False
    assert metrics["top_denied_concerns"][0] == ("no-pii-egress", 1)


def test_rubber_stamp_pattern_detected():
    # 25 asks, all approved, instantly: the gate is theater.
    events = [_ask("allow", 300.0) for _ in range(25)]
    metrics = compute_hitl_metrics(events)
    assert metrics["rubber_stamp_risk"] is True

    # Same volume, deliberate latency: healthy gate.
    slow = compute_hitl_metrics([_ask("allow", 9000.0) for _ in range(25)])
    assert slow["rubber_stamp_risk"] is False


def test_allow_always_pressure_is_counted():
    events = [_ask("allow", 5000, ask_choice="allow_always") for _ in range(4)]
    assert compute_hitl_metrics(events)["allow_always_count"] == 4


# ── drift ────────────────────────────────────────────────────────────────────────


def _decision(tool, decision="allow", final=None, action="read"):
    return {"data": {"tool": tool, "decision": decision,
                     "final": final or ("allow" if decision != "deny" else "deny"),
                     "action_type": action}}


def test_drift_declared_vs_observed():
    document = {
        "permitted_tools": ["query_db", "send_report"],
        "environment_constraints": {"egress_blocked": True},
    }
    decisions = (
        [_decision("query_db")] * 3
        + [_decision("curl_external", "deny")] * 2
        + [_decision("export_csv", "ask", "allow")] * 3
    )
    scan = {"findings": [{"finding_type": "blastcontain.env.egress_unrestricted",
                          "severity": "HIGH"}]}
    report = compute_drift(document, decisions, scan)
    assert report["drift_detected"] is True
    assert report["unused_grants"] == ["send_report"]
    assert report["unlisted_attempts"][0] == {"tool": "curl_external",
                                              "attempts": 2, "denied": 2}
    assert report["learning_candidates"][0]["tool"] == "export_csv"
    assert report["scan_contradictions"][0]["constraint"] == "egress_blocked"


def test_no_drift_when_use_matches_charter():
    document = {"permitted_tools": ["query_db"],
                "environment_constraints": {"egress_blocked": False}}
    report = compute_drift(document, [_decision("query_db")], latest_scan=None)
    assert report["drift_detected"] is False


# ── scrubbing ────────────────────────────────────────────────────────────────────


def test_scrub_text_hashes_pii_and_secrets():
    text = ("contact alice@example.com, key sk_live_abcdefghijklmnop1234, "
            "ssn 123-45-6789")
    scrubbed, hits = scrub_text(text)
    assert hits >= 3
    assert "alice@example.com" not in scrubbed
    assert "sk_live_abcdefghijklmnop1234" not in scrubbed
    assert "123-45-6789" not in scrubbed
    assert "[scrubbed:" in scrubbed


def test_scrub_is_correlatable():
    # The same secret scrubs to the same token — correlation without exposure.
    a, _ = scrub_text("leak: bob@example.com")
    b, _ = scrub_text("again: bob@example.com")
    token_a = a.split("leak: ")[1]
    assert token_a in b


def test_scrub_packet_targets_sensitive_keys_only():
    packet = {
        "agent_id": "bot@host",                      # identity key: untouched
        "findings": [{
            "finding_type": "blastcontain.cred.x",
            "evidence": "found key AKIAABCDEFGHIJKLMNOP in env",
        }],
    }
    scrubbed, hits = scrub_packet(packet)
    assert hits == 1
    assert scrubbed["agent_id"] == "bot@host"
    assert "AKIA" not in scrubbed["findings"][0]["evidence"]
    assert scrubbed["evidence_scrubbed"] == 1


# ── compliance grade ─────────────────────────────────────────────────────────────


CLEAN_SCAN = {"status": "PASSED", "summary": {"critical": 0, "high": 0}}
HEALTHY_HITL = {"events_total": 50, "asks_total": 30, "rubber_stamp_risk": False}


def test_grade_a_requires_everything_healthy():
    grade, rationale = compliance_grade(
        {"version": "1.0.0"}, CLEAN_SCAN, [], HEALTHY_HITL, "active")
    assert grade == "A"
    assert rationale


def test_grade_ladder():
    # F: tombstone traffic
    assert compliance_grade({}, CLEAN_SCAN, [], HEALTHY_HITL, "decommissioned",
                            tombstone_findings=2)[0] == "F"
    # F: criticals open while running
    assert compliance_grade({}, None, ["x.y"], HEALTHY_HITL, "active")[0] == "F"
    # D: quarantined (governance reacted)
    assert compliance_grade({}, None, [], HEALTHY_HITL, "quarantined")[0] == "D"
    # C: advisory-signed charter
    assert compliance_grade({}, CLEAN_SCAN, [], HEALTHY_HITL, "active",
                            advisory_signed=True)[0] == "C"
    # C: rubber-stamped gate
    stamped = dict(HEALTHY_HITL, rubber_stamp_risk=True)
    assert compliance_grade({}, CLEAN_SCAN, [], stamped, "active")[0] == "C"
    # B: no scan on record
    assert compliance_grade({}, None, [], HEALTHY_HITL, "active")[0] == "B"


# ── API integration ──────────────────────────────────────────────────────────────


def _sign(client, charter_body, env="prod"):
    assert client.post("/v1/charters", json=charter_body).status_code == 201
    response = client.post(
        f"/v1/charters/{charter_body['agent_id']}/sign?env={env}",
        json={"actor": "alice@example.com"},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _post_decision(client, tool="query_invoice", decision="allow", final=None,
                   latency=5000.0, reason=""):
    event = {"specversion": "1.0", "type": "com.blastcontain.guard.decision",
             "source": "blastcontain-guard/invoice-bot", "subject": tool,
             "data": {"agent_id": "invoice-bot", "environment": "prod",
                      "tool": tool, "decision": decision,
                      "final": final or ("deny" if decision == "deny" else "allow"),
                      "latency_ms": latency, "reason": reason}}
    assert client.post("/v1/agents/invoice-bot/decisions", json=event).status_code == 202


def test_decision_ingest_scrubs_payloads(client, charter_body):
    _sign(client, charter_body)
    _post_decision(client, reason="user carol@example.com asked for it")
    stored = client.get("/v1/agents/invoice-bot/decisions?env=prod").json()["decisions"]
    assert "carol@example.com" not in str(stored)
    assert "[scrubbed:email:" in str(stored)


def test_finding_ingest_scrubs_evidence(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/findings", json={
        "environment": "staging", "status": "PASSED", "summary": {"critical": 0},
        "findings": [{"finding_type": "blastcontain.cred.env_secret",
                      "severity": "HIGH",
                      "evidence": "API key AKIAABCDEFGHIJKLMNOP visible"}],
    })
    assert response.json()["evidence_scrubbed"] == 1
    stored = client.get("/v1/agents/invoice-bot/findings?env=staging").json()
    assert "AKIA" not in str(stored)


def test_calibration_roundtrip_and_mpl(client, charter_body):
    _sign(client, charter_body)
    baseline = client.get("/v1/agents/invoice-bot/mpl?env=prod").json()
    assert baseline["band"] in ("LOW", "MODERATE", "HIGH", "SEVERE")
    assert baseline["calibrated"] is False
    assert baseline["inputs"]["oversight"] == "none"     # no decision evidence yet

    assert client.post("/v1/ledger/calibration",
                       json={"global_scale": 10.0, "note": "org calibration"}
                       ).status_code == 200
    assert client.get("/v1/ledger/calibration").json()["calibration"]["global_scale"] == 10.0

    calibrated = client.get("/v1/agents/invoice-bot/mpl?env=prod").json()
    assert calibrated["calibrated"] is True
    assert calibrated["exposure"] == baseline["exposure"] * 10
    assert calibrated["mpl_usd"] == calibrated["exposure"]   # back-compat alias


def test_hitl_endpoint_aggregates_the_gate(client, charter_body):
    _sign(client, charter_body)
    for _ in range(2):
        _post_decision(client, tool="update_ledger", decision="ask", final="allow")
    _post_decision(client, tool="update_ledger", decision="ask", final="deny")
    metrics = client.get("/v1/agents/invoice-bot/hitl?env=prod").json()
    assert metrics["asks_total"] == 3
    assert metrics["approvals"] == 2
    assert metrics["overrides"] == 1


def test_drift_endpoint(client, charter_body):
    _sign(client, charter_body)
    _post_decision(client, tool="query_invoice")
    _post_decision(client, tool="curl_external", decision="deny")
    report = client.get("/v1/agents/invoice-bot/drift?env=prod").json()
    assert "send_receipt" in report["unused_grants"]
    assert report["unlisted_attempts"][0]["tool"] == "curl_external"
    assert report["drift_detected"] is True


def test_drift_requires_a_charter(client):
    assert client.get("/v1/agents/ghost/drift?env=prod").status_code == 404


def test_audit_packet_is_signed_and_graded(client, charter_body):
    _sign(client, charter_body)
    client.post("/v1/agents/invoice-bot/findings", json={
        "environment": "prod", "status": "PASSED", "scanned_at": "2026-06-11T00:00:00Z",
        "summary": {"critical": 0, "high": 0}, "findings": [],
    })
    _post_decision(client)
    bundle = client.get("/v1/agents/invoice-bot/audit-packet?env=prod").json()
    assert verify_packet(bundle) is True
    packet = bundle["packet"]
    assert packet["packet_type"] == "blastcontain.audit_packet/v1"
    assert packet["compliance"]["grade"] == "A"
    assert packet["charter"]["version"] == "1.0.0"
    assert packet["mpl"]["band"]
    assert packet["hitl"]["events_total"] == 1

    listing = client.get("/v1/agents/invoice-bot/audit-packets").json()["audit_packets"]
    assert listing and listing[0]["grade"] == "A"


def test_decommission_emits_final_audit_packet(client, charter_body):
    _sign(client, charter_body)
    response = client.post("/v1/agents/invoice-bot/decommission?env=prod",
                           json={"actor": "alice"})
    final = response.json()["final_audit_packet"]
    assert final["grade"] in ("A", "B", "C", "D", "F")
    listing = client.get("/v1/agents/invoice-bot/audit-packets").json()["audit_packets"]
    assert any(p["kind"] == "final" for p in listing)


def test_tombstone_traffic_fails_the_next_audit(client, charter_body):
    _sign(client, charter_body)
    client.post("/v1/agents/invoice-bot/decommission?env=prod", json={"actor": "alice"})
    _post_decision(client)          # traffic after retirement
    bundle = client.get("/v1/agents/invoice-bot/audit-packet?env=prod").json()
    assert bundle["packet"]["compliance"]["grade"] == "F"
    assert "tombstone" in str(bundle["packet"]["compliance"]["rationale"])
