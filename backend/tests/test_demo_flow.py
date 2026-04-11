"""Tests for the demo endpoints and enriched fixture flow."""
from __future__ import annotations

from uuid import UUID

import pytest

from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS


# ── GET /api/v1/demo/sample-raw-alerts ───────────────────────────────────

def test_sample_raw_alerts_returns_all_types(test_client):
    resp = test_client.get("/api/v1/demo/sample-raw-alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 10
    for alert_type in SAMPLE_RAW_ALERTS:
        assert alert_type in data


# ── POST /api/v1/demo/reset ──────────────────────────────────────────────

def test_reset_clears_data(test_client):
    test_client.post("/api/v1/demo/load-fixtures")
    cases = test_client.get("/api/v1/cases", params={"tenantId": "demo-tenant"}).json()
    assert len(cases) > 0

    resp = test_client.post("/api/v1/demo/reset")
    assert resp.status_code == 200
    assert resp.json()["status"] == "reset"

    cases = test_client.get("/api/v1/cases", params={"tenantId": "demo-tenant"}).json()
    assert len(cases) == 0


# ── POST /api/v1/demo/enrich-raw  (basic mode) ──────────────────────────

@pytest.mark.parametrize("alert_type", list(SAMPLE_RAW_ALERTS.keys()))
def test_enrich_raw_returns_case_for_every_type(test_client, alert_type: str):
    payload = {
        "alertType": alert_type,
        "rawAlert": SAMPLE_RAW_ALERTS[alert_type],
    }
    resp = test_client.post("/api/v1/demo/enrich-raw", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["schemaVersion"] == "case.v0.2"
    assert data["alertType"] == alert_type
    assert data["confidence"]["score"] > 0
    assert len(data["confidence"]["explanation"]) >= 1
    assert len(data["recommendedPlaybook"]) >= 3
    assert len(data["recommendedActions"]) >= 2


# ── POST /api/v1/demo/enrich-raw  (debug mode) ──────────────────────────

def test_enrich_raw_debug_returns_envelope(test_client):
    payload = {
        "alertType": "identity.suspiciousSignIn",
        "rawAlert": SAMPLE_RAW_ALERTS["identity.suspiciousSignIn"],
    }
    resp = test_client.post(
        "/api/v1/demo/enrich-raw", json=payload, params={"includeDebug": True}
    )
    assert resp.status_code == 200
    data = resp.json()

    assert "rawInput" in data
    assert "derivedSignals" in data
    assert "scoreBreakdown" in data
    assert "confidence" in data
    assert "recommendedPlaybook" in data
    assert "recommendedActions" in data
    assert "finalCase" in data

    assert data["scoreBreakdown"]["severityBase"] == 15  # medium base (reduced so signals drive scoring)
    assert data["scoreBreakdown"]["signalBoost"] > 0
    # finalScore may be capped at 65 if no verified signals fired (tier-based cap)
    assert data["scoreBreakdown"]["finalScore"] <= 100
    assert data["scoreBreakdown"]["finalScore"] > 0

    fired = [s for s in data["derivedSignals"] if s["fired"]]
    not_fired = [s for s in data["derivedSignals"] if not s["fired"]]
    assert len(fired) >= 3
    assert all("signal" in s and "weight" in s and "label" in s for s in fired)
    assert isinstance(not_fired, list)


@pytest.mark.parametrize("alert_type,expected_signal", [
    ("identity.suspiciousSignIn", "impossible_travel"),
    ("identity.passwordSpray", "successful_login"),
    ("identity.mfaFatigue", "anomalous_ip"),
    ("identity.oauthConsentRisk", "broad_scopes"),
    ("identity.privilegeElevation", "admin_role_grant"),
    ("endpoint.malwareDetection", "rare_file"),
    ("endpoint.suspiciousProcess", "living_off_the_land"),
    ("email.forwardingRule", "external_forward"),
    ("cloud.secretStoreAccessAnomaly", "new_app"),
    ("network.impossibleGeoAccess", "multi_country_access"),
])
def test_debug_includes_expected_signal(test_client, alert_type: str, expected_signal: str):
    payload = {
        "alertType": alert_type,
        "rawAlert": SAMPLE_RAW_ALERTS[alert_type],
    }
    resp = test_client.post(
        "/api/v1/demo/enrich-raw", json=payload, params={"includeDebug": True}
    )
    assert resp.status_code == 200
    fired_names = {
        s["signal"] for s in resp.json()["derivedSignals"] if s["fired"]
    }
    assert expected_signal in fired_names, (
        f"{alert_type}: expected '{expected_signal}' in {fired_names}"
    )


# ── Persist mode ─────────────────────────────────────────────────────────

def test_enrich_raw_persist_stores_case(test_client, db_session):
    test_client.post("/api/v1/demo/reset")

    payload = {
        "alertType": "identity.suspiciousSignIn",
        "rawAlert": SAMPLE_RAW_ALERTS["identity.suspiciousSignIn"],
        "persist": True,
    }
    resp = test_client.post("/api/v1/demo/enrich-raw", json=payload)
    assert resp.status_code == 200
    case_id = resp.json()["caseId"]

    get_resp = test_client.get(f"/api/v1/cases/{case_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["alertType"] == "identity.suspiciousSignIn"


# ── Enriched fixture quality ─────────────────────────────────────────────

def test_fixtures_produce_high_confidence_cases(test_client):
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")

    cases = test_client.get(
        "/api/v1/cases", params={"tenantId": "demo-tenant"}
    ).json()
    assert len(cases) == 10

    high_or_critical = [
        c for c in cases
        if c["confidence"]["label"] in ("high", "critical")
    ]
    assert len(high_or_critical) >= 7, (
        f"Only {len(high_or_critical)}/10 are high/critical: "
        + str([(c["alertType"], c["confidence"]["label"]) for c in cases])
    )

    for c in cases:
        assert len(c["recommendedPlaybook"]) >= 3
        assert len(c["recommendedActions"]) >= 2
        assert len(c["enrichment"]["enrichmentNotes"]) >= 1
