"""Tests for Phase 7: integration config, dynamic impactSummary, case readiness, export."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


# ── Config endpoints ─────────────────────────────────────────────────────

def test_config_get_returns_defaults(test_client):
    """GET /api/v1/config returns a config with mode and webhookTargets."""
    resp = test_client.get("/api/v1/config")
    assert resp.status_code == 200
    data = resp.json()
    assert "mode" in data
    assert "webhookTargets" in data
    assert data["mode"] in ("automated", "manual")


def test_config_add_webhook(test_client, tmp_path, monkeypatch):
    """POST /api/v1/config/webhooks adds a target and persists it."""
    monkeypatch.setattr(
        "backend.app.services.config_service._CONFIG_PATH",
        tmp_path / "test_config.json",
    )
    resp = test_client.post(
        "/api/v1/config/webhooks",
        json={"name": "Test SOAR", "url": "https://soar.acme.com/ingest"},
    )
    assert resp.status_code == 200
    targets = resp.json()
    names = [t["name"] for t in targets]
    assert "Test SOAR" in names


def test_config_list_webhooks(test_client):
    """GET /api/v1/config/webhooks returns the webhook target list."""
    resp = test_client.get("/api/v1/config/webhooks")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_config_patch_mode(test_client, tmp_path, monkeypatch):
    """PATCH /api/v1/config updates the mode field."""
    monkeypatch.setattr(
        "backend.app.services.config_service._CONFIG_PATH",
        tmp_path / "test_config2.json",
    )
    resp = test_client.patch(
        "/api/v1/config",
        json={"mode": "manual"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "manual"


# ── Dynamic impactSummary ────────────────────────────────────────────────

def test_impact_summary_dynamic_time_saved(test_client):
    """timeSavedMinutes should vary based on signal count and entities, not be static."""
    from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS

    times: list[int] = []
    for at in ["identity.suspiciousSignIn", "endpoint.malwareDetection", "email.forwardingRule"]:
        resp = test_client.post(
            "/api/v1/demo/enrich-raw",
            json={"alertType": at, "rawAlert": SAMPLE_RAW_ALERTS[at]},
        )
        assert resp.status_code == 200
        imp = resp.json()["enrichment"]["impactSummary"]
        assert imp["timeSavedMinutes"] >= 5
        assert imp["timeSavedMinutes"] <= 45
        times.append(imp["timeSavedMinutes"])
    assert len(set(times)) > 1, "timeSavedMinutes should vary across alert types"


def test_impact_summary_privileged_gets_more_time(test_client):
    """A privileged account should result in higher timeSavedMinutes."""
    base_alert = {
        "identity": {"identityType": "user", "userId": "u-1", "upn": "user@test.com",
                      "privilegeTier": "standard"},
        "ips": [{"role": "anomalous", "ipAddress": "1.2.3.4"}],
        "device": {"hostname": "PC-1", "managed": True},
    }
    priv_alert = {
        "identity": {"identityType": "user", "userId": "u-1", "upn": "admin@test.com",
                      "privilegeTier": "admin", "mfaStatus": "disabled", "riskLevel": "high"},
        "ips": [{"role": "anomalous", "ipAddress": "1.2.3.4",
                 "geo": {"country": "RU"}},
                {"role": "legitimate", "ipAddress": "10.0.0.1",
                 "geo": {"country": "US"}}],
        "device": {"hostname": "PC-1", "managed": False},
    }
    r1 = test_client.post("/api/v1/demo/enrich-raw",
                          json={"alertType": "identity.suspiciousSignIn", "rawAlert": base_alert})
    r2 = test_client.post("/api/v1/demo/enrich-raw",
                          json={"alertType": "identity.suspiciousSignIn", "rawAlert": priv_alert})
    t1 = r1.json()["enrichment"]["impactSummary"]["timeSavedMinutes"]
    t2 = r2.json()["enrichment"]["impactSummary"]["timeSavedMinutes"]
    assert t2 > t1, f"Privileged ({t2}) should save more time than standard ({t1})"


def test_impact_risk_string_is_alert_specific(test_client):
    """Risk string should be specific to alert type, not generic."""
    from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS

    resp = test_client.post(
        "/api/v1/demo/enrich-raw",
        json={"alertType": "identity.suspiciousSignIn",
              "rawAlert": SAMPLE_RAW_ALERTS["identity.suspiciousSignIn"]},
    )
    risk = resp.json()["enrichment"]["impactSummary"]["risk"]
    assert any(kw in risk.lower() for kw in ["account", "credential", "sign-in", "session"]), \
        f"Risk should be identity-specific, got: {risk}"


# ── Case readiness ───────────────────────────────────────────────────────

def test_case_readiness_present(test_client):
    """Every enriched case should include caseReadiness."""
    from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS

    for at in list(SAMPLE_RAW_ALERTS.keys())[:3]:
        resp = test_client.post(
            "/api/v1/demo/enrich-raw",
            json={"alertType": at, "rawAlert": SAMPLE_RAW_ALERTS[at]},
        )
        assert resp.status_code == 200
        rd = resp.json()["enrichment"]["caseReadiness"]
        assert rd is not None
        assert "readyForAction" in rd
        assert "missingContext" in rd
        assert "confidenceLevel" in rd


def test_case_readiness_ready_when_complete(test_client):
    """A well-formed alert with high confidence should be readyForAction."""
    from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS

    resp = test_client.post(
        "/api/v1/demo/enrich-raw",
        json={"alertType": "identity.suspiciousSignIn",
              "rawAlert": SAMPLE_RAW_ALERTS["identity.suspiciousSignIn"]},
    )
    rd = resp.json()["enrichment"]["caseReadiness"]
    assert rd["readyForAction"] is True
    assert rd["missingContext"] == []


def test_case_readiness_persisted_in_db(test_client):
    """caseReadiness should survive persist -> read cycle."""
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")
    cases = test_client.get("/api/v1/cases", params={"tenantId": "demo-tenant"}).json()
    assert len(cases) > 0
    for c in cases:
        rd = c["enrichment"]["caseReadiness"]
        assert rd is not None
        assert "readyForAction" in rd


# ── Export endpoint ──────────────────────────────────────────────────────

def test_export_returns_envelope(test_client):
    """GET /api/v1/cases/{id}/export returns clean export envelope."""
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")
    cases = test_client.get("/api/v1/cases", params={"tenantId": "demo-tenant"}).json()
    case_id = cases[0]["caseId"]

    resp = test_client.get(f"/api/v1/cases/{case_id}/export")
    assert resp.status_code == 200
    data = resp.json()
    assert data["exportVersion"] == "1.0"
    assert data["format"] == "case.v0.2"
    assert "exportedAt" in data
    assert data["case"]["caseId"] == case_id


def test_export_404_for_missing_case(test_client):
    """Export of non-existent case returns 404."""
    resp = test_client.get("/api/v1/cases/00000000-0000-0000-0000-000000000000/export")
    assert resp.status_code == 404
