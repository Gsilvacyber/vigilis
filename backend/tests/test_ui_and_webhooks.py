"""Tests for UI pages, webhook logs, impactSummary, and ttfdComparison."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest


# ── UI endpoints return 200 ──────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "/demo/ui/",
    "/demo/ui/enrich",
    "/demo/ui/cases",
    "/demo/ui/incidents",
    "/demo/ui/metrics",
    "/demo/ui/upload",
    "/demo/ui/cases/fake-case-id-123",
])
def test_ui_pages_return_html(test_client, path: str):
    resp = test_client.get(path)
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "<html" in resp.text


def test_case_detail_page_has_back_link(test_client):
    resp = test_client.get("/demo/ui/cases/some-id")
    assert resp.status_code == 200
    assert "/demo/ui/cases" in resp.text
    assert "Vigilis - Case Detail" in resp.text


# ── Webhook logs endpoint ────────────────────────────────────────────────

def test_webhook_logs_empty(test_client):
    test_client.post("/api/v1/demo/reset")
    resp = test_client.get("/api/v1/webhooks/logs")
    assert resp.status_code == 200
    assert resp.json() == []


def test_webhook_logs_after_pilot(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    resp = test_client.get("/api/v1/webhooks/logs")
    assert resp.status_code == 200
    logs = resp.json()
    assert len(logs) == 4
    for entry in logs:
        assert "caseId" in entry
        assert "target" in entry
        assert entry["status"] == "delivered"
        assert entry["statusCode"] == 200
        assert entry["attemptNo"] == 1


# ── impactSummary presence ───────────────────────────────────────────────

def test_impact_summary_on_case_creation(test_client):
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")

    cases = test_client.get(
        "/api/v1/cases", params={"tenantId": "demo-tenant"}
    ).json()
    assert len(cases) == 10

    for c in cases:
        imp = c["enrichment"]["impactSummary"]
        assert imp is not None
        assert "risk" in imp
        assert imp["timeSavedMinutes"] > 0
        assert len(imp["manualStepsReplaced"]) >= 3


def test_impact_summary_in_enrich_raw(test_client):
    from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS

    payload = {
        "alertType": "identity.suspiciousSignIn",
        "rawAlert": SAMPLE_RAW_ALERTS["identity.suspiciousSignIn"],
    }
    resp = test_client.post("/api/v1/demo/enrich-raw", json=payload)
    assert resp.status_code == 200
    imp = resp.json()["enrichment"]["impactSummary"]
    assert len(imp["risk"]) > 10, "Risk string should be descriptive"
    assert imp["timeSavedMinutes"] >= 10


# ── ttfdComparison presence ──────────────────────────────────────────────

def test_ttfd_comparison_after_disposition(test_client):
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")

    cases = test_client.get(
        "/api/v1/cases", params={"tenantId": "demo-tenant"}
    ).json()
    case_id = cases[0]["caseId"]
    ingested_dt = datetime.fromisoformat(cases[0]["timestamps"]["ingestedTime"])

    decision_dt = ingested_dt + timedelta(seconds=90)
    test_client.patch(
        f"/api/v1/cases/{case_id}/disposition",
        json={
            "status": "investigating",
            "setBy": "analyst-1",
            "setAt": decision_dt.isoformat(),
        },
    )

    updated = test_client.get(f"/api/v1/cases/{case_id}").json()
    comp = updated["outputs"]["ttfdComparison"]
    assert comp is not None
    assert abs(comp["automatedSeconds"] - 90.0) < 1
    assert comp["estimatedManualSeconds"] == 900
    assert "x faster" in comp["improvement"]


def test_ttfd_comparison_after_pilot(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")

    cases = test_client.get(
        "/api/v1/cases", params={"tenantId": "demo-tenant"}
    ).json()

    with_comp = [
        c for c in cases
        if c["outputs"].get("ttfdComparison") is not None
    ]
    assert len(with_comp) == 8

    for c in with_comp:
        comp = c["outputs"]["ttfdComparison"]
        assert comp["automatedSeconds"] > 0
        assert "x faster" in comp["improvement"]
