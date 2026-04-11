"""Tests for pilot metrics, TTFD, and simulate-pilot flow."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


# ── Empty state ──────────────────────────────────────────────────────────

def test_summary_empty(test_client):
    test_client.post("/api/v1/demo/reset")
    resp = test_client.get("/api/v1/metrics/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data["totalCases"] == 0
    assert data["casesWithFirstDecision"] == 0
    assert data["casesOpenNoDecision"] == 0
    assert data["webhookDeliveryCount"] == 0


def test_ttfd_empty(test_client):
    test_client.post("/api/v1/demo/reset")
    resp = test_client.get("/api/v1/metrics/ttfd")
    assert resp.status_code == 200
    data = resp.json()
    assert data["averageTtfdSeconds"] is None
    assert data["casesWithTtfd"] == 0


# ── After loading fixtures (no decisions yet) ────────────────────────────

def test_summary_after_fixtures(test_client):
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")
    resp = test_client.get("/api/v1/metrics/summary")
    data = resp.json()
    assert data["totalCases"] == 10
    assert len(data["casesByAlertType"]) == 10
    assert data["avgConfidenceScore"] > 50
    assert data["casesWithFirstDecision"] == 0
    assert data["casesOpenNoDecision"] == 10
    assert data["dispositionCounts"]["open"] == 10


# ── TTFD calculation correctness ─────────────────────────────────────────

def test_ttfd_single_disposition(test_client):
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")

    cases = test_client.get(
        "/api/v1/cases", params={"tenantId": "demo-tenant"}
    ).json()
    case_id = cases[0]["caseId"]
    ingested_str = cases[0]["timestamps"]["ingestedTime"]
    ingested_dt = datetime.fromisoformat(ingested_str)

    decision_dt = ingested_dt + timedelta(seconds=120)
    test_client.patch(
        f"/api/v1/cases/{case_id}/disposition",
        json={
            "status": "investigating",
            "setBy": "analyst-1",
            "setAt": decision_dt.isoformat(),
        },
    )

    ttfd = test_client.get("/api/v1/metrics/ttfd").json()
    assert ttfd["casesWithTtfd"] == 1
    assert ttfd["casesWithoutTtfd"] == 9
    assert abs(ttfd["averageTtfdSeconds"] - 120.0) < 1
    assert abs(ttfd["medianTtfdSeconds"] - 120.0) < 1
    assert ttfd["minTtfdSeconds"] == ttfd["maxTtfdSeconds"]


def test_first_decision_only_counts_once(test_client):
    """Second disposition should NOT overwrite the original TTFD."""
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")

    cases = test_client.get(
        "/api/v1/cases", params={"tenantId": "demo-tenant"}
    ).json()
    case_id = cases[0]["caseId"]
    ingested_dt = datetime.fromisoformat(cases[0]["timestamps"]["ingestedTime"])

    decision1 = ingested_dt + timedelta(seconds=60)
    test_client.patch(
        f"/api/v1/cases/{case_id}/disposition",
        json={
            "status": "investigating",
            "setBy": "analyst-1",
            "setAt": decision1.isoformat(),
        },
    )

    decision2 = ingested_dt + timedelta(seconds=600)
    test_client.patch(
        f"/api/v1/cases/{case_id}/disposition",
        json={
            "status": "true_positive",
            "setBy": "analyst-1",
            "setAt": decision2.isoformat(),
        },
    )

    ttfd = test_client.get("/api/v1/metrics/ttfd").json()
    assert ttfd["casesWithTtfd"] == 1
    assert abs(ttfd["averageTtfdSeconds"] - 60.0) < 1


# ── By-alert-type aggregation ────────────────────────────────────────────

def test_by_alert_type_aggregation(test_client):
    test_client.post("/api/v1/demo/reset")
    test_client.post("/api/v1/demo/load-fixtures")

    resp = test_client.get("/api/v1/metrics/by-alert-type")
    assert resp.status_code == 200
    data = resp.json()["alertTypes"]
    assert len(data) == 10

    for at, metrics in data.items():
        assert metrics["count"] >= 1
        assert metrics["avgConfidenceScore"] > 0
        assert "dispositions" in metrics
        assert metrics["avgTtfdSeconds"] is None  # no decisions yet


# ── Simulate pilot ───────────────────────────────────────────────────────

def test_simulate_pilot_endpoint(test_client):
    resp = test_client.post("/api/v1/demo/simulate-pilot")
    assert resp.status_code == 200
    sim = resp.json()
    assert sim["casesLoaded"] == 10
    assert sim["decisionsApplied"] == 8
    assert sim["casesLeftOpen"] == 2
    assert sim["webhookDeliveries"] == 4  # 2 true_positive + 2 escalated


def test_simulate_pilot_populates_summary(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")

    summary = test_client.get("/api/v1/metrics/summary").json()
    assert summary["totalCases"] == 10
    assert summary["casesWithFirstDecision"] == 8
    assert summary["casesOpenNoDecision"] == 2
    assert summary["webhookDeliveryCount"] == 4
    assert "investigating" in summary["dispositionCounts"]
    assert "true_positive" in summary["dispositionCounts"]


def test_simulate_pilot_populates_ttfd(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")

    ttfd = test_client.get("/api/v1/metrics/ttfd").json()
    assert ttfd["casesWithTtfd"] == 8
    assert ttfd["casesWithoutTtfd"] == 2
    assert 210 <= ttfd["averageTtfdSeconds"] <= 220
    assert 125 <= ttfd["medianTtfdSeconds"] <= 130
    assert ttfd["minTtfdSeconds"] == 25.0
    assert ttfd["maxTtfdSeconds"] == 600.0
    assert len(ttfd["ttfdByAlertType"]) >= 5


def test_simulate_pilot_by_alert_type(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")

    data = test_client.get("/api/v1/metrics/by-alert-type").json()["alertTypes"]
    decided = [at for at, m in data.items() if m["casesWithFirstDecision"] > 0]
    open_types = [at for at, m in data.items() if m["casesWithFirstDecision"] == 0]
    assert len(decided) == 8
    assert len(open_types) == 2

    with_webhooks = sum(1 for m in data.values() if m["webhookDeliveries"] > 0)
    assert with_webhooks == 4


# ── Tenant filtering ────────────────────────────────────────────────────

def test_by_tenant_returns_filtered(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")

    resp = test_client.get("/api/v1/metrics/by-tenant/demo-tenant")
    assert resp.status_code == 200
    assert resp.json()["totalCases"] == 10

    resp = test_client.get("/api/v1/metrics/by-tenant/nonexistent-tenant")
    assert resp.status_code == 403, "Cross-tenant access should be blocked"


def test_summary_with_tenant_filter(test_client):
    """Summary is always scoped to the authenticated tenant (query param ignored)."""
    test_client.post("/api/v1/demo/simulate-pilot")

    resp = test_client.get(
        "/api/v1/metrics/summary", params={"tenantId": "demo-tenant"}
    )
    assert resp.json()["totalCases"] == 10

    resp = test_client.get(
        "/api/v1/metrics/summary", params={"tenantId": "other"}
    )
    assert resp.json()["totalCases"] == 10, "tenantId param is ignored; scoped by API key"
