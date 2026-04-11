"""Tests for API key auth, tenant isolation, rate limiting, and admin endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlmodel import SQLModel, Session

from backend.app.core.auth import DEMO_API_KEY, seed_demo_key, _hash_key
from backend.app.core.db import engine
from backend.app.db.models import ApiKey
from backend.app.main import app


def _fresh_raw_client() -> TestClient:
    return TestClient(app)


def _client_with_key(key: str) -> TestClient:
    return TestClient(app, headers={"X-API-Key": key})


# ── Missing / invalid API key ─────────────────────────────────────────────

class TestAuthRejection:
    """Endpoints behind require_tenant must reject missing/invalid keys."""

    def test_cases_list_no_key_401(self):
        c = _fresh_raw_client()
        resp = c.get("/api/v1/cases")
        assert resp.status_code == 401
        assert "Missing API key" in resp.json()["detail"]

    def test_metrics_no_key_401(self):
        c = _fresh_raw_client()
        resp = c.get("/api/v1/metrics/summary")
        assert resp.status_code == 401

    def test_config_no_key_401(self):
        c = _fresh_raw_client()
        resp = c.get("/api/v1/config")
        assert resp.status_code == 401

    def test_webhook_logs_no_key_401(self):
        c = _fresh_raw_client()
        resp = c.get("/api/v1/webhooks/logs")
        assert resp.status_code == 401

    def test_invalid_key_401(self, test_client):
        c = _client_with_key("totally-bogus-key")
        resp = c.get("/api/v1/cases")
        assert resp.status_code == 401
        assert "Invalid API key" in resp.json()["detail"]


# ── Valid API key ─────────────────────────────────────────────────────────

class TestAuthSuccess:
    """Valid demo key should grant access."""

    def test_cases_with_demo_key(self, test_client):
        resp = test_client.get("/api/v1/cases")
        assert resp.status_code == 200

    def test_metrics_with_demo_key(self, test_client):
        resp = test_client.get("/api/v1/metrics/summary")
        assert resp.status_code == 200

    def test_config_with_demo_key(self, test_client):
        resp = test_client.get("/api/v1/config")
        assert resp.status_code == 200


# ── Demo endpoints work without key ──────────────────────────────────────

class TestDemoBypass:
    """Demo endpoints use optional_tenant - work without API key."""

    def test_sample_alerts_no_key(self):
        c = _fresh_raw_client()
        resp = c.get("/api/v1/demo/sample-raw-alerts")
        assert resp.status_code == 200

    def test_enrich_raw_no_key(self):
        c = _fresh_raw_client()
        resp = c.post("/api/v1/demo/enrich-raw", json={
            "alertType": "identity.suspiciousSignIn",
            "rawAlert": {"identity": {"userId": "u-1"}},
        })
        assert resp.status_code == 200

    def test_health_no_key(self):
        c = _fresh_raw_client()
        resp = c.get("/health")
        assert resp.status_code == 200

    def test_ui_pages_no_key(self):
        c = _fresh_raw_client()
        for path in ["/demo/ui/", "/demo/ui/enrich", "/demo/ui/cases", "/demo/ui/metrics", "/demo/ui/upload", "/demo/ui/cases/test-id"]:
            resp = c.get(path)
            assert resp.status_code == 200, f"Expected 200 for {path}, got {resp.status_code}"


# ── Tenant isolation ──────────────────────────────────────────────────────

class TestTenantIsolation:
    """Tenants cannot see each other's data."""

    def test_tenant_a_cannot_see_tenant_b_cases(self, test_client):
        test_client.post("/api/v1/demo/reset")
        test_client.post("/api/v1/demo/load-fixtures")

        tenant_b_key = "sk-tenant-b-test-key"
        with Session(engine) as session:
            session.add(ApiKey(key_hash=_hash_key(tenant_b_key), key_prefix=tenant_b_key[:8], tenant_id="other-tenant", name="Tenant B"))
            session.commit()

        client_b = _client_with_key(tenant_b_key)
        resp = client_b.get("/api/v1/cases")
        assert resp.status_code == 200
        assert resp.json() == [], "Tenant B should see no cases from demo-tenant"

    def test_tenant_b_cannot_access_tenant_a_case(self, test_client):
        test_client.post("/api/v1/demo/reset")
        test_client.post("/api/v1/demo/load-fixtures")

        cases = test_client.get("/api/v1/cases").json()
        assert len(cases) > 0
        case_id = cases[0]["caseId"]

        tenant_b_key = "sk-tenant-b-isolation-key"
        with Session(engine) as session:
            session.add(ApiKey(key_hash=_hash_key(tenant_b_key), key_prefix=tenant_b_key[:8], tenant_id="other-tenant", name="Tenant B"))
            session.commit()

        client_b = _client_with_key(tenant_b_key)
        resp = client_b.get(f"/api/v1/cases/{case_id}")
        assert resp.status_code == 403

    def test_tenant_metrics_isolated(self, test_client):
        test_client.post("/api/v1/demo/simulate-pilot")

        demo_summary = test_client.get("/api/v1/metrics/summary").json()
        assert demo_summary["totalCases"] == 10

        tenant_b_key = "sk-tenant-b-metrics-key"
        with Session(engine) as session:
            session.add(ApiKey(key_hash=_hash_key(tenant_b_key), key_prefix=tenant_b_key[:8], tenant_id="isolated-tenant", name="Isolated"))
            session.commit()

        client_b = _client_with_key(tenant_b_key)
        isolated_summary = client_b.get("/api/v1/metrics/summary").json()
        assert isolated_summary["totalCases"] == 0

    def test_by_tenant_rejects_cross_tenant(self, test_client):
        resp = test_client.get("/api/v1/metrics/by-tenant/some-other-tenant")
        assert resp.status_code == 403


# ── Rate limiting ─────────────────────────────────────────────────────────

class TestRateLimiting:
    def test_rate_limit_triggers_429(self, monkeypatch):
        import backend.app.core.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_RATE_LIMIT", 3)
        auth_mod._rate_counts.clear()

        c = _client_with_key(DEMO_API_KEY)
        for i in range(3):
            resp = c.get("/api/v1/cases")
            assert resp.status_code == 200, f"Request {i+1} should succeed"

        resp = c.get("/api/v1/cases")
        assert resp.status_code == 429
        assert "Rate limit" in resp.json()["detail"]

        monkeypatch.setattr(auth_mod, "_RATE_LIMIT", 100)
        auth_mod._rate_counts.clear()


# ── Admin endpoints ───────────────────────────────────────────────────────

class TestAdminEndpoints:
    def test_create_api_key(self):
        c = _client_with_key(DEMO_API_KEY)
        resp = c.post("/api/v1/admin/api-keys", json={
            "tenantId": "new-tenant",
            "name": "New Key",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"].startswith("sk-")
        assert data["tenantId"] == "new-tenant"
        assert data["isActive"] is True

    def test_list_api_keys(self):
        c = _client_with_key(DEMO_API_KEY)
        resp = c.get("/api/v1/admin/api-keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert len(keys) >= 1
        assert all("tenantId" in k for k in keys)

    def test_created_key_works(self, test_client):
        test_client.post("/api/v1/demo/reset")

        c = _client_with_key(DEMO_API_KEY)
        create_resp = c.post("/api/v1/admin/api-keys", json={
            "tenantId": "functional-tenant",
            "name": "Functional Test",
        })
        new_key = create_resp.json()["key"]

        client = _client_with_key(new_key)
        resp = client.get("/api/v1/cases")
        assert resp.status_code == 200
        assert resp.json() == []
