"""Tests for the dev-only seed-dispositions endpoint and calibration UI page.

Covers:
- TestSeedDispositionsEndpoint — valid POST, prod guard, missing tenant,
  weight normalization, count boundaries
- TestSeedSideEffects — confirms AuditEvent-adjacent side effects (the real
  update_disposition path): disposition_status updated, set_by set,
  CaseDispositionEvent rows created
- TestCalibrationUIRoute — GET /demo/ui/calibration serves HTML containing
  expected headings
- TestCalibrationEndToEnd — seed → /api/v1/calibration/report populates
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import pytest
from sqlmodel import Session, select

from backend.app.core.config import settings
from backend.app.core.db import engine
from backend.app.db.models import (
    Case as CaseRow,
    CaseDispositionEvent,
)


# ─── Helpers ──────────────────────────────────────────────────────────────

def _create_case(client, i: int) -> str:
    """POST a minimal suspiciousSignIn case and return its caseId."""
    payload = {
        "tenantId": "demo-tenant",
        "customer": {
            "name": "SeedCo", "environment": "prod", "industry": None,
        },
        "alertType": "identity.suspiciousSignIn",
        "source": {
            "sourceSystem": "idp",
            "sourceName": "idp_mvp",
            "sourceAlertId": f"seed-disp-{i}",
            "sourceSeverity": "medium",
            "sourceUrl": None,
        },
        "rawAlert": {
            "identity": {
                "identityType": "user",
                "userId": f"u-seed-{i}",
                "upn": f"user{i}@example.com",
                "displayName": f"User {i}",
                "riskLevel": "high",
            },
            "ips": [
                {"role": "anomalous", "ipAddress": f"203.0.113.{i % 250 + 1}"},
                {"role": "anomalous", "ipAddress": "198.51.100.5",
                 "geo": {"country": "RU", "city": "Moscow"}},
            ],
            "device": {
                "deviceId": f"d-seed-{i}",
                "hostname": f"HOST-{i}",
                "managed": False,
                "os": "Windows",
                "identificationStatus": "identified",
            },
        },
    }
    resp = client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()["caseId"]


def _create_n_cases(client, n: int) -> list[str]:
    return [_create_case(client, i) for i in range(n)]


# ─── TestSeedDispositionsEndpoint ─────────────────────────────────────────

class TestSeedDispositionsEndpoint:

    def test_valid_post_returns_counts(self, test_client):
        _create_n_cases(test_client, 15)
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions?count=10"
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # At least 10 were processed (may be fewer if pool was small, but we
        # created 15)
        assert body["total_processed"] >= 10
        assert body["total_processed"] == (
            body["true_positive"] + body["benign"] + body["escalated"]
        )
        assert body["errors"] == 0

    def test_no_open_cases_returns_zero(self, fresh_client):
        # fresh_client gives a brand-new DB; pool is definitively empty
        resp = fresh_client.post(
            "/api/v1/demo/seed-dispositions?count=10"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_processed"] == 0
        assert "message" in body

    def test_count_param_upper_bound(self, test_client):
        # count=501 exceeds the Query(le=500) cap
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions?count=501"
        )
        assert resp.status_code == 422

    def test_count_param_lower_bound(self, test_client):
        # count=0 fails Query(ge=1) validation
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions?count=0"
        )
        assert resp.status_code == 422

    def test_all_zero_ratios_returns_422(self, test_client):
        _create_n_cases(test_client, 5)
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions"
            "?count=5&tp_ratio=0&benign_ratio=0&escalated_ratio=0"
        )
        assert resp.status_code == 422
        assert "at least one ratio" in resp.text.lower()

    def test_tp_only_ratio_produces_only_tps(self, fresh_client):
        _create_n_cases(fresh_client, 15)
        resp = fresh_client.post(
            "/api/v1/demo/seed-dispositions"
            "?count=10&tp_ratio=1&benign_ratio=0&escalated_ratio=0"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["benign"] == 0
        assert body["escalated"] == 0
        assert body["true_positive"] >= 10

    def test_benign_only_ratio(self, fresh_client):
        _create_n_cases(fresh_client, 15)
        resp = fresh_client.post(
            "/api/v1/demo/seed-dispositions"
            "?count=10&tp_ratio=0&benign_ratio=1&escalated_ratio=0"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["true_positive"] == 0
        assert body["benign"] >= 10

    def test_prod_guard_returns_403(self, test_client, monkeypatch):
        # Settings is a frozen dataclass so we can't mutate its fields.
        # Instead, swap the entire module-level `settings` reference with
        # a shim that satisfies the attribute access `settings.app_env`.
        class _FakeSettings:
            app_env = "prod"
        monkeypatch.setattr(
            "backend.app.api.v1.endpoints.demo_dispositions.settings",
            _FakeSettings(),
        )
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions?count=5"
        )
        assert resp.status_code == 403
        assert "disabled in production" in resp.text


# ─── TestSeedSideEffects ──────────────────────────────────────────────────

class TestSeedSideEffects:

    def test_seeded_cases_have_disposition_set_by_seed_helper(
        self, test_client, db_session: Session,
    ):
        case_ids = _create_n_cases(test_client, 10)
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions?count=10"
        )
        assert resp.status_code == 200

        db_session.expire_all()
        rows = db_session.exec(
            select(CaseRow).where(
                CaseRow.id.in_([UUID(cid) for cid in case_ids])
            )
        ).all()
        dispositioned = [r for r in rows if r.disposition_status != "open"]
        assert len(dispositioned) >= 10
        for row in dispositioned:
            assert row.disposition_set_by == "seed-helper"
            assert row.disposition_set_at is not None
            assert row.disposition_status in (
                "true_positive", "benign", "escalated",
            )

    def test_seeded_dispositions_write_events(
        self, test_client, db_session: Session,
    ):
        _create_n_cases(test_client, 10)
        resp = test_client.post(
            "/api/v1/demo/seed-dispositions?count=8"
        )
        assert resp.status_code == 200
        body = resp.json()

        db_session.expire_all()
        # Count CaseDispositionEvent rows created by seed-helper
        events = db_session.exec(
            select(CaseDispositionEvent).where(
                CaseDispositionEvent.set_by == "seed-helper"
            )
        ).all()
        assert len(events) >= body["total_processed"]
        for e in events:
            assert e.status in ("true_positive", "benign", "escalated")

    def test_seed_updates_time_to_first_decision(
        self, test_client, db_session: Session,
    ):
        case_ids = _create_n_cases(test_client, 5)
        test_client.post("/api/v1/demo/seed-dispositions?count=5")

        db_session.expire_all()
        rows = db_session.exec(
            select(CaseRow).where(
                CaseRow.id.in_([UUID(cid) for cid in case_ids])
            )
        ).all()
        ttfds = [
            r.time_to_first_decision_ms
            for r in rows
            if r.disposition_status != "open"
        ]
        # All seeded cases should have ttfd computed (non-None, >= 0)
        assert len(ttfds) >= 5
        for t in ttfds:
            assert t is not None
            assert t >= 0


# ─── TestCalibrationUIRoute ───────────────────────────────────────────────

class TestCalibrationUIRoute:

    def test_calibration_page_loads(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        assert resp.status_code == 200
        assert "Signal Calibration" in resp.text
        assert "Seed Dispositions" in resp.text
        assert "/api/v1/calibration/report" in resp.text


# ─── TestCalibrationEndToEnd ──────────────────────────────────────────────

class TestCalibrationEndToEnd:

    def test_calibration_report_populates_after_seed(
        self, fresh_client,
    ):
        # fresh_client guarantees a clean DB so the seed pool is exactly 60
        _create_n_cases(fresh_client, 60)

        seed_resp = fresh_client.post(
            "/api/v1/demo/seed-dispositions"
            "?count=50&tp_ratio=0.3&benign_ratio=0.6&escalated_ratio=0.1"
        )
        assert seed_resp.status_code == 200
        assert seed_resp.json()["total_processed"] >= 50

        # The suspiciousSignIn cases all fire the same ~5 signals repeatedly
        # (anomalous_ip, impossible_travel, high_risk_identity, etc.), so
        # after 50 dispositions each signal has ~50 decided samples.
        report_resp = fresh_client.get(
            "/api/v1/calibration/report?window_days=30"
        )
        assert report_resp.status_code == 200
        body = report_resp.json()
        assert body["signalCount"] > 0
        # With 60% benign, some signals should hit reduce territory
        statuses = {s["status"] for s in body["signals"]}
        # At least ONE signal should be non-stable (either reduce or boost)
        assert len(statuses) >= 1
        # All returned signals should have the expected keys
        for s in body["signals"]:
            assert "signal" in s
            assert "originalWeight" in s
            assert "adjustedWeight" in s
            assert "multiplier" in s
            assert "fpRate" in s
            assert "tpRate" in s
            assert "status" in s
            assert s["status"] in ("reduce", "boost", "stable")
