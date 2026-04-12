"""Tests for the case re-enrichment service + admin endpoint.

Covers:
- TestReenrichCase: service function updates score, preserves disposition,
  deletes + re-inserts signal rows, writes audit log
- TestRawAlertPreservation: new cases stash raw_alert in audit JSON
- TestReenrichmentEndpoint: admin POST endpoint with auth, aggregation stats
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest
from sqlmodel import Session, SQLModel, select

from backend.app.core.db import engine
from backend.app.db.models import (
    AuditEvent,
    Case as CaseRow,
    CaseConfidenceSignal,
    Tenant as TenantRow,
)
from backend.app.services.case_service import reenrich_case


# ─── Helpers ──────────────────────────────────────────────────────────────

def _create_test_case(client, suffix: str = "r1") -> str:
    """POST a case via the API so it flows through the full create_case path
    (including the new raw_alert preservation in audit)."""
    payload = {
        "tenantId": "demo-tenant",
        "customer": {
            "name": "ReenrichCo", "environment": "prod", "industry": None,
        },
        "alertType": "identity.suspiciousSignIn",
        "source": {
            "sourceSystem": "idp",
            "sourceName": "idp_mvp",
            "sourceAlertId": f"reenrich-{suffix}",
            "sourceSeverity": "medium",
            "sourceUrl": None,
        },
        "rawAlert": {
            "identity": {
                "identityType": "user",
                "userId": f"u-{suffix}",
                "upn": f"user-{suffix}@example.com",
                "displayName": f"User {suffix}",
                "riskLevel": "high",
            },
            "ips": [
                {"role": "anomalous", "ipAddress": "203.0.113.10",
                 "geo": {"country": "US"}},
                {"role": "anomalous", "ipAddress": "198.51.100.5",
                 "geo": {"country": "RU"}},
            ],
            "device": {
                "deviceId": f"d-{suffix}",
                "hostname": f"HOST-{suffix}",
                "managed": False,
                "os": "Windows",
                "identificationStatus": "identified",
            },
        },
    }
    resp = client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 200, resp.text
    return resp.json()["caseId"]


# ─── TestRawAlertPreservation ────────────────────────────────────────────

class TestRawAlertPreservation:
    """New cases should stash the raw alert dict + original alert_type/severity
    in the audit JSON so re-enrichment can work cleanly."""

    def test_new_case_preserves_raw_alert_in_audit(self, fresh_client):
        case_id_str = _create_test_case(fresh_client, "preserved")
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id_str))
            ).first()
            assert case is not None
            audit = case.audit or {}
            assert "_rawAlertPreserved" in audit
            preserved = audit["_rawAlertPreserved"]
            assert isinstance(preserved, dict)
            # The preserved dict should contain the original request fields
            assert preserved.get("identity", {}).get("upn") == "user-preserved@example.com"
            assert preserved.get("device", {}).get("hostname") == "HOST-preserved"
            # Original alert type + severity also preserved
            assert audit.get("_originalAlertType") == "identity.suspiciousSignIn"
            assert audit.get("_originalSeverity") == "medium"


# ─── TestReenrichCase ────────────────────────────────────────────────────

class TestReenrichCase:
    """Service function: loads a case, re-runs enrichment, updates in place."""

    def test_reenrich_returns_success_with_scores(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc1")
        with Session(engine) as s:
            result = reenrich_case(s, UUID(case_id))
        assert result["success"] is True
        assert result["caseId"] == case_id
        assert "oldScore" in result
        assert "newScore" in result
        assert "delta" in result
        assert result["delta"] == result["newScore"] - result["oldScore"]

    def test_reenrich_preserves_disposition(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc2")
        # Disposition the case
        r = fresh_client.patch(
            f"/api/v1/cases/{case_id}/disposition",
            json={"status": "true_positive", "setBy": "tester", "notes": "confirmed"},
        )
        assert r.status_code == 200

        # Re-enrich
        with Session(engine) as s:
            reenrich_case(s, UUID(case_id), set_by="test")

        # Verify disposition is unchanged
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            assert case is not None
            assert case.disposition_status == "true_positive"
            assert case.disposition_set_by == "tester"
            assert case.disposition_set_at is not None
            assert case.disposition_notes == "confirmed"

    def test_reenrich_preserves_ttfd(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc3")
        # Create TTFD by dispositioning the case
        fresh_client.patch(
            f"/api/v1/cases/{case_id}/disposition",
            json={"status": "benign", "setBy": "analyst"},
        )
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            original_ttfd = case.time_to_first_decision_ms
            assert original_ttfd is not None

        # Re-enrich
        with Session(engine) as s:
            reenrich_case(s, UUID(case_id))

        # TTFD should be unchanged
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            assert case.time_to_first_decision_ms == original_ttfd

    def test_reenrich_preserves_created_at_and_event_time(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc4")
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            original_created = case.created_at
            original_event = case.event_time

        with Session(engine) as s:
            reenrich_case(s, UUID(case_id))

        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            assert case.created_at == original_created
            assert case.event_time == original_event

    def test_reenrich_updates_enriched_time(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc5")
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            original_enriched = case.enriched_time

        with Session(engine) as s:
            reenrich_case(s, UUID(case_id))

        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(case_id))
            ).first()
            # enriched_time should advance (or equal if clocks are too fast)
            assert case.enriched_time >= original_enriched

    def test_reenrich_deletes_and_reinserts_signal_rows(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc6")
        with Session(engine) as s:
            original_sigs = s.exec(
                select(CaseConfidenceSignal).where(
                    CaseConfidenceSignal.case_id == UUID(case_id)
                )
            ).all()
            original_count = len(original_sigs)
            assert original_count > 0

        with Session(engine) as s:
            reenrich_case(s, UUID(case_id))

        with Session(engine) as s:
            new_sigs = s.exec(
                select(CaseConfidenceSignal).where(
                    CaseConfidenceSignal.case_id == UUID(case_id)
                )
            ).all()
            # Should still have signals (not left empty)
            assert len(new_sigs) > 0
            # No internal _score_breakdown rows should exist in the DB
            assert all(not s.signal.startswith("_") for s in new_sigs)

    def test_reenrich_writes_audit_log(self, fresh_client):
        case_id = _create_test_case(fresh_client, "svc7")
        with Session(engine) as s:
            reenrich_case(s, UUID(case_id), set_by="test-actor")

        with Session(engine) as s:
            events = s.exec(
                select(AuditEvent).where(
                    AuditEvent.action == "case.re_enriched",
                    AuditEvent.resource_id == case_id,
                )
            ).all()
            assert len(events) >= 1
            event = events[0]
            assert event.actor == "test-actor"
            assert "oldScore" in event.details
            assert "newScore" in event.details
            assert "delta" in event.details

    def test_reenrich_missing_case_returns_not_found(self, fresh_client):
        fake_id = UUID("00000000-0000-0000-0000-000000000001")
        with Session(engine) as s:
            result = reenrich_case(s, fake_id)
        assert result["success"] is False
        assert result["error"] == "not_found"


# ─── TestReenrichmentEndpoint ────────────────────────────────────────────

class TestReenrichmentEndpoint:
    """POST /api/v1/admin/re-enrich aggregates stats across a batch of cases."""

    def test_endpoint_requires_admin(self, fresh_client, raw_client):
        # Create a case first
        _create_test_case(fresh_client, "ep1")
        # Try with no API key
        resp = raw_client.post("/api/v1/admin/re-enrich")
        assert resp.status_code == 401

    def test_endpoint_returns_summary_stats(self, fresh_client):
        for i in range(5):
            _create_test_case(fresh_client, f"ep2-{i}")

        resp = fresh_client.post("/api/v1/admin/re-enrich?window_days=14&max_count=10")
        assert resp.status_code == 200
        body = resp.json()
        assert "processed" in body
        assert "updated" in body
        assert "errors" in body
        assert "avg_score_before" in body
        assert "avg_score_after" in body
        assert "avg_delta" in body
        assert "score_increases" in body
        assert "score_decreases" in body
        assert body["processed"] >= 5
        assert body["updated"] >= 5

    def test_endpoint_respects_max_count(self, fresh_client):
        for i in range(10):
            _create_test_case(fresh_client, f"ep3-{i}")

        resp = fresh_client.post("/api/v1/admin/re-enrich?window_days=14&max_count=3")
        body = resp.json()
        assert body["processed"] == 3
        assert body["updated"] == 3

    def test_endpoint_filters_by_alert_type(self, fresh_client):
        for i in range(3):
            _create_test_case(fresh_client, f"ep4-{i}")

        resp = fresh_client.post(
            "/api/v1/admin/re-enrich?window_days=14&alert_type=identity.suspiciousSignIn&max_count=100"
        )
        body = resp.json()
        assert body["updated"] >= 3
        # Filter with a non-matching alert type → 0 cases touched
        resp2 = fresh_client.post(
            "/api/v1/admin/re-enrich?window_days=14&alert_type=endpoint.nonexistent&max_count=100"
        )
        body2 = resp2.json()
        assert body2["processed"] == 0

    def test_endpoint_preserves_dispositions_in_batch(self, fresh_client):
        """Re-enriching a batch doesn't clobber disposition state on any case."""
        case_ids = [
            _create_test_case(fresh_client, f"ep5-{i}") for i in range(3)
        ]
        # Disposition one of them
        target = case_ids[1]
        fresh_client.patch(
            f"/api/v1/cases/{target}/disposition",
            json={"status": "escalated", "setBy": "analyst"},
        )

        # Run re-enrich on the batch
        resp = fresh_client.post(
            "/api/v1/admin/re-enrich?window_days=14&max_count=10"
        )
        assert resp.status_code == 200

        # The dispositioned case should still be escalated
        with Session(engine) as s:
            case = s.exec(
                select(CaseRow).where(CaseRow.id == UUID(target))
            ).first()
            assert case.disposition_status == "escalated"
            assert case.disposition_set_by == "analyst"
