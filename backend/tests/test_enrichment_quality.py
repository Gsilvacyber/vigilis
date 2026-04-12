"""Tests for the enrichment quality fix + diagnostic dashboard.

Covers:
- TestHistoricalSignalFix: host_repeat_target and repeat_offender fire only
  on recent (6h) confirmed threats — not on any historical case count
- TestEnrichmentQualityEndpoint: /api/v1/metrics/enrichment-quality returns
  the correct shape with score histogram, signals-per-case, noisy signals,
  and quality score
- TestEnrichmentQualityService: unit tests for compute_enrichment_quality()
  that seed cases with known properties and assert the computed metrics
- TestMetricsHtmlContract: the metrics.html page contains the new section
  markup and the renderEnrichmentQuality function
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlmodel import Session, SQLModel, select

from backend.app.core.db import engine
from backend.app.db.models import (
    Case as CaseRow,
    CaseConfidenceSignal,
    Tenant as TenantRow,
)
from backend.app.services.enrichment.historical import (
    check_hostname_history,
    check_user_history,
)
from backend.app.services.metrics_service import compute_enrichment_quality


# ─── Fixtures / helpers ──────────────────────────────────────────────────

@pytest.fixture
def fresh_db():
    """Wipe tables so each test starts clean (bypasses session scope)."""
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        for row in s.exec(select(CaseConfidenceSignal)).all():
            s.delete(row)
        for row in s.exec(select(CaseRow)).all():
            s.delete(row)
        for row in s.exec(select(TenantRow)).all():
            s.delete(row)
        s.commit()
    yield


def _make_tenant(session: Session, tenant_id: str = "t-quality") -> TenantRow:
    t = TenantRow(
        tenant_id=tenant_id,
        customer_name="QualityCo",
        customer_environment="prod",
    )
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


def _make_case(
    session: Session,
    tenant: TenantRow,
    hostname: str = "test-host",
    user_upn: str = "alice@example.com",
    event_time: datetime | None = None,
    confidence_score: int = 50,
    disposition: str = "open",
    alert_type: str = "identity.suspiciousSignIn",
    signals: list[tuple[str, int]] | None = None,
) -> CaseRow:
    now = datetime.now(timezone.utc)
    ts = event_time or now
    case = CaseRow(
        tenant_id=tenant.id,
        alert_type=alert_type,
        title="test",
        description="test",
        severity="medium",
        event_time=ts,
        ingested_time=ts,
        enriched_time=ts,
        created_at=ts,
        confidence_score=confidence_score,
        confidence_label="medium",
        disposition_status=disposition,
        entities={
            "identity": {"upn": user_upn},
            "device": {"hostname": hostname},
        },
    )
    session.add(case)
    session.flush()
    for name, weight in (signals or []):
        session.add(CaseConfidenceSignal(
            case_id=case.id,
            signal=name,
            weight=weight,
        ))
    session.commit()
    session.refresh(case)
    return case


# ─── TestHistoricalSignalFix ─────────────────────────────────────────────

class TestHistoricalSignalFix:
    """The two broken signals should now require recent (6h) confirmed
    threats instead of any-history-in-30d."""

    def test_host_repeat_target_does_not_fire_on_old_history(self, fresh_db):
        """50 old cases on a host with no recent confirmed threats → no fire."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            # Create 50 cases from 20 days ago, all un-dispositioned and mid-score
            for i in range(50):
                _make_case(s, tenant,
                           hostname="ancient-host",
                           event_time=now - timedelta(days=20),
                           confidence_score=65,
                           disposition="open")

        signals = check_hostname_history(
            "ancient-host",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        signal_names = {s.name for s in signals}
        assert "host_repeat_target" not in signal_names

    def test_host_repeat_target_does_not_fire_on_recent_low_confidence(self, fresh_db):
        """Many recent cases but none meeting the confirmed-threat bar → no fire."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            for i in range(10):
                _make_case(s, tenant,
                           hostname="noisy-host",
                           event_time=now - timedelta(hours=2),
                           confidence_score=65,  # below 85 threshold
                           disposition="open")

        signals = check_hostname_history(
            "noisy-host",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        assert "host_repeat_target" not in {s.name for s in signals}

    def test_host_repeat_target_fires_on_recent_dispositioned_threats(self, fresh_db):
        """2+ recent cases dispositioned as true_positive → signal fires."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            # 3 recent TP cases on the same host
            for i in range(3):
                _make_case(s, tenant,
                           hostname="compromised-host",
                           event_time=now - timedelta(hours=2),
                           confidence_score=70,
                           disposition="true_positive")

        signals = check_hostname_history(
            "compromised-host",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        fired = [s for s in signals if s.name == "host_repeat_target"]
        assert len(fired) == 1
        assert fired[0].fired is True
        assert fired[0].tier == "verified"
        assert "confirmed" in fired[0].label.lower()

    def test_host_repeat_target_does_NOT_fire_on_high_score_without_disposition(self, fresh_db):
        """High-scoring cases without analyst disposition should NOT fire.

        Previously the signal used `confidence_score >= 85` as a fallback,
        which created a cascade effect during re-enrichment (high-scoring
        cases trigger the signal for nearby cases, inflating their scores,
        which triggers the signal for even more cases). Now it's
        disposition-only: only analyst-confirmed TP/escalated cases count.
        """
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            for i in range(2):
                _make_case(s, tenant,
                           hostname="active-threat",
                           event_time=now - timedelta(hours=1),
                           confidence_score=90,
                           disposition="open")  # open, not dispositioned

        signals = check_hostname_history(
            "active-threat",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        # Should NOT fire — open cases don't count as confirmed threats
        assert "host_repeat_target" not in {s.name for s in signals}

    def test_host_repeat_target_6h_window_expires(self, fresh_db):
        """Recent-ish cases that are OUTSIDE the 6h window → no fire."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            # 2 TP cases from 12h ago — outside the 6h window
            for i in range(2):
                _make_case(s, tenant,
                           hostname="aging-host",
                           event_time=now - timedelta(hours=12),
                           confidence_score=90,
                           disposition="true_positive")

        signals = check_hostname_history(
            "aging-host",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        assert "host_repeat_target" not in {s.name for s in signals}

    def test_repeat_offender_same_semantics_for_users(self, fresh_db):
        """repeat_offender fires on 2+ recent confirmed threats for a user."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            for i in range(3):
                _make_case(s, tenant,
                           user_upn="evil@example.com",
                           event_time=now - timedelta(hours=3),
                           confidence_score=90,
                           disposition="escalated")

        signals = check_user_history(
            "evil@example.com",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        fired = [s for s in signals if s.name == "repeat_offender"]
        assert len(fired) == 1
        assert fired[0].tier == "verified"

    def test_repeat_offender_does_not_fire_on_open_low_score(self, fresh_db):
        """Classic noise case — 30 recent open cases, all mid-score → no fire."""
        with Session(engine) as s:
            tenant = _make_tenant(s)
            now = datetime.now(timezone.utc)
            for i in range(30):
                _make_case(s, tenant,
                           user_upn="bob@example.com",
                           event_time=now - timedelta(hours=1),
                           confidence_score=65,
                           disposition="open")

        signals = check_user_history(
            "bob@example.com",
            event_time=datetime.now(timezone.utc),
            tenant_id="t-quality",
        )
        assert "repeat_offender" not in {s.name for s in signals}


# ─── TestEnrichmentQualityService ────────────────────────────────────────

class TestEnrichmentQualityService:
    """Unit tests for compute_enrichment_quality() with seeded cases."""

    def test_empty_tenant_returns_zero(self, fresh_db):
        with Session(engine) as s:
            _make_tenant(s)
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            assert result["totalCases"] == 0
            assert result["qualityScore"] is None

    def test_score_histogram_buckets_correctly(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # Seed cases into known buckets
            for score in [95, 95, 85, 75, 75, 65, 65, 65, 55, 15]:
                _make_case(s, tenant, confidence_score=score)
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            hist = result["scoreHistogram"]
            assert hist["90-100"] == 2
            assert hist["80-89"] == 1
            assert hist["70-79"] == 2
            assert hist["60-69"] == 3
            assert hist["50-59"] == 1
            assert hist["0-19"] == 1
            assert result["totalCases"] == 10

    def test_signals_per_case_histogram(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            _make_case(s, tenant, signals=[])
            _make_case(s, tenant, signals=[("sig_a", 10)])
            _make_case(s, tenant, signals=[("sig_a", 10), ("sig_b", 12)])
            _make_case(s, tenant, signals=[
                ("sig_a", 10), ("sig_b", 12), ("sig_c", 15),
                ("sig_d", 8), ("sig_e", 20), ("sig_f", 14),
            ])
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            spc = result["signalsPerCase"]
            assert spc["0"] == 1
            assert spc["1"] == 1
            assert spc["2"] == 1
            assert spc["6+"] == 1

    def test_noisy_signals_flagged_above_50pct(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # 10 cases total, 6 with "spam_signal" = 60% → noisy
            for i in range(10):
                sigs = [("spam_signal", 10)] if i < 6 else []
                _make_case(s, tenant, signals=sigs)
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            noisy = result["noisySignals"]
            assert any(n["name"] == "spam_signal" for n in noisy)
            spam = [n for n in noisy if n["name"] == "spam_signal"][0]
            assert spam["fires"] == 6
            assert spam["pctOfCases"] == 60.0

    def test_noisy_signal_not_flagged_below_50pct(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # 10 cases, only 4 have the signal = 40% → NOT noisy
            for i in range(10):
                sigs = [("medium_signal", 10)] if i < 4 else []
                _make_case(s, tenant, signals=sigs)
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            assert not any(n["name"] == "medium_signal" for n in result["noisySignals"])

    def test_per_alert_type_compressed_variance(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # 100 cases all scoring exactly 65 → stddev 0 → compressed
            for i in range(100):
                _make_case(s, tenant,
                           alert_type="endpoint.powershellExecution",
                           confidence_score=65)
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            pat = result["perAlertType"]
            assert len(pat) >= 1
            entry = next(p for p in pat if p["alertType"] == "endpoint.powershellExecution")
            assert entry["count"] == 100
            assert entry["stddev"] == 0.0
            assert entry["compressed"] is True

    def test_quality_score_penalizes_bunched_noisy_data(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # 120 cases, all scoring 65 (bunched), all firing 2 noisy signals
            for i in range(120):
                _make_case(s, tenant,
                           alert_type="endpoint.powershellExecution",
                           confidence_score=65,
                           signals=[
                               ("noisy_a", 10),
                               ("noisy_b", 10),
                               ("real_sig", 15),
                           ])
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            # Expect: bunched (stddev=0), 3 noisy signals all 100%, compressed
            assert result["qualityScore"] < 50
            assert result["scoreStddev"] == 0.0
            assert len(result["noisySignals"]) >= 2

    def test_quality_score_rewards_good_spread(self, fresh_db):
        with Session(engine) as s:
            tenant = _make_tenant(s)
            # Create wide score spread with diverse signals, no noise
            for i, score in enumerate([20, 30, 40, 50, 60, 70, 80, 90, 100] * 3):
                _make_case(s, tenant,
                           alert_type=f"endpoint.type{i%5}",
                           confidence_score=score,
                           signals=[
                               (f"rare_sig_{i%7}", 10),
                               (f"another_{i%5}", 12),
                               (f"third_{i%3}", 8),
                               (f"fourth_{i%4}", 15),
                           ])
            result = compute_enrichment_quality(s, tenant_id="t-quality")
            # Wide spread + rare signals + no bunching = high quality
            assert result["qualityScore"] >= 60
            assert result["scoreStddev"] > 15


# ─── TestEnrichmentQualityEndpoint ───────────────────────────────────────

class TestEnrichmentQualityEndpoint:

    def test_endpoint_returns_200_and_expected_keys(self, test_client):
        resp = test_client.get("/api/v1/metrics/enrichment-quality")
        assert resp.status_code == 200
        body = resp.json()
        # Either empty tenant or populated — both should have these keys
        assert "totalCases" in body
        if body["totalCases"] > 0:
            assert "scoreHistogram" in body
            assert "signalsPerCase" in body
            assert "perAlertType" in body
            assert "noisySignals" in body
            assert "autoCloseRate" in body
            assert "qualityScore" in body
            assert "scoreStddev" in body

    def test_endpoint_requires_auth(self, raw_client):
        resp = raw_client.get("/api/v1/metrics/enrichment-quality")
        assert resp.status_code == 401


# ─── TestMetricsHtmlContract ─────────────────────────────────────────────

class TestMetricsHtmlContract:

    def test_metrics_html_has_enrichment_quality_section(self, test_client):
        resp = test_client.get("/demo/ui/metrics")
        assert resp.status_code == 200
        assert 'id="enrichment-quality-section"' in resp.text

    def test_metrics_html_fetches_new_endpoint(self, test_client):
        resp = test_client.get("/demo/ui/metrics")
        assert "/api/v1/metrics/enrichment-quality" in resp.text

    def test_metrics_html_has_render_function(self, test_client):
        resp = test_client.get("/demo/ui/metrics")
        assert "renderEnrichmentQuality" in resp.text

    def test_metrics_html_has_noisy_signals_warning(self, test_client):
        resp = test_client.get("/demo/ui/metrics")
        assert "Noisy Signals" in resp.text
