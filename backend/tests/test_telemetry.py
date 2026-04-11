"""Tests for Phase 5: Signal Telemetry Analytics.

Covers: TelemetryCollector recording, in-memory buffer, DB persistence,
analytics methods (signal_frequency, signal_effectiveness, weight_impact,
false_positive_rate), and the telemetry dashboard endpoint.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest
from sqlmodel import select

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.telemetry import TelemetryCollector, get_collector
from backend.app.services.enrichment import enrich, get_telemetry
from backend.app.services.enrichment.cross_alert import reset_scanner
from backend.app.db.models import CalibrationFeedback, SignalTelemetry
from sqlalchemy import text


def _utc() -> datetime:
    return datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc)


# ── TelemetryCollector Unit Tests ────────────────────────────────────

class TestTelemetryCollector:
    def setup_method(self):
        self.collector = get_collector()
        self.collector.clear_buffer()
        reset_scanner()

    def test_record_adds_to_buffer(self):
        signals = [
            Signal("anomalous_ip", 12, True, "Anomalous IP"),
            Signal("external_geo", 8, True, "External geo"),
            Signal("safe_ip", 0, False, "Safe IP"),
        ]
        entry = self.collector.record(
            "identity.suspiciousSignIn", "medium", signals, 45, "sentinel")
        assert entry["alert_type"] == "identity.suspiciousSignIn"
        assert entry["signals_fired"] == ["anomalous_ip", "external_geo"]
        assert entry["signal_count"] == 2
        assert entry["confidence_score"] == 45
        assert entry["source_tool"] == "sentinel"

    def test_record_includes_asset_and_user_tiers(self):
        entry = self.collector.record(
            "endpoint.malwareDetection", "high", [], 70, None,
            asset_tier="critical", user_risk_tier="critical_user")
        assert entry["asset_tier"] == "critical"
        assert entry["user_risk_tier"] == "critical_user"

    def test_record_includes_cross_alert_flags(self):
        entry = self.collector.record(
            "identity.suspiciousSignIn", "medium", [], 50, None,
            cross_alert_flags=["_multiVectorAttack"])
        assert entry["cross_alert_flags"] == ["_multiVectorAttack"]

    def test_buffer_capped_at_max(self):
        from backend.app.services.enrichment.telemetry import _TELEMETRY, _TELEMETRY_MAX
        _TELEMETRY.clear()
        original_persist = self.collector._persist
        self.collector._persist = lambda entry: None
        try:
            for i in range(_TELEMETRY_MAX + 100):
                self.collector.record(f"type.{i}", "low", [], i, None)
            assert len(_TELEMETRY) <= _TELEMETRY_MAX
        finally:
            self.collector._persist = original_persist

    def test_get_buffer_returns_copy(self):
        self.collector.record("identity.test", "low", [], 10, None)
        buf = self.collector.get_buffer()
        assert isinstance(buf, list)
        assert len(buf) >= 1
        buf.clear()
        assert len(self.collector.get_buffer()) >= 1

    def test_clear_buffer(self):
        self.collector.record("identity.test", "low", [], 10, None)
        self.collector.clear_buffer()
        assert len(self.collector.get_buffer()) == 0

    def test_unknown_source_tool_defaults(self):
        entry = self.collector.record("identity.test", "low", [], 10, None)
        assert entry["source_tool"] == "unknown"


# ── DB Persistence ───────────────────────────────────────────────────

class TestDBPersistence:
    @pytest.fixture(autouse=True)
    def setup(self, fresh_client, db_session):
        self.client = fresh_client
        self.session = db_session
        self.collector = get_collector()
        self.collector.clear_buffer()
        reset_scanner()

    def test_record_persists_to_db(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP")]
        self.collector.record(
            "identity.suspiciousSignIn", "medium", signals, 37, "crowdstrike",
            asset_tier="high", user_risk_tier="standard_user")

        records = self.session.exec(select(SignalTelemetry)).all()
        assert len(records) >= 1
        latest = records[-1]
        assert latest.alert_type == "identity.suspiciousSignIn"
        assert latest.confidence_score == 37
        assert latest.asset_tier == "high"
        assert "anomalous_ip" in latest.signals_fired

    def test_enrichment_pipeline_persists_telemetry(self):
        raw = {
            "identity": {"upn": "teltest@corp.com", "displayName": "Tel Test"},
            "ips": [{"ipAddress": "8.8.8.8", "role": "observed"}],
            "device": {"hostname": "WS-01"},
        }
        enrich("identity.suspiciousSignIn", "medium", raw, _utc())

        records = self.session.exec(select(SignalTelemetry)).all()
        assert len(records) >= 1

    def test_multiple_enrichments_create_multiple_records(self):
        for i in range(3):
            raw = {
                "identity": {"upn": f"batch{i}@corp.com"},
                "device": {"hostname": f"WS-{i}"},
                "ips": [],
            }
            enrich("identity.suspiciousSignIn", "medium", raw, _utc())

        records = self.session.exec(select(SignalTelemetry)).all()
        assert len(records) >= 3


# ── Analytics Methods ────────────────────────────────────────────────

class TestAnalytics:
    @pytest.fixture(autouse=True)
    def setup(self, fresh_client, db_session):
        self.client = fresh_client
        self.session = db_session
        self.collector = get_collector()
        self.collector.clear_buffer()
        reset_scanner()

    def test_signal_frequency(self):
        signals = [
            Signal("anomalous_ip", 12, True, "Anomalous IP"),
            Signal("impossible_travel", 25, True, "Impossible travel"),
        ]
        self.collector.record("identity.test", "medium", signals, 50, None)
        self.collector.record("identity.test", "medium",
                              [Signal("anomalous_ip", 12, True, "Anomalous IP")], 30, None)

        freq = self.collector.signal_frequency(window_hours=1)
        assert freq.get("anomalous_ip", 0) == 2
        assert freq.get("impossible_travel", 0) == 1

    def test_signal_effectiveness_with_calibration(self):
        self.session.add(CalibrationFeedback(
            case_id="c1", analyst_verdict="true_positive",
            alert_type="identity.test", signals_fired=["anomalous_ip", "external_geo"]))
        self.session.add(CalibrationFeedback(
            case_id="c2", analyst_verdict="false_positive",
            alert_type="identity.test", signals_fired=["anomalous_ip"]))
        self.session.commit()

        eff = self.collector.signal_effectiveness()
        assert "anomalous_ip" in eff
        assert eff["anomalous_ip"]["tp_count"] == 1
        assert eff["anomalous_ip"]["fp_count"] == 1
        assert eff["anomalous_ip"]["precision"] == 0.5

    def test_signal_effectiveness_empty(self):
        eff = self.collector.signal_effectiveness()
        assert eff == {}

    def test_weight_impact_analysis(self):
        signals = [Signal("impossible_travel", 25, True, "Impossible travel")]
        for _ in range(3):
            self.collector.record("identity.test", "high", signals, 80, None)

        impacts = self.collector.weight_impact_analysis(window_hours=1)
        it_impact = next((i for i in impacts if i["signal"] == "impossible_travel"), None)
        assert it_impact is not None
        assert it_impact["fire_count"] == 3
        assert it_impact["total_impact"] == 75  # 25 * 3

    def test_false_positive_rate_none_without_feedback(self):
        rate = self.collector.false_positive_rate()
        assert rate is None

    def test_false_positive_rate_computed(self):
        self.session.add(CalibrationFeedback(
            case_id="c1", analyst_verdict="true_positive", alert_type="test"))
        self.session.add(CalibrationFeedback(
            case_id="c2", analyst_verdict="false_positive", alert_type="test"))
        self.session.add(CalibrationFeedback(
            case_id="c3", analyst_verdict="true_positive", alert_type="test"))
        self.session.commit()

        rate = self.collector.false_positive_rate()
        assert rate == round(1 / 3, 4)


# ── get_telemetry backward compatibility ─────────────────────────────

class TestGetTelemetryCompat:
    def test_get_telemetry_returns_list(self):
        collector = get_collector()
        collector.clear_buffer()
        collector.record("identity.test", "low", [], 10, None)
        result = get_telemetry()
        assert isinstance(result, list)
        assert len(result) >= 1
        assert result[-1]["alert_type"] == "identity.test"


# ── Telemetry Dashboard Endpoint ─────────────────────────────────────

class TestTelemetryDashboard:
    @pytest.fixture(autouse=True)
    def setup(self, fresh_client, db_session):
        self.client = fresh_client
        self.session = db_session
        self.session.exec(text("DELETE FROM signal_telemetry"))
        self.session.commit()
        self.collector = get_collector()
        self.collector.clear_buffer()
        reset_scanner()

    def test_empty_dashboard(self):
        resp = self.client.get("/api/v1/telemetry/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_enrichments"] == 0
        assert data["avg_confidence"] is None

    def test_dashboard_after_enrichments(self):
        for i in range(5):
            raw = {
                "identity": {"upn": f"dash{i}@corp.com"},
                "device": {"hostname": f"WS-{i}"},
                "ips": [{"ipAddress": f"8.8.{i}.{i}", "role": "observed"}],
            }
            enrich("identity.suspiciousSignIn", "medium", raw, _utc())

        resp = self.client.get("/api/v1/telemetry/dashboard?window_hours=1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_enrichments"] >= 5
        assert data["avg_confidence"] is not None
        assert "signal_frequency" in data
        assert "alert_type_distribution" in data
        assert "asset_tier_distribution" in data
        assert "top_signals_by_impact" in data

    def test_dashboard_score_distribution(self):
        signals_high = [Signal("impossible_travel", 25, True, "IT"),
                        Signal("anomalous_ip", 12, True, "AIP")]
        self.collector.record("identity.test", "critical", signals_high, 92, None)
        self.collector.record("identity.test", "low", [], 10, None)

        resp = self.client.get("/api/v1/telemetry/dashboard?window_hours=1")
        data = resp.json()
        dist = data["score_distribution"]
        assert dist["critical"] >= 1
        assert dist["low"] >= 1

    def test_dashboard_custom_window(self):
        resp = self.client.get("/api/v1/telemetry/dashboard?window_hours=48")
        assert resp.status_code == 200
        data = resp.json()
        assert data["window_hours"] == 48
