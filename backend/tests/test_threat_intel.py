"""Tests for Phase 4: Threat Intel Hooks.

Covers: StaticListProvider lookups (IP, domain, hash), provider protocol
compliance, ThreatIntelEnricher signal generation, pipeline integration,
and calibration feedback storage + stats calculation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from backend.app.services.enrichment.threat_intel import (
    StaticListProvider,
    ThreatIntelEnricher,
    ThreatIntelProvider,
    ThreatIntelResult,
    reset_threat_intel,
)
from backend.app.services.enrichment import enrich, enrich_debug


def _utc() -> datetime:
    return datetime(2026, 4, 2, 12, 0, 0, tzinfo=timezone.utc)


# ── Static List Provider ─────────────────────────────────────────────

class TestStaticListProvider:
    def setup_method(self):
        self.provider = StaticListProvider()

    def test_known_malicious_ip_detected(self):
        result = self.provider.check_ip("185.220.100.240")
        assert result is not None
        assert result.is_malicious is True
        assert "tor_exit_node" in result.tags or "known_malicious" in result.tags

    def test_tor_exit_node_detected(self):
        result = self.provider.check_ip("162.247.74.27")
        assert result is not None
        assert result.is_malicious is True
        assert "tor_exit_node" in result.tags

    def test_clean_ip_not_malicious(self):
        result = self.provider.check_ip("8.8.8.8")
        assert result is None or result.is_malicious is False

    def test_suspicious_domain_tld_detected(self):
        result = self.provider.check_domain("evil-site.tk")
        assert result is not None
        assert result.is_malicious is True

    def test_long_random_subdomain_detected(self):
        result = self.provider.check_domain("a" * 35 + ".evil.com")
        assert result is not None
        assert result.is_malicious is True

    def test_clean_domain_not_malicious(self):
        result = self.provider.check_domain("google.com")
        assert result is None or result.is_malicious is False

    def test_known_bad_hash_detected(self):
        result = self.provider.check_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert result is not None
        assert result.is_malicious is True
        assert "known_bad_hash" in result.tags

    def test_clean_hash_not_malicious(self):
        result = self.provider.check_hash("abcd1234" * 8)
        assert result is None or result.is_malicious is False


# ── Provider Protocol Compliance ─────────────────────────────────────

class TestProtocolCompliance:
    def test_static_list_is_provider(self):
        assert isinstance(StaticListProvider(), ThreatIntelProvider)

    def test_custom_provider_protocol(self):
        class CustomProvider:
            def check_ip(self, ip: str) -> ThreatIntelResult | None:
                return None
            def check_domain(self, domain: str) -> ThreatIntelResult | None:
                return None
            def check_hash(self, file_hash: str) -> ThreatIntelResult | None:
                return None

        assert isinstance(CustomProvider(), ThreatIntelProvider)


# ── ThreatIntelEnricher ──────────────────────────────────────────────

class TestThreatIntelEnricher:
    def test_enriches_known_malicious_ip(self):
        enricher = ThreatIntelEnricher()
        raw = {"ips": [{"ipAddress": "185.220.100.240"}]}
        signals = enricher.enrich(raw)
        names = {s.name for s in signals}
        assert "known_malicious_ip" in names or "tor_exit_node" in names

    def test_enriches_tor_exit_node(self):
        enricher = ThreatIntelEnricher()
        raw = {"ips": [{"ipAddress": "162.247.74.27"}]}
        signals = enricher.enrich(raw)
        names = {s.name for s in signals}
        assert "tor_exit_node" in names

    def test_enriches_suspicious_domain_from_context(self):
        enricher = ThreatIntelEnricher()
        raw = {"_additionalContext": "User visited phishing-site.tk and downloaded file"}
        signals = enricher.enrich(raw)
        names = {s.name for s in signals}
        assert "recently_registered_domain" in names

    def test_enriches_known_bad_hash(self):
        enricher = ThreatIntelEnricher()
        raw = {"file": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}
        signals = enricher.enrich(raw)
        names = {s.name for s in signals}
        assert "known_bad_hash" in names

    def test_deduplicates_signals(self):
        enricher = ThreatIntelEnricher()
        raw = {"ips": [
            {"ipAddress": "185.220.100.240"},
            {"ipAddress": "185.220.100.241"},
        ]}
        signals = enricher.enrich(raw)
        tor_count = sum(1 for s in signals if s.name == "tor_exit_node")
        assert tor_count <= 1

    def test_clean_alert_no_signals(self):
        enricher = ThreatIntelEnricher()
        raw = {"ips": [{"ipAddress": "8.8.8.8"}], "file": {"sha256": "abcd1234" * 8}}
        signals = enricher.enrich(raw)
        assert signals == []

    def test_private_ips_excluded(self):
        enricher = ThreatIntelEnricher()
        raw = {"ips": [{"ipAddress": "10.0.0.1"}, {"ipAddress": "192.168.1.1"}]}
        signals = enricher.enrich(raw)
        assert signals == []

    def test_multiple_providers(self):
        class AlwaysMaliciousProvider:
            def check_ip(self, ip: str) -> ThreatIntelResult | None:
                return ThreatIntelResult(
                    is_malicious=True, confidence=1.0,
                    source="custom", tags=["custom_threat"])
            def check_domain(self, domain: str) -> ThreatIntelResult | None:
                return None
            def check_hash(self, file_hash: str) -> ThreatIntelResult | None:
                return None

        enricher = ThreatIntelEnricher(providers=[StaticListProvider(), AlwaysMaliciousProvider()])
        raw = {"ips": [{"ipAddress": "1.2.3.4"}]}
        signals = enricher.enrich(raw)
        names = {s.name for s in signals}
        assert "custom_threat" in names

    def test_forwarding_domain_extraction(self):
        enricher = ThreatIntelEnricher()
        raw = {"mailbox": {"forwardingAddress": "evil@drop-site.tk"}}
        signals = enricher.enrich(raw)
        names = {s.name for s in signals}
        assert "recently_registered_domain" in names

    def test_signals_are_proper_signal_objects(self):
        enricher = ThreatIntelEnricher()
        raw = {"ips": [{"ipAddress": "162.247.74.27"}]}
        signals = enricher.enrich(raw)
        from backend.app.services.enrichment.base import Signal
        for s in signals:
            assert isinstance(s, Signal)
            assert s.fired is True
            assert s.weight > 0


# ── Pipeline Integration ─────────────────────────────────────────────

class TestPipelineIntegration:
    def test_threat_intel_signals_in_enrichment(self):
        reset_threat_intel()
        raw = {
            "identity": {"upn": "alice@corp.com", "displayName": "Alice"},
            "ips": [{"ipAddress": "162.247.74.27", "role": "anomalous", "geo": {"country": "RU"}}],
            "device": {"hostname": "WS-01"},
        }
        result = enrich("identity.suspiciousSignIn", "medium", raw, _utc())
        signal_names = {s["signal"] for s in result.confidence_explanation}
        assert "tor_exit_node" in signal_names

    def test_threat_intel_boosts_score(self):
        reset_threat_intel()
        raw_clean = {
            "identity": {"upn": "bob@corp.com", "displayName": "Bob"},
            "ips": [{"ipAddress": "8.8.8.8", "role": "anomalous", "geo": {"country": "US"}}],
            "device": {"hostname": "WS-02"},
        }
        raw_malicious = {
            "identity": {"upn": "charlie@corp.com", "displayName": "Charlie"},
            "ips": [{"ipAddress": "162.247.74.27", "role": "anomalous", "geo": {"country": "RU"}}],
            "device": {"hostname": "WS-03"},
        }
        result_clean = enrich("identity.suspiciousSignIn", "medium", raw_clean, _utc())
        result_malicious = enrich("identity.suspiciousSignIn", "medium", raw_malicious, _utc())
        assert result_malicious.confidence_score > result_clean.confidence_score

    def test_debug_shows_threat_intel_signals(self):
        reset_threat_intel()
        raw = {
            "identity": {"upn": "debug@corp.com"},
            "device": {"hostname": "DC-01"},
            "file": {
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "signer": "Unknown", "prevalence": "rare",
            },
        }
        debug = enrich_debug("endpoint.malwareDetection", "high", raw, _utc())
        ti_signals = [s for s in debug.all_signals if s.name == "known_bad_hash"]
        assert len(ti_signals) >= 1


# ── Calibration Endpoints ────────────────────────────────────────────

class TestCalibrationFeedback:
    """Test the calibration endpoints at /api/v1/calibration/."""

    @pytest.fixture()
    def client(self, fresh_client):
        return fresh_client

    def _create_case(self, client, alert_type="identity.suspiciousSignIn"):
        """Helper to create a real case and return its caseId."""
        raw_alerts = {
            "identity.suspiciousSignIn": {
                "identity": {"upn": "test@corp.com", "displayName": "Test"},
                "ips": [{"ipAddress": "8.8.8.8", "role": "anomalous", "geo": {"country": "US"}}],
                "device": {"hostname": "WS-01"},
            },
            "identity.passwordSpray": {
                "identity": {"upn": "test@corp.com", "displayName": "Test"},
                "ips": [{"ipAddress": "8.8.8.8", "role": "anomalous"}],
                "bulkTarget": {"count": 25, "successCount": 1},
            },
            "endpoint.malwareDetection": {
                "identity": {"upn": "test@corp.com", "displayName": "Test"},
                "device": {"hostname": "WS-01", "managed": True, "os": "Windows"},
                "file": {"fileName": "bad.exe", "sha256": "cafe" * 16, "signer": "Unknown", "prevalence": "rare"},
            },
        }
        raw = raw_alerts.get(alert_type, raw_alerts["identity.suspiciousSignIn"])
        resp = client.post("/api/v1/demo/enrich-raw", json={
            "alertType": alert_type,
            "rawAlert": raw,
            "customer": {"name": "Test", "environment": "prod"},
            "persist": True,
        })
        assert resp.status_code == 200, f"Case creation failed: {resp.text}"
        return resp.json()["caseId"]

    def test_submit_feedback(self, client):
        case_id = self._create_case(client)
        resp = client.post("/api/v1/calibration/feedback", json={
            "case_id": case_id,
            "analyst_verdict": "true_positive",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["analyst_verdict"] == "true_positive"
        assert data["case_id"] == case_id

    def test_invalid_verdict_rejected(self, client):
        case_id = self._create_case(client)
        resp = client.post("/api/v1/calibration/feedback", json={
            "case_id": case_id,
            "analyst_verdict": "maybe",
        })
        assert resp.status_code == 422

    def test_stats_empty(self, client):
        resp = client.get("/api/v1/calibration/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_feedback"] == 0
        assert data["precision"] is None

    def test_stats_after_feedback(self, client):
        c1 = self._create_case(client, "identity.suspiciousSignIn")
        c2 = self._create_case(client, "identity.suspiciousSignIn")
        c3 = self._create_case(client, "endpoint.malwareDetection")

        client.post("/api/v1/calibration/feedback", json={
            "case_id": c1, "analyst_verdict": "true_positive",
        })
        client.post("/api/v1/calibration/feedback", json={
            "case_id": c2, "analyst_verdict": "false_positive",
        })
        client.post("/api/v1/calibration/feedback", json={
            "case_id": c3, "analyst_verdict": "true_positive",
        })

        resp = client.get("/api/v1/calibration/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_feedback"] == 3
        assert data["true_positives"] == 2
        assert data["false_positives"] == 1
        assert data["precision"] == round(2 / 3, 4)
        assert data["false_positive_rate"] == round(1 / 3, 4)
        assert "identity.suspiciousSignIn" in data["by_alert_type"]
        assert "endpoint.malwareDetection" in data["by_alert_type"]

    def test_by_alert_type_precision(self, client):
        c1 = self._create_case(client, "identity.passwordSpray")
        c2 = self._create_case(client, "identity.passwordSpray")

        client.post("/api/v1/calibration/feedback", json={
            "case_id": c1, "analyst_verdict": "true_positive",
        })
        client.post("/api/v1/calibration/feedback", json={
            "case_id": c2, "analyst_verdict": "false_positive",
        })

        resp = client.get("/api/v1/calibration/stats")
        data = resp.json()
        ps = data["by_alert_type"]["identity.passwordSpray"]
        assert ps["precision"] == 0.5
        assert ps["fp_rate"] == 0.5
