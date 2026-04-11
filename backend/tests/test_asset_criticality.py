"""Tests for Phase 2: Asset criticality + user risk scoring integration."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.app.services.enrichment.asset_criticality import (
    compute_asset_criticality,
    compute_user_risk,
)
from backend.app.services.enrichment import enrich, enrich_debug
from backend.app.services.enrichment.cross_alert import reset_scanner
from backend.app.services.enrichment.scoring import compute_confidence
from backend.app.services.enrichment.base import Signal


# ── Asset Criticality Detection ──────────────────────────────────────

class TestAssetCriticality:
    def test_domain_controller_hostname(self):
        raw = {"device": {"hostname": "DC-PROD-01"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"
        assert weight == 20

    def test_ad_hostname(self):
        raw = {"device": {"hostname": "AD-Server-01"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"
        assert weight == 20

    def test_pki_hostname(self):
        raw = {"device": {"hostname": "PKI-ROOT-CA"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"

    def test_scada_hostname(self):
        raw = {"device": {"hostname": "SCADA-HMI-01"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"

    def test_production_server_hostname(self):
        raw = {"device": {"hostname": "SRV-WEB-PROD"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "high"
        assert weight == 12

    def test_bastion_host(self):
        raw = {"device": {"hostname": "bastion-us-east"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "high"

    def test_dev_machine(self):
        raw = {"device": {"hostname": "DEV-LAPTOP-042"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "low"
        assert weight == -5

    def test_sandbox_hostname(self):
        raw = {"device": {"hostname": "sandbox-test-env"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "low"

    def test_standard_workstation(self):
        raw = {"device": {"hostname": "LAPTOP-ABC123"}}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "standard"
        assert weight == 0

    def test_no_device(self):
        weight, tier = compute_asset_criticality({})
        assert tier == "standard"
        assert weight == 0

    def test_explicit_tier_override(self):
        raw = {"device": {"hostname": "anything"}, "_assetCriticality": "critical"}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"
        assert weight == 20

    def test_explicit_tier_low(self):
        raw = {"_assetCriticality": "low"}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "low"
        assert weight == -5

    def test_plc_device_type(self):
        raw = {"_deviceType": "PLC controller"}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"

    def test_server_device_type(self):
        raw = {"_deviceType": "application server"}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "high"

    def test_iot_device_type(self):
        raw = {"_deviceType": "ip camera"}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "high"

    def test_sil_safety_level(self):
        raw = {"_safetyLevel": "SIL3"}
        weight, tier = compute_asset_criticality(raw)
        assert tier == "critical"


# ── User Risk Detection ──────────────────────────────────────────────

class TestUserRisk:
    def test_ceo_upn(self):
        raw = {"identity": {"upn": "ceo@company.com", "displayName": ""}}
        weight, tier = compute_user_risk(raw)
        assert tier == "critical_user"
        assert weight == 15

    def test_ciso_upn(self):
        raw = {"identity": {"upn": "ciso@company.com", "displayName": ""}}
        weight, tier = compute_user_risk(raw)
        assert tier == "critical_user"

    def test_chief_title(self):
        raw = {"identity": {"upn": "jane@co.com", "displayName": "chief technology officer"}}
        weight, tier = compute_user_risk(raw)
        assert tier == "critical_user"
        assert weight == 15

    def test_director_title(self):
        raw = {"identity": {"upn": "bob@co.com", "displayName": "director of engineering"}}
        weight, tier = compute_user_risk(raw)
        assert tier == "critical_user"

    def test_admin_privilege_tier(self):
        raw = {"identity": {"upn": "admin-ops@co.com", "privilegeTier": "admin"}}
        weight, tier = compute_user_risk(raw)
        assert tier == "high_risk_user"
        assert weight == 10

    def test_resignation_flag(self):
        raw = {"identity": {"upn": "john@co.com"}, "_insiderResignation": True}
        weight, tier = compute_user_risk(raw)
        assert tier == "high_risk_user"
        assert weight == 10

    def test_service_account(self):
        raw = {"identity": {"upn": "svc-backup@co.com", "privilegeTier": "service"}}
        weight, tier = compute_user_risk(raw)
        assert tier == "low_risk_user"
        assert weight == -5

    def test_monitoring_account(self):
        raw = {"identity": {"upn": "datadog-monitor@co.com"}}
        weight, tier = compute_user_risk(raw)
        assert tier == "low_risk_user"
        assert weight == -5

    def test_standard_user(self):
        raw = {"identity": {"upn": "alice@company.com", "displayName": "Alice Smith"}}
        weight, tier = compute_user_risk(raw)
        assert tier == "standard_user"
        assert weight == 0

    def test_no_identity(self):
        weight, tier = compute_user_risk({})
        assert tier == "standard_user"
        assert weight == 0


# ── Scoring Integration ──────────────────────────────────────────────

class TestScoringIntegration:
    def test_asset_weight_applied_in_scoring(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP detected")]
        score_no_asset, _, _ = compute_confidence("medium", signals)
        score_with_asset, _, expl = compute_confidence(
            "medium", signals, asset_weight=20)
        assert score_with_asset > score_no_asset
        asset_items = [e for e in expl if e["signal"] == "asset_criticality"]
        assert len(asset_items) == 1
        assert asset_items[0]["weight"] == 20

    def test_user_weight_applied_in_scoring(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP detected")]
        score_no_user, _, _ = compute_confidence("medium", signals)
        score_with_user, _, expl = compute_confidence(
            "medium", signals, user_weight=15)
        assert score_with_user > score_no_user
        user_items = [e for e in expl if e["signal"] == "user_risk"]
        assert len(user_items) == 1

    def test_negative_asset_weight_reduces_score(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP detected")]
        score_normal, _, _ = compute_confidence("medium", signals)
        score_low_asset, _, _ = compute_confidence(
            "medium", signals, asset_weight=-5)
        assert score_low_asset < score_normal

    def test_combined_asset_and_user(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP detected")]
        score_combined, _, expl = compute_confidence(
            "medium", signals, asset_weight=20, user_weight=15)
        score_plain, _, _ = compute_confidence("medium", signals)
        # When both asset and user weights fire, combined contribution is 70%
        # of the sum to prevent ceiling effect: int((20+15) * 0.7) = 24
        expected_delta = int((20 + 15) * 0.7)
        assert score_combined - score_plain == expected_delta

    def test_no_asset_user_entries_when_zero(self):
        signals = [Signal("anomalous_ip", 12, True, "Anomalous IP detected")]
        _, _, expl = compute_confidence("medium", signals)
        assert not any(e["signal"] in ("asset_criticality", "user_risk") for e in expl)


# ── End-to-End Pipeline Integration ──────────────────────────────────

class TestEndToEndIntegration:
    def setup_method(self):
        reset_scanner(window_minutes=15)

    def _now(self):
        return datetime.now(timezone.utc)

    def test_dc_scores_higher_than_dev_laptop(self):
        dc_alert = {
            "identity": {"upn": "dc-test-user@co.com", "displayName": "DC User"},
            "ips": [{"ipAddress": "198.51.100.1", "role": "anomalous", "geo": {"country": "Russia"}}],
            "device": {"hostname": "DC-PROD-01"},
        }
        dc_result = enrich("identity.suspiciousSignIn", "high", dc_alert, self._now())

        reset_scanner(window_minutes=15)

        dev_alert = {
            "identity": {"upn": "dev-test-user@co.com", "displayName": "Dev User"},
            "ips": [{"ipAddress": "198.51.100.2", "role": "anomalous", "geo": {"country": "Russia"}}],
            "device": {"hostname": "DEV-LAPTOP-01"},
        }
        dev_result = enrich("identity.suspiciousSignIn", "high", dev_alert, self._now())
        assert dc_result.confidence_score > dev_result.confidence_score
        assert dc_result.asset_tier == "critical"
        assert dev_result.asset_tier == "low"

    def test_ceo_scores_higher_than_intern(self):
        base_alert = {
            "device": {"hostname": "LAPTOP-123"},
            "ips": [{"ipAddress": "1.2.3.4", "role": "anomalous", "geo": {"country": "China"}}],
        }
        ceo_alert = {**base_alert, "identity": {"upn": "ceo@acme.com", "displayName": "CEO"}}
        intern_alert = {**base_alert, "identity": {"upn": "intern@acme.com", "displayName": "Intern"}}

        ceo_result = enrich("identity.suspiciousSignIn", "high", ceo_alert, self._now())
        intern_result = enrich("identity.suspiciousSignIn", "high", intern_alert, self._now())
        assert ceo_result.confidence_score > intern_result.confidence_score
        assert ceo_result.user_risk_tier == "critical_user"
        assert intern_result.user_risk_tier == "standard_user"

    def test_debug_includes_tiers(self):
        raw = {
            "identity": {"upn": "ciso@co.com", "displayName": "CISO"},
            "device": {"hostname": "SRV-PROD-01"},
            "ips": [{"ipAddress": "1.2.3.4", "role": "observed"}],
        }
        debug = enrich_debug("identity.suspiciousSignIn", "medium", raw, self._now())
        assert debug.result.asset_tier == "high"
        assert debug.result.user_risk_tier == "critical_user"
        assert any("Asset tier" in n for n in debug.result.enrichment_notes)
        assert any("User risk" in n for n in debug.result.enrichment_notes)

    def test_telemetry_includes_tiers(self):
        from backend.app.services.enrichment import _TELEMETRY
        _TELEMETRY.clear()
        raw = {
            "identity": {"upn": "alice@co.com"},
            "device": {"hostname": "DC-FINANCE-01"},
            "ips": [],
        }
        enrich("identity.suspiciousSignIn", "medium", raw, self._now())
        assert len(_TELEMETRY) >= 1
        last = _TELEMETRY[-1]
        assert last["asset_tier"] == "critical"
        assert "user_risk_tier" in last

    def test_standard_tiers_not_in_notes(self):
        raw = {
            "identity": {"upn": "normal.user@co.com"},
            "device": {"hostname": "LAPTOP-XYZ"},
            "ips": [],
        }
        result = enrich("identity.suspiciousSignIn", "medium", raw, self._now())
        assert not any("Asset tier" in n for n in result.enrichment_notes)
        assert not any("User risk" in n for n in result.enrichment_notes)
