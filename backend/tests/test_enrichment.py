"""Tests for the enrichment engine.

Covers: signal extraction, confidence scoring, playbook generation,
action generation, and normalizer integration for all 10 alert types.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from backend.app.services.enrichment import enrich, EnrichmentResult
from backend.app.services.enrichment.scoring import compute_confidence
from backend.app.services.enrichment.base import Signal


def _utc(hour: int = 14) -> datetime:
    return datetime(2026, 3, 26, hour, 0, 0, tzinfo=timezone.utc)


# ── Sample raw alerts (realistic enough for demo) ────────────────────────

SAMPLES: dict[str, dict[str, Any]] = {
    "identity.suspiciousSignIn": {
        "identity": {"identityType": "user", "userId": "u-123", "upn": "alice@example.com",
                     "displayName": "Alice", "riskLevel": "high"},
        "actor": {"identityType": "user", "userId": "u-123", "upn": "alice@example.com",
                  "displayName": "Alice"},
        "ips": [{"role": "anomalous", "ipAddress": "203.0.113.10",
                 "geo": {"country": "US", "city": "Seattle"}},
                {"role": "anomalous", "ipAddress": "198.51.100.5",
                 "geo": {"country": "RU", "city": "Moscow"}}],
        "device": {"deviceId": "d-1", "hostname": "ALICE-LAPTOP",
                   "managed": False, "os": "Windows",
                   "identificationStatus": "identified"},
    },
    "identity.passwordSpray": {
        "identity": {"identityType": "user", "userId": "u-999",
                     "upn": "bob@example.com", "displayName": "Bob"},
        "ips": [{"role": "anomalous", "ipAddress": "198.51.100.22"}],
        "bulkTarget": {"count": 25, "successCount": 1,
                       "succeededAccounts": ["user-1"],
                       "sampleTargets": ["bob@example.com", "cathy@example.com"]},
    },
    "identity.mfaFatigue": {
        "identity": {"identityType": "user", "userId": "u-222",
                     "upn": "dan@example.com", "displayName": "Dan"},
        "ips": [{"role": "anomalous", "ipAddress": "192.0.2.5"}],
    },
    "identity.oauthConsentRisk": {
        "identity": {"identityType": "user", "userId": "u-333",
                     "upn": "erin@example.com", "displayName": "Erin"},
        "app": {"appId": "app-xyz", "name": "Contoso CRM",
                "publisher": "Contoso",
                "scopes": ["Mail.ReadWrite", "Files.ReadWrite.All",
                           "User.ReadWrite.All", "Directory.ReadWrite.All"]},
    },
    "identity.privilegeElevation": {
        "identity": {"identityType": "service_principal",
                     "servicePrincipalId": "sp-1",
                     "displayName": "PrivElevator",
                     "newPrivilegeTier": "admin"},
        "actor": {"identityType": "service_principal",
                  "servicePrincipalId": "sp-2",
                  "displayName": "AdminBot"},
    },
    "endpoint.malwareDetection": {
        "identity": {"identityType": "user", "upn": "frank@example.com",
                     "displayName": "Frank"},
        "device": {"deviceId": "d-2", "hostname": "FRANK-VM",
                   "managed": True, "os": "Windows",
                   "identificationStatus": "identified"},
        "file": {"fileName": "bad.exe",
                 "filePath": "C:\\Temp\\bad.exe",
                 "sha256": "deadbeef" * 8,
                 "signer": "Unknown",
                 "prevalence": "rare"},
    },
    "endpoint.suspiciousProcess": {
        "identity": {"identityType": "user", "upn": "gina@example.com",
                     "displayName": "Gina"},
        "device": {"deviceId": "d-3", "hostname": "GINA-LAPTOP",
                   "managed": True, "os": "Windows",
                   "identificationStatus": "identified"},
        "file": {"fileName": "powershell.exe",
                 "sha256": "cafebabe" * 8,
                 "signer": "Microsoft"},
    },
    "email.forwardingRule": {
        "identity": {"identityType": "user", "upn": "hank@example.com",
                     "displayName": "Hank"},
        "mailbox": {"primaryAddress": "hank@example.com",
                    "ruleName": "Forwarding rule 1",
                    "forwardingAddress": "evil@external.com"},
        "ips": [{"role": "anomalous", "ipAddress": "203.0.113.99"}],
    },
    "cloud.secretStoreAccessAnomaly": {
        "identity": {"identityType": "managed_identity",
                     "servicePrincipalId": "mi-1",
                     "displayName": "App MI"},
        "app": {"appId": "app-secret", "name": "Secrets Processor",
                "publisher": "Fabrikam"},
    },
    "network.impossibleGeoAccess": {
        "identity": {"identityType": "user", "upn": "ivy@example.com",
                     "displayName": "Ivy", "riskLevel": "high"},
        "authResult": "success",
        "ips": [
            {"role": "anomalous", "ipAddress": "203.0.113.77",
             "geo": {"country": "FR", "city": "Paris"}},
            {"role": "anomalous", "ipAddress": "203.0.113.78",
             "geo": {"country": "US", "city": "Boston"}},
        ],
    },
}


# ── Scoring unit tests ───────────────────────────────────────────────────

def test_scoring_severity_base_only():
    score, label, explanation = compute_confidence("medium", [])
    assert score == 15  # medium base (reduced from 25 so signals drive the score)
    assert label == "low"  # 15 < 35 threshold
    # Explanation should only have the _score_breakdown entry
    assert len([e for e in explanation if e["signal"] != "_score_breakdown"]) == 0


def test_scoring_with_signals():
    signals = [
        Signal("a", 10, True, "A fired"),
        Signal("b", 15, True, "B fired"),
        Signal("c", 8, False, "C did not fire"),
    ]
    score, label, explanation = compute_confidence("medium", signals)
    # base=15 + signals scaled by tier (default inferred=0.6x): int(15*0.6)=9 + int(10*0.6)=6 = 30
    assert score == 30
    assert label == "low"
    real_sigs = [e for e in explanation if e["signal"] != "_score_breakdown"]
    assert len(real_sigs) == 2


def test_scoring_caps_at_65_without_verified():
    """Inferred-only signals are capped at 65 (no verified signal fired)."""
    signals = [Signal("x", 50, True, "big"), Signal("y", 50, True, "also big")]
    score, _, _ = compute_confidence("critical", signals)
    assert score == 65  # capped: no verified signal


# ── Per-alert-type enrichment tests ──────────────────────────────────────

@pytest.mark.parametrize("alert_type", list(SAMPLES.keys()))
def test_enrichment_produces_complete_result(alert_type: str):
    raw = SAMPLES[alert_type]
    result = enrich(alert_type, "medium", raw, _utc())

    assert isinstance(result, EnrichmentResult)
    assert 0 <= result.confidence_score <= 100
    assert result.confidence_label in ("low", "medium", "high", "critical")
    assert len(result.confidence_explanation) >= 1
    assert len(result.recommended_playbook) >= 3
    assert len(result.recommended_actions) >= 2
    assert len(result.enrichment_notes) >= 1


def test_suspicious_sign_in_signals():
    raw = SAMPLES["identity.suspiciousSignIn"]
    result = enrich("identity.suspiciousSignIn", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "anomalous_ip" in signal_names
    assert "impossible_travel" in signal_names
    assert "unmanaged_device" in signal_names
    assert "high_risk_identity" in signal_names
    assert result.confidence_score >= 30  # tier multipliers reduce observed/inferred signals


def test_password_spray_signals():
    raw = SAMPLES["identity.passwordSpray"]
    result = enrich("identity.passwordSpray", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "high_target_count" in signal_names
    assert "successful_login" in signal_names
    assert "anomalous_source_ip" in signal_names
    assert result.confidence_score >= 30  # tier multipliers reduce observed/inferred signals


def test_mfa_fatigue_signals():
    raw = SAMPLES["identity.mfaFatigue"]
    result = enrich("identity.mfaFatigue", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "anomalous_ip" in signal_names


def test_oauth_consent_risk_signals():
    raw = SAMPLES["identity.oauthConsentRisk"]
    result = enrich("identity.oauthConsentRisk", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "broad_scopes" in signal_names
    assert "unknown_publisher" in signal_names
    assert "first_seen_app" in signal_names


def test_privilege_elevation_signals():
    raw = SAMPLES["identity.privilegeElevation"]
    result = enrich("identity.privilegeElevation", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "actor_identity_mismatch" in signal_names
    assert "admin_role_grant" in signal_names
    assert "service_principal_actor" in signal_names


def test_malware_detection_signals():
    raw = SAMPLES["endpoint.malwareDetection"]
    result = enrich("endpoint.malwareDetection", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "rare_file" in signal_names
    assert "unsigned_binary" in signal_names
    assert "suspicious_path" in signal_names


def test_suspicious_process_signals():
    raw = SAMPLES["endpoint.suspiciousProcess"]
    result = enrich("endpoint.suspiciousProcess", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "living_off_the_land" in signal_names


def test_forwarding_rule_signals():
    raw = SAMPLES["email.forwardingRule"]
    result = enrich("email.forwardingRule", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "external_forward" in signal_names
    assert "anomalous_ip" in signal_names
    assert "rule_obfuscation" in signal_names


def test_secret_store_anomaly_signals():
    raw = SAMPLES["cloud.secretStoreAccessAnomaly"]
    result = enrich("cloud.secretStoreAccessAnomaly", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "new_app" in signal_names
    assert "service_principal_access" in signal_names
    assert "unknown_publisher" in signal_names


def test_impossible_geo_signals():
    raw = SAMPLES["network.impossibleGeoAccess"]
    result = enrich("network.impossibleGeoAccess", "medium", raw, _utc())
    signal_names = {s["signal"] for s in result.confidence_explanation}
    assert "multi_country_access" in signal_names
    assert "anomalous_ip" in signal_names
    assert "successful_auth" in signal_names
    assert result.confidence_score >= 30  # tier multipliers + reduced base


# ── Conditional action tests ─────────────────────────────────────────────

def test_password_spray_reset_action_on_success():
    raw = SAMPLES["identity.passwordSpray"]
    result = enrich("identity.passwordSpray", "medium", raw, _utc())
    action_ids = {a["action"] for a in result.recommended_actions}
    assert "reset_passwords" in action_ids


def test_malware_detection_threat_intel_on_rare_file():
    raw = SAMPLES["endpoint.malwareDetection"]
    result = enrich("endpoint.malwareDetection", "medium", raw, _utc())
    action_ids = {a["action"] for a in result.recommended_actions}
    assert "submit_threat_intel" in action_ids


def test_forwarding_rule_audit_on_external_forward():
    raw = SAMPLES["email.forwardingRule"]
    result = enrich("email.forwardingRule", "medium", raw, _utc())
    action_ids = {a["action"] for a in result.recommended_actions}
    assert "audit_forwarded_email" in action_ids


# ── Fallback for unknown alert type ──────────────────────────────────────

def test_unknown_alert_type_returns_safe_default():
    result = enrich("unknown.alertType", "medium", {}, _utc())
    assert result.confidence_score == 15  # medium base (reduced so signals drive scoring)
    assert result.confidence_label in ("low", "medium")
    assert result.recommended_playbook == []
    assert result.recommended_actions == []
    assert "No enrichment rules" in result.enrichment_notes[0]


# ── Normalizer integration ───────────────────────────────────────────────

def test_normalizer_produces_enriched_case():
    from backend.app.services.normalizer import normalize_case_from_request

    case = normalize_case_from_request(
        tenant={"tenantId": "t-1", "name": "Test", "environment": "prod"},
        source={"sourceSystem": "idp", "sourceName": "test",
                "sourceAlertId": "a-1", "sourceSeverity": "medium"},
        alert_type="identity.suspiciousSignIn",
        title="Test Alert",
        description="Test",
        severity="medium",
        event_time=_utc(),
        raw_alert=SAMPLES["identity.suspiciousSignIn"],
    )
    assert case.confidence.score > 0
    assert len(case.confidence.explanation) >= 1
    assert len(case.recommendedPlaybook) >= 3
    assert len(case.recommendedActions) >= 2
    assert case.enrichment.riskScore > 0
    assert len(case.enrichment.enrichmentNotes) >= 1
    assert "rule_engine_v1" in case.audit.enrichmentSources


# ── API integration (uses test_client from conftest) ─────────────────────

def test_api_case_creation_returns_enriched_data(test_client):
    payload = {
        "tenantId": "tenant-enrichment",
        "customer": {"name": "EnrichTest", "environment": "prod"},
        "alertType": "identity.suspiciousSignIn",
        "source": {
            "sourceSystem": "idp", "sourceName": "idp_mvp",
            "sourceAlertId": "enrich-1", "sourceSeverity": "medium",
        },
        "rawAlert": SAMPLES["identity.suspiciousSignIn"],
    }
    resp = test_client.post("/api/v1/cases", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["confidence"]["score"] > 0
    assert len(data["confidence"]["explanation"]) >= 1
    assert len(data["recommendedPlaybook"]) >= 3
    assert len(data["recommendedActions"]) >= 2
    assert data["enrichment"]["riskScore"] > 0
    assert len(data["enrichment"]["enrichmentNotes"]) >= 1
