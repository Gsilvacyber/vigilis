"""Tests for Phase 3: Cross-Alert Intelligence.

Covers: entity key extraction, cross-alert pattern detection (multi-vector,
corroboration, rapid escalation), window expiry, action cascades, thread
safety, and end-to-end pipeline integration.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.services.enrichment.cross_alert import (
    CrossAlertScanner,
    CrossAlertSignal,
    _extract_entity_keys,
    reset_scanner,
)
from backend.app.services.enrichment import enrich, _TELEMETRY


def _utc(minute: int = 0) -> datetime:
    return datetime(2026, 4, 2, 12, minute, 0, tzinfo=timezone.utc)


# ── Entity Key Extraction ────────────────────────────────────────────

class TestEntityKeyExtraction:
    def test_extracts_upn(self):
        raw = {"identity": {"upn": "Alice@Corp.com"}}
        keys = _extract_entity_keys(raw)
        assert "alice@corp.com" in keys

    def test_extracts_hostname(self):
        raw = {"device": {"hostname": "ws-prod-01"}}
        keys = _extract_entity_keys(raw)
        assert "WS-PROD-01" in keys

    def test_extracts_public_ip(self):
        raw = {"ips": [{"ipAddress": "203.0.113.10"}]}
        keys = _extract_entity_keys(raw)
        assert "203.0.113.10" in keys

    def test_excludes_private_ip(self):
        raw = {"ips": [{"ipAddress": "10.0.0.1"}, {"ipAddress": "192.168.1.1"}]}
        keys = _extract_entity_keys(raw)
        assert "10.0.0.1" not in keys
        assert "192.168.1.1" not in keys

    def test_excludes_loopback(self):
        raw = {"ips": [{"ipAddress": "127.0.0.1"}]}
        keys = _extract_entity_keys(raw)
        assert "127.0.0.1" not in keys

    def test_deduplicates(self):
        raw = {
            "identity": {"upn": "alice@corp.com"},
            "ips": [{"ipAddress": "203.0.113.10"}, {"ipAddress": "203.0.113.10"}],
        }
        keys = _extract_entity_keys(raw)
        assert len(keys) == len(set(keys))

    def test_empty_alert(self):
        keys = _extract_entity_keys({})
        assert keys == []

    def test_invalid_ip_ignored(self):
        raw = {"ips": [{"ipAddress": "not-an-ip"}]}
        keys = _extract_entity_keys(raw)
        assert keys == []


# ── Multi-Vector Attack Detection ────────────────────────────────────

class TestMultiVectorAttack:
    def test_two_domains_triggers_multi_vector(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("endpoint.malwareDetection", ["alice@corp.com"], _utc(5))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_multiVectorAttack" in names

    def test_same_domain_does_not_trigger_multi_vector(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("identity.passwordSpray", ["alice@corp.com"], _utc(5))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_multiVectorAttack" not in names

    def test_multi_vector_includes_contributing_alerts(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("cloud.secretStoreAccessAnomaly", ["alice@corp.com"], _utc(3))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        mv = [s for s in signals if s.name == "_multiVectorAttack"][0]
        assert "identity.suspiciousSignIn" in mv.contributing_alerts
        assert "cloud.secretStoreAccessAnomaly" in mv.contributing_alerts

    def test_multi_vector_weight(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.mfaFatigue", ["bob@corp.com"], _utc(0))
        scanner.register_alert("endpoint.suspiciousProcess", ["bob@corp.com"], _utc(2))
        signals = scanner.scan_for_patterns(["bob@corp.com"])
        mv = [s for s in signals if s.name == "_multiVectorAttack"][0]
        assert mv.weight == 12


# ── Cross-Alert Corroboration ────────────────────────────────────────

class TestCrossAlertCorroboration:
    def test_same_domain_two_alerts_triggers(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("identity.passwordSpray", ["alice@corp.com"], _utc(5))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_crossAlertCorroboration" in names

    def test_corroboration_weight(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("identity.mfaFatigue", ["alice@corp.com"], _utc(5))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        corr = [s for s in signals if s.name == "_crossAlertCorroboration"][0]
        assert corr.weight == 8

    def test_single_alert_no_corroboration(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_crossAlertCorroboration" not in names


# ── Rapid Escalation ────────────────────────────────────────────────

class TestRapidEscalation:
    def test_three_alerts_in_five_minutes(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("identity.passwordSpray", ["alice@corp.com"], _utc(1))
        scanner.register_alert("identity.mfaFatigue", ["alice@corp.com"], _utc(3))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_rapidEscalation" in names

    def test_two_alerts_not_enough(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("identity.passwordSpray", ["alice@corp.com"], _utc(1))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_rapidEscalation" not in names

    def test_three_alerts_spread_over_10_minutes_no_rapid(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("identity.passwordSpray", ["alice@corp.com"], _utc(4))
        scanner.register_alert("identity.mfaFatigue", ["alice@corp.com"], _utc(9))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_rapidEscalation" not in names

    def test_rapid_escalation_weight(self):
        scanner = CrossAlertScanner(window_minutes=15)
        for i in range(3):
            scanner.register_alert(f"identity.type{i}", ["bob@corp.com"], _utc(i))
        signals = scanner.scan_for_patterns(["bob@corp.com"])
        rapid = [s for s in signals if s.name == "_rapidEscalation"][0]
        assert rapid.weight == 10


# ── Window Expiry ────────────────────────────────────────────────────

class TestWindowExpiry:
    def test_old_alerts_pruned(self):
        scanner = CrossAlertScanner(window_minutes=10)
        old_time = _utc(0)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], old_time)
        new_time = old_time + timedelta(minutes=15)
        scanner.register_alert("endpoint.malwareDetection", ["alice@corp.com"], new_time)
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_multiVectorAttack" not in names

    def test_within_window_detected(self):
        scanner = CrossAlertScanner(window_minutes=10)
        t0 = _utc(0)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], t0)
        scanner.register_alert("endpoint.malwareDetection", ["alice@corp.com"], t0 + timedelta(minutes=8))
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        names = {s.name for s in signals}
        assert "_multiVectorAttack" in names


# ── Action Cascades ──────────────────────────────────────────────────

class TestActionCascades:
    def test_identity_cloud_multi_vector_revokes_tokens(self):
        from backend.app.services.enrichment.actions import _cross_alert_cascades
        scanner = reset_scanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("cloud.secretStoreAccessAnomaly", ["alice@corp.com"], _utc(3))
        cross_signals = scanner.scan_for_patterns(["alice@corp.com"])
        actions = _cross_alert_cascades(cross_signals, ["alice@corp.com"])
        action_ids = {a["action"] for a in actions}
        assert "revoke_all_tokens" in action_ids

    def test_identity_endpoint_multi_vector_isolates(self):
        from backend.app.services.enrichment.actions import _cross_alert_cascades
        scanner = reset_scanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("endpoint.malwareDetection", ["alice@corp.com"], _utc(3))
        cross_signals = scanner.scan_for_patterns(["alice@corp.com"])
        actions = _cross_alert_cascades(cross_signals, ["alice@corp.com"])
        action_ids = {a["action"] for a in actions}
        assert "isolate_and_revoke" in action_ids

    def test_rapid_escalation_escalates_to_ic(self):
        from backend.app.services.enrichment.actions import _cross_alert_cascades
        scanner = reset_scanner(window_minutes=15)
        for i in range(3):
            scanner.register_alert(f"identity.type{i}", ["bob@corp.com"], _utc(i))
        cross_signals = scanner.scan_for_patterns(["bob@corp.com"])
        actions = _cross_alert_cascades(cross_signals, ["bob@corp.com"])
        action_ids = {a["action"] for a in actions}
        assert "escalate_to_ic" in action_ids

    def test_no_cross_alerts_no_cascades(self):
        from backend.app.services.enrichment.actions import _cross_alert_cascades
        actions = _cross_alert_cascades([], ["alice@corp.com"])
        assert actions == []


# ── Thread Safety ────────────────────────────────────────────────────

class TestThreadSafety:
    def test_concurrent_registration(self):
        scanner = CrossAlertScanner(window_minutes=15)
        errors: list[Exception] = []

        def register(entity: str, domain: str, idx: int):
            try:
                scanner.register_alert(
                    f"{domain}.alert{idx}", [entity], _utc(idx % 15))
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(20):
            t = threading.Thread(
                target=register,
                args=(f"user{i % 3}@corp.com", ["identity", "endpoint", "cloud"][i % 3], i),
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0

    def test_concurrent_scan(self):
        scanner = CrossAlertScanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.register_alert("endpoint.malwareDetection", ["alice@corp.com"], _utc(3))
        errors: list[Exception] = []
        results: list[list[CrossAlertSignal]] = []

        def scan():
            try:
                signals = scanner.scan_for_patterns(["alice@corp.com"])
                results.append(signals)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=scan) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 10
        for r in results:
            assert any(s.name == "_multiVectorAttack" for s in r)


# ── End-to-End Pipeline Integration ──────────────────────────────────

class TestPipelineIntegration:
    def _make_alert(self, upn: str, ips: list[str] | None = None) -> dict:
        alert = {"identity": {"upn": upn, "displayName": "Test"}}
        if ips:
            alert["ips"] = [{"ipAddress": ip, "role": "anomalous", "geo": {"country": "RU"}} for ip in ips]
        return alert

    def test_multi_vector_boosts_score(self):
        reset_scanner(window_minutes=15)
        _TELEMETRY.clear()
        t = _utc(0)

        alert1 = self._make_alert("crosstest@corp.com", ["203.0.113.10"])
        result1 = enrich("identity.suspiciousSignIn", "medium", alert1, t)

        alert2 = {
            **self._make_alert("crosstest@corp.com"),
            "device": {"hostname": "WS-01", "managed": True, "os": "Windows"},
            "file": {"fileName": "bad.exe", "sha256": "a" * 64, "signer": "Unknown", "prevalence": "rare"},
        }
        result2 = enrich("endpoint.malwareDetection", "medium", alert2, t + timedelta(minutes=3))

        assert any("_multiVectorAttack" in n for n in result2.enrichment_notes
                    ) or any("Multi-vector" in n for n in result2.enrichment_notes)

    def test_telemetry_includes_cross_alert_flags(self):
        reset_scanner(window_minutes=15)
        _TELEMETRY.clear()
        t = _utc(0)

        alert1 = self._make_alert("teltest@corp.com", ["203.0.113.20"])
        enrich("identity.suspiciousSignIn", "medium", alert1, t)
        alert2 = self._make_alert("teltest@corp.com", ["203.0.113.20"])
        enrich("identity.passwordSpray", "medium", {
            **alert2,
            "bulkTarget": {"count": 25, "successCount": 1},
        }, t + timedelta(minutes=2))

        assert len(_TELEMETRY) >= 2
        last = _TELEMETRY[-1]
        assert "cross_alert_flags" in last

    def test_scanner_reset_clears_state(self):
        scanner = reset_scanner(window_minutes=15)
        scanner.register_alert("identity.suspiciousSignIn", ["alice@corp.com"], _utc(0))
        scanner.clear()
        signals = scanner.scan_for_patterns(["alice@corp.com"])
        assert signals == []
