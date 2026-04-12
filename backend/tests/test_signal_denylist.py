"""Tests for Day 5 Lite — per-tenant signal denylist.

Covers:
- TestConfigServicePersistence — disabledSignals in _TENANT_DEFAULT, normalize/
  dedupe/sort behavior, get_disabled_signals helper
- TestConfigAPI — PATCH accepts disabledSignals, GET round-trips, signals-catalog
  excludes negative/internal signals
- TestScoringFilter — compute_confidence filters denylisted signals entirely
  from both score AND explanation
- TestEnrichmentEndToEnd — POST /api/v1/cases honors denylist via the enrichment
  pipeline (full integration)
- TestCalibrationUIRoute — calibration.html page contains Signal Configuration
  markup
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from backend.app.services.config_service import (
    _CONFIG_PATH,
    get_config,
    get_disabled_signals,
    save_config,
    update_config,
)
from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.scoring import compute_confidence


@pytest.fixture(autouse=True)
def _restore_config():
    """Snapshot the config file around each test so one test's writes don't
    leak into another. The file is `vigilis_config.json` (or legacy
    `socai_config.json`) at the repo root."""
    path: Path = _CONFIG_PATH
    backup: str | None = None
    if path.exists():
        backup = path.read_text()
    yield
    if backup is not None:
        path.write_text(backup)
    elif path.exists():
        path.unlink()


# ─── TestConfigServicePersistence ─────────────────────────────────────────

class TestConfigServicePersistence:

    def test_default_empty_list(self):
        cfg = get_config("brand-new-tenant-xyz")
        assert "disabledSignals" in cfg
        assert cfg["disabledSignals"] == []

    def test_get_disabled_signals_helper_returns_set(self):
        result = get_disabled_signals("brand-new-tenant-xyz")
        assert isinstance(result, set)
        assert result == set()

    def test_round_trip_persist(self):
        update_config("demo-tenant",
                      {"disabledSignals": ["after_hours", "anomalous_ip"]})
        cfg = get_config("demo-tenant")
        assert cfg["disabledSignals"] == ["after_hours", "anomalous_ip"]
        # And the helper returns the same thing as a set
        assert get_disabled_signals("demo-tenant") == {"after_hours", "anomalous_ip"}

    def test_normalize_dedupes_and_strips_empty(self):
        update_config("demo-tenant", {
            "disabledSignals": ["after_hours", "after_hours", "", "  ", "anomalous_ip"],
        })
        cfg = get_config("demo-tenant")
        # Deduped, empties stripped, sorted
        assert cfg["disabledSignals"] == ["after_hours", "anomalous_ip"]

    def test_normalize_sorts_for_stable_output(self):
        update_config("demo-tenant", {
            "disabledSignals": ["zzz_last", "aaa_first", "mmm_middle"],
        })
        cfg = get_config("demo-tenant")
        assert cfg["disabledSignals"] == ["aaa_first", "mmm_middle", "zzz_last"]


# ─── TestConfigAPI ────────────────────────────────────────────────────────

class TestConfigAPI:

    def test_patch_disabled_signals(self, test_client):
        resp = test_client.patch(
            "/api/v1/config",
            json={"disabledSignals": ["after_hours"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["disabledSignals"] == ["after_hours"]

    def test_get_config_includes_disabled(self, test_client):
        test_client.patch(
            "/api/v1/config",
            json={"disabledSignals": ["anomalous_ip", "unsigned_binary"]},
        )
        resp = test_client.get("/api/v1/config")
        assert resp.status_code == 200
        body = resp.json()
        assert "disabledSignals" in body
        assert set(body["disabledSignals"]) == {"anomalous_ip", "unsigned_binary"}

    def test_patch_mode_does_not_clobber_denylist(self, test_client):
        # Set denylist first
        test_client.patch("/api/v1/config",
                          json={"disabledSignals": ["after_hours"]})
        # Then patch only mode — denylist should survive
        test_client.patch("/api/v1/config", json={"mode": "manual"})
        resp = test_client.get("/api/v1/config")
        body = resp.json()
        assert body["disabledSignals"] == ["after_hours"]

    def test_signals_catalog_endpoint_returns_list(self, test_client):
        resp = test_client.get("/api/v1/config/signals-catalog")
        assert resp.status_code == 200
        catalog = resp.json()
        assert isinstance(catalog, list)
        assert len(catalog) > 100  # we have ~175 positive-weight signals
        for entry in catalog:
            assert "name" in entry
            assert "weight" in entry
            assert "tier" in entry
            assert entry["weight"] > 0
            assert not entry["name"].startswith("_")

    def test_signals_catalog_excludes_negative_signals(self, test_client):
        resp = test_client.get("/api/v1/config/signals-catalog")
        catalog = resp.json()
        names = {e["name"] for e in catalog}
        # These suppression signals must NEVER be in the catalog because
        # disabling them would INCREASE scores
        assert "noise_flag" not in names
        assert "ir_response" not in names
        assert "authorized_admin_activity" not in names
        assert "service_account_noise" not in names
        assert "blocked" not in names


# ─── TestScoringFilter ────────────────────────────────────────────────────

class TestScoringFilter:

    def _build_signals(self) -> list[Signal]:
        """A signal set that produces a non-zero score when all fire."""
        return [
            Signal("after_hours", 18, True, "After hours activity"),
            Signal("anomalous_ip", 12, True, "Anomalous IP"),
            Signal("privileged_account", 20, True, "Privileged account"),
        ]

    def test_empty_denylist_no_effect(self):
        signals = self._build_signals()
        score_a, _, _ = compute_confidence("medium", signals)
        score_b, _, _ = compute_confidence("medium", signals, disabled_signals=None)
        score_c, _, _ = compute_confidence("medium", signals, disabled_signals=set())
        assert score_a == score_b == score_c

    def test_disabled_signal_lowers_score(self):
        signals = self._build_signals()
        baseline_score, _, baseline_expl = compute_confidence("medium", signals)
        filtered_score, _, filtered_expl = compute_confidence(
            "medium", signals, disabled_signals={"after_hours"},
        )
        assert filtered_score < baseline_score

    def test_disabled_signal_not_in_explanation(self):
        signals = self._build_signals()
        _, _, explanation = compute_confidence(
            "medium", signals, disabled_signals={"after_hours"},
        )
        # Filter out the _score_breakdown marker
        real_signals = [
            e for e in explanation if not e.get("signal", "").startswith("_")
        ]
        names = {e["signal"] for e in real_signals}
        assert "after_hours" not in names
        # The other two signals should still be there
        assert "anomalous_ip" in names
        assert "privileged_account" in names

    def test_disable_all_firing_signals(self):
        signals = self._build_signals()
        all_names = {s.name for s in signals}
        score, _, explanation = compute_confidence(
            "medium", signals, disabled_signals=all_names,
        )
        # With every signal disabled, score collapses to just the severity base (15)
        assert score == 15  # medium base
        real_signals = [
            e for e in explanation if not e.get("signal", "").startswith("_")
        ]
        assert len(real_signals) == 0

    def test_disabled_denylist_does_not_affect_negative_signals(self):
        """noise_flag should still fire and reduce the score even if listed
        in disabled_signals — the filter only touches positive_fired."""
        signals = [
            Signal("privileged_account", 20, True, "Privileged"),
            Signal("noise_flag", -25, True, "Noise marker"),
        ]
        baseline, _, _ = compute_confidence("medium", signals)
        # Adding noise_flag to denylist should NOT resurrect its impact
        filtered, _, _ = compute_confidence(
            "medium", signals, disabled_signals={"noise_flag"},
        )
        # Both scores should be the same because noise_flag is negative
        # and the filter only applies to positive_fired
        assert baseline == filtered


# ─── TestEnrichmentEndToEnd ───────────────────────────────────────────────

class TestEnrichmentEndToEnd:
    """Full pipeline test: create a case, set denylist, confirm enrichment
    drops the disabled signal from the case's confidence_explanation."""

    def _payload(self, i: int) -> dict[str, Any]:
        return {
            "tenantId": "demo-tenant",
            "customer": {
                "name": "DenyCo", "environment": "prod", "industry": None,
            },
            "alertType": "identity.suspiciousSignIn",
            "source": {
                "sourceSystem": "idp",
                "sourceName": "idp_mvp",
                "sourceAlertId": f"deny-test-{i}",
                "sourceSeverity": "medium",
                "sourceUrl": None,
            },
            "rawAlert": {
                "identity": {
                    "identityType": "user",
                    "userId": f"u-deny-{i}",
                    "upn": f"deny{i}@example.com",
                    "displayName": f"User {i}",
                    "riskLevel": "high",
                },
                "ips": [
                    {"role": "anomalous", "ipAddress": f"203.0.113.{i % 250 + 1}",
                     "geo": {"country": "US"}},
                    {"role": "anomalous", "ipAddress": "198.51.100.5",
                     "geo": {"country": "RU", "city": "Moscow"}},
                ],
                "device": {
                    "deviceId": f"d-deny-{i}",
                    "hostname": f"DENY-HOST-{i}",
                    "managed": False,
                    "os": "Windows",
                    "identificationStatus": "identified",
                },
            },
        }

    def test_enrichment_baseline_contains_anomalous_ip(self, fresh_client):
        """Confirm the canonical payload normally fires anomalous_ip so our
        denylist assertion in the next test has something to remove."""
        resp = fresh_client.post("/api/v1/cases", json=self._payload(1))
        assert resp.status_code == 200
        body = resp.json()
        signal_names = {
            s["signal"] for s in body["confidence"]["explanation"]
            if not s.get("signal", "").startswith("_")
        }
        assert "anomalous_ip" in signal_names

    def test_enrichment_honors_tenant_denylist(self, fresh_client):
        # Disable anomalous_ip via the config API
        r = fresh_client.patch(
            "/api/v1/config",
            json={"disabledSignals": ["anomalous_ip"]},
        )
        assert r.status_code == 200

        # Then create a case that would normally fire anomalous_ip
        resp = fresh_client.post("/api/v1/cases", json=self._payload(2))
        assert resp.status_code == 200
        body = resp.json()

        signal_names = {
            s["signal"] for s in body["confidence"]["explanation"]
            if not s.get("signal", "").startswith("_")
        }
        # anomalous_ip should NOT be in the explanation — it was denylisted
        assert "anomalous_ip" not in signal_names
        # Other signals should still be present
        assert "high_risk_identity" in signal_names or "impossible_travel" in signal_names


# ─── TestCalibrationUIRoute ───────────────────────────────────────────────

class TestCalibrationUIRoute:

    def test_calibration_page_contains_signal_config_section(self, test_client):
        resp = test_client.get("/demo/ui/calibration")
        assert resp.status_code == 200
        assert "signal-config-section" in resp.text
        assert "Signal Configuration" in resp.text
        assert "signal-toggle" in resp.text
        assert "/api/v1/config/signals-catalog" in resp.text
