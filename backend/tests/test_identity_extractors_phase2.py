"""Tests for the 2 Phase 2 identity extractors + regression on 3 existing ones.

Covers:
- extract_logon_success   (Windows Security Event 4624)
- extract_account_creation (Windows Security Event 4720)
- Regression smoke tests for extract_suspicious_sign_in,
  extract_privilege_elevation, extract_impossible_travel to confirm
  the Phase 2 additions didn't break them
"""
from __future__ import annotations

from datetime import datetime, timezone

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.mappers.identity import (
    IDENTITY_EXTRACTORS,
    extract_account_creation,
    extract_impossible_travel,
    extract_logon_success,
    extract_privilege_elevation,
    extract_suspicious_sign_in,
)


def _utc(hour: int = 14) -> datetime:
    return datetime(2026, 4, 10, hour, 0, 0, tzinfo=timezone.utc)


def _after_hours() -> datetime:
    return datetime(2026, 4, 10, 3, 30, 0, tzinfo=timezone.utc)


def _fired(signals: list[Signal], name: str) -> bool:
    for s in signals:
        if s.name == name:
            return s.fired
    raise AssertionError(f"signal {name!r} was not emitted")


# ─── extract_logon_success (EID 4624) ─────────────────────────────────────

class TestExtractLogonSuccess:

    def test_interactive_logon_emits_signals(self):
        raw = {
            "identity": {"upn": "alice@example.com"},
            "_logonType": "2",
            "device": {"hostname": "ALICE-LAPTOP"},
        }
        signals = extract_logon_success(raw, "informational", _utc())
        assert len(signals) >= 4

    def test_after_hours_logon_fires(self):
        raw = {"identity": {"upn": "alice@example.com"}}
        signals = extract_logon_success(raw, "informational", _after_hours())
        assert _fired(signals, "after_hours") is True

    def test_anomalous_ip_logon_fires(self):
        raw = {
            "identity": {"upn": "alice@example.com"},
            "ips": [{"role": "anomalous", "ipAddress": "203.0.113.99"}],
        }
        signals = extract_logon_success(raw, "informational", _utc())
        assert _fired(signals, "anomalous_ip") is True

    def test_benign_internal_logon_no_noise(self):
        raw = {"identity": {"upn": "alice@example.com"}}
        signals = extract_logon_success(raw, "informational", _utc())
        # None of the interesting signals should fire for a plain 14:00 logon
        assert _fired(signals, "after_hours") is False
        assert _fired(signals, "anomalous_ip") is False


# ─── extract_account_creation (EID 4720) ──────────────────────────────────

class TestExtractAccountCreation:

    def test_account_creation_fires_on_flag(self):
        raw = {"_accountCreated": True, "identity": {"upn": "admin@example.com"}}
        signals = extract_account_creation(raw, "high", _utc())
        assert _fired(signals, "account_creation") is True

    def test_account_creation_without_flag_no_fire(self):
        raw = {"identity": {"upn": "admin@example.com"}}
        signals = extract_account_creation(raw, "high", _utc())
        assert _fired(signals, "account_creation") is False

    def test_account_creation_after_hours_compounds(self):
        raw = {
            "_accountCreated": True,
            "identity": {"upn": "admin@example.com"},
        }
        signals = extract_account_creation(raw, "high", _after_hours())
        assert _fired(signals, "account_creation") is True
        assert _fired(signals, "after_hours") is True


# ─── Registry shows Phase 2 types ─────────────────────────────────────────

class TestIdentityRegistry:

    def test_logon_success_registered(self):
        assert "identity.logonSuccess" in IDENTITY_EXTRACTORS
        assert IDENTITY_EXTRACTORS["identity.logonSuccess"] is extract_logon_success

    def test_account_creation_registered(self):
        assert "identity.accountCreation" in IDENTITY_EXTRACTORS
        assert IDENTITY_EXTRACTORS["identity.accountCreation"] is extract_account_creation


# ─── Regression guards on existing extractors ─────────────────────────────

class TestExistingExtractorsRegression:
    """Smoke tests — confirm Phase 2 additions didn't break canonical payloads."""

    def test_suspicious_sign_in_still_fires(self):
        raw = {
            "identity": {
                "identityType": "user",
                "upn": "alice@example.com",
                "riskLevel": "high",
            },
            "ips": [
                {"role": "anomalous", "ipAddress": "203.0.113.10",
                 "geo": {"country": "US"}},
                {"role": "anomalous", "ipAddress": "198.51.100.5",
                 "geo": {"country": "RU"}},
            ],
            "device": {"hostname": "ALICE-LAPTOP", "managed": False},
        }
        signals = extract_suspicious_sign_in(raw, "medium", _utc())
        assert _fired(signals, "anomalous_ip") is True
        assert _fired(signals, "impossible_travel") is True
        assert _fired(signals, "unmanaged_device") is True
        assert _fired(signals, "high_risk_identity") is True

    def test_privilege_elevation_still_fires(self):
        raw = {
            "identity": {
                "identityType": "service_principal",
                "servicePrincipalId": "sp-1",
                "newPrivilegeTier": "admin",
            },
            "actor": {
                "identityType": "service_principal",
                "servicePrincipalId": "sp-2",
            },
        }
        signals = extract_privilege_elevation(raw, "high", _utc())
        assert _fired(signals, "actor_identity_mismatch") is True
        assert _fired(signals, "admin_role_grant") is True
        assert _fired(signals, "service_principal_actor") is True

    def test_impossible_travel_still_fires(self):
        raw = {
            "identity": {"upn": "ivy@example.com", "riskLevel": "high"},
            "ips": [
                {"role": "anomalous", "ipAddress": "203.0.113.77",
                 "geo": {"country": "FR"}},
                {"role": "anomalous", "ipAddress": "203.0.113.78",
                 "geo": {"country": "JP"}},
            ],
            "_distanceKm": 10000,
        }
        signals = extract_impossible_travel(raw, "medium", _utc())
        assert _fired(signals, "impossible_travel") is True
        assert _fired(signals, "impossible_travel_distance") is True
        assert _fired(signals, "high_risk_identity") is True
