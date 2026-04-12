"""Tests for the 6 Phase 2/3 endpoint extractors.

Covers:
- extract_powershell_execution  (PSBL / EventID 4104)
- extract_lsass_access          (Sysmon EID 10)
- extract_pipe_activity         (Sysmon EIDs 17/18)
- extract_wmi_persistence       (Sysmon EIDs 19/20/21)
- extract_mass_file_create      (Phase 1.2 aggregation)
- extract_state_drift           (Phase 3 drift events)

Each extractor returns a list[Signal] — the tests assert specific named
signals `fired` (or did not fire) for canonical payloads.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.mappers.endpoint import (
    extract_lsass_access,
    extract_mass_file_create,
    extract_pipe_activity,
    extract_powershell_execution,
    extract_state_drift,
    extract_wmi_persistence,
)


def _utc(hour: int = 14) -> datetime:
    # 14:00 UTC lands inside normal business hours in most zones so after-hours
    # signals do not fire from the time alone.
    return datetime(2026, 4, 10, hour, 0, 0, tzinfo=timezone.utc)


def _after_hours() -> datetime:
    # 03:30 UTC → definitely outside business hours
    return datetime(2026, 4, 10, 3, 30, 0, tzinfo=timezone.utc)


def _fired(signals: list[Signal], name: str) -> bool:
    """Did a signal with this name fire?"""
    for s in signals:
        if s.name == name:
            return s.fired
    raise AssertionError(f"signal {name!r} was not emitted at all")


def _emitted(signals: list[Signal], name: str) -> bool:
    """Was a signal with this name even emitted (regardless of fired state)?"""
    return any(s.name == name for s in signals)


# ─── extract_powershell_execution ──────────────────────────────────────────

class TestExtractPowershellExecution:

    def test_encoded_command_fires(self):
        raw = {"_encodedCommand": True}
        signals = extract_powershell_execution(raw, "medium", _utc())
        assert _fired(signals, "encoded_command") is True

    def test_download_cradle_fires(self):
        raw = {"_downloadCradle": True}
        signals = extract_powershell_execution(raw, "medium", _utc())
        assert _fired(signals, "download_cradle") is True

    def test_process_injection_fires(self):
        raw = {"_processInjection": True}
        signals = extract_powershell_execution(raw, "medium", _utc())
        assert _fired(signals, "process_injection") is True

    def test_lolbin_abuse_fires(self):
        raw = {"_lolbinAbuse": True}
        signals = extract_powershell_execution(raw, "medium", _utc())
        assert _fired(signals, "lolbin_abuse") is True

    def test_benign_payload_no_encoded_command(self):
        raw = {"commandLine": "Get-Date"}
        signals = extract_powershell_execution(raw, "medium", _utc())
        assert _fired(signals, "encoded_command") is False
        assert _fired(signals, "download_cradle") is False
        assert _fired(signals, "process_injection") is False

    def test_empty_payload_no_crash(self):
        signals = extract_powershell_execution({}, "medium", _utc())
        assert len(signals) >= 4  # at least the Phase 2 signals

    def test_after_hours_flag(self):
        raw = {"_encodedCommand": True}
        signals = extract_powershell_execution(raw, "medium", _after_hours())
        assert _fired(signals, "after_hours") is True


# ─── extract_lsass_access ──────────────────────────────────────────────────

class TestExtractLsassAccess:

    def test_lsass_access_fires_on_flag(self):
        raw = {"_lsassAccess": True}
        signals = extract_lsass_access(raw, "high", _utc())
        assert _fired(signals, "lsass_access") is True

    def test_lsass_access_not_fired_without_flag(self):
        raw = {}
        signals = extract_lsass_access(raw, "high", _utc())
        assert _fired(signals, "lsass_access") is False

    def test_server_target_detected(self):
        raw = {
            "_lsassAccess": True,
            "device": {"hostname": "dc-primary"},
        }
        signals = extract_lsass_access(raw, "high", _utc())
        assert _fired(signals, "server_target") is True
        assert _fired(signals, "lsass_access") is True


# ─── extract_pipe_activity ─────────────────────────────────────────────────

class TestExtractPipeActivity:

    def test_named_pipe_activity_fires(self):
        raw = {"_namedPipeActivity": True}
        signals = extract_pipe_activity(raw, "low", _utc())
        assert _fired(signals, "named_pipe_activity") is True

    def test_lateral_movement_pipe_fires(self):
        raw = {"_namedPipeActivity": True, "_lateralMovementPipe": True}
        signals = extract_pipe_activity(raw, "low", _utc())
        assert _fired(signals, "lateral_movement_pipe") is True

    def test_benign_pipe_no_lateral(self):
        raw = {"_namedPipeActivity": True}  # no lateral flag
        signals = extract_pipe_activity(raw, "low", _utc())
        assert _fired(signals, "named_pipe_activity") is True
        assert _fired(signals, "lateral_movement_pipe") is False

    def test_empty_payload_no_fire(self):
        signals = extract_pipe_activity({}, "low", _utc())
        assert _fired(signals, "named_pipe_activity") is False


# ─── extract_wmi_persistence ───────────────────────────────────────────────

class TestExtractWmiPersistence:

    def test_wmi_persistence_fires(self):
        raw = {"_wmiPersistence": True}
        signals = extract_wmi_persistence(raw, "high", _utc())
        assert _fired(signals, "wmi_persistence") is True

    def test_wmi_persistence_not_fired_without_flag(self):
        signals = extract_wmi_persistence({}, "high", _utc())
        assert _fired(signals, "wmi_persistence") is False

    def test_after_hours_fires_combined(self):
        raw = {"_wmiPersistence": True}
        signals = extract_wmi_persistence(raw, "high", _after_hours())
        assert _fired(signals, "wmi_persistence") is True
        assert _fired(signals, "after_hours") is True


# ─── extract_mass_file_create ──────────────────────────────────────────────

class TestExtractMassFileCreate:

    def test_mass_file_create_fires_above_threshold(self):
        raw = {"_fileCreateCount": 25}
        signals = extract_mass_file_create(raw, "high", _utc())
        assert _fired(signals, "mass_file_create") is True

    def test_mass_file_create_not_fired_at_boundary(self):
        # Threshold is `> 3` — exactly 3 should NOT fire
        raw = {"_fileCreateCount": 3}
        signals = extract_mass_file_create(raw, "medium", _utc())
        assert _fired(signals, "mass_file_create") is False

    def test_mass_file_create_just_above_threshold(self):
        raw = {"_fileCreateCount": 4}
        signals = extract_mass_file_create(raw, "medium", _utc())
        assert _fired(signals, "mass_file_create") is True

    def test_missing_file_count_no_fire(self):
        signals = extract_mass_file_create({}, "medium", _utc())
        assert _fired(signals, "mass_file_create") is False

    def test_combined_with_shadow_copy_deletion(self):
        raw = {"_fileCreateCount": 50, "_shadowCopyDeletion": True}
        signals = extract_mass_file_create(raw, "high", _utc())
        assert _fired(signals, "mass_file_create") is True
        assert _fired(signals, "shadow_copy_deletion") is True


# ─── extract_state_drift ───────────────────────────────────────────────────

class TestExtractStateDrift:

    def test_state_drift_service_added(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "EvilSvc",
        }
        signals = extract_state_drift(raw, "informational", _utc())
        assert _fired(signals, "state_drift") is True

    def test_state_drift_autorun_userland(self):
        raw = {
            "_stateCategory": "autorun",
            "_driftAction": "added",
            "_userlandAutorun": True,
        }
        signals = extract_state_drift(raw, "informational", _utc())
        assert _fired(signals, "state_drift") is True
        assert _fired(signals, "userland_autorun") is True

    def test_state_drift_scheduled_task_script(self):
        raw = {
            "_stateCategory": "scheduled_task",
            "_driftAction": "added",
            "_scriptScheduledTask": True,
        }
        signals = extract_state_drift(raw, "informational", _utc())
        assert _fired(signals, "state_drift") is True
        assert _fired(signals, "script_scheduled_task") is True

    def test_state_drift_unusual_service_path(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_unusualServicePath": True,
        }
        signals = extract_state_drift(raw, "informational", _utc())
        assert _fired(signals, "unusual_service_path") is True

    def test_missing_state_category_no_fire(self):
        signals = extract_state_drift({}, "informational", _utc())
        assert _fired(signals, "state_drift") is False
        assert _fired(signals, "unusual_service_path") is False
        assert _fired(signals, "userland_autorun") is False
        assert _fired(signals, "script_scheduled_task") is False

    def test_local_user_drift(self):
        raw = {
            "_stateCategory": "local_user",
            "_driftAction": "added",
            "_driftItem": "evil-backdoor",
        }
        signals = extract_state_drift(raw, "informational", _utc())
        assert _fired(signals, "state_drift") is True
