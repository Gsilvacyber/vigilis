"""Tests for entity_graph.check_state_drift and _extract_state_drift_pairs.

Target: Phase 3 state drift signal generation + relationship extraction.

Covers:
- TestStateDriftPairExtraction — one test per drift category
- TestStateDriftSignals — verified signals per category (unusual_service_path,
  userland_autorun, script_scheduled_task, privilege_escalation_drift, base)
- TestOperatorPrecedenceRegression — regression guard for the bug where
  `str(X or Y if cond else Z)` parsed as `str(X or (Y if cond else Z))`
  and produced the literal string 'none' when both sources were None
- TestNonAddedActions — modifications/removals should not fire signals
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.entity_graph import (
    _extract_state_drift_pairs,
    check_state_drift,
)


def _utc() -> datetime:
    return datetime(2026, 4, 10, 14, 0, 0, tzinfo=timezone.utc)


def _fired(signals: list[Signal], name: str) -> bool:
    for s in signals:
        if s.name == name and s.fired:
            return True
    return False


def _get_signal(signals: list[Signal], name: str) -> Signal | None:
    for s in signals:
        if s.name == name:
            return s
    return None


# ─── _extract_state_drift_pairs ────────────────────────────────────────────

class TestStateDriftPairExtraction:
    """Confirm each drift category maps to the correct entity-relationship tuple.

    Tuple format: (rel_type, a_type, a_value, b_type, b_value)
    """

    def test_service_drift_emits_host_service(self):
        raw = {
            "_stateCategory": "service",
            "_driftItem": "EvilSvc",
            "device": {"hostname": "VIGILIS-VM"},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert len(pairs) == 1
        rel_type, a_type, a_value, b_type, b_value = pairs[0]
        assert rel_type == "host_service"
        assert a_type == "host"
        assert a_value == "vigilis-vm"  # lowercased
        assert b_type == "service"
        assert b_value == "EvilSvc"

    def test_scheduled_task_drift_emits_host_scheduled_task(self):
        raw = {
            "_stateCategory": "scheduled_task",
            "_driftItem": "\\Microsoft\\EvilTask",
            "device": {"hostname": "WS-01"},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert len(pairs) == 1
        rel_type, _, _, b_type, _ = pairs[0]
        assert rel_type == "host_scheduled_task"
        assert b_type == "task"

    def test_autorun_drift_emits_host_autorun(self):
        raw = {
            "_stateCategory": "autorun",
            "_driftItem": "HKCU\\...\\Run\\Evil",
            "device": {"hostname": "WS-01"},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert len(pairs) == 1
        rel_type, _, _, b_type, _ = pairs[0]
        assert rel_type == "host_autorun"
        assert b_type == "autorun"

    def test_local_user_drift_emits_host_local_user(self):
        raw = {
            "_stateCategory": "local_user",
            "_driftItem": "evil-backdoor",
            "device": {"hostname": "WS-01"},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert len(pairs) == 1
        rel_type, _, _, b_type, _ = pairs[0]
        assert rel_type == "host_local_user"
        assert b_type == "user"

    def test_installed_program_drift_emits_host_installed_program(self):
        raw = {
            "_stateCategory": "installed_program",
            "_driftItem": "AnyDesk 7.0",
            "device": {"hostname": "WS-01"},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert len(pairs) == 1
        rel_type, _, _, b_type, _ = pairs[0]
        assert rel_type == "host_installed_program"
        assert b_type == "program"

    def test_missing_category_no_pairs(self):
        raw = {"_driftItem": "something", "device": {"hostname": "WS-01"}}
        pairs = _extract_state_drift_pairs(raw)
        assert pairs == []

    def test_missing_hostname_no_pairs(self):
        raw = {
            "_stateCategory": "service",
            "_driftItem": "EvilSvc",
            "device": {},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert pairs == []

    def test_unknown_category_no_pairs(self):
        raw = {
            "_stateCategory": "firewall_rule",  # not in map
            "_driftItem": "allow-everything",
            "device": {"hostname": "WS-01"},
        }
        pairs = _extract_state_drift_pairs(raw)
        assert pairs == []


# ─── check_state_drift — signal generation ────────────────────────────────

class TestStateDriftSignals:

    def test_base_state_drift_fires_on_added(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "AnySvc",
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "state_drift") is True

    def test_unusual_service_path_fires(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "EvilSvc",
            "_servicePath": "C:\\Users\\Public\\evil.exe",
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "unusual_service_path") is True
        assert raw.get("_unusualServicePath") is True

    def test_unusual_service_path_via_details_pathname(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "EvilSvc",
            "_driftDetails": {"pathName": "C:\\Temp\\bad.exe"},
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "unusual_service_path") is True

    def test_service_in_windows_no_unusual_path(self):
        # Service in C:\Windows\ should be fine
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "GoodSvc",
            "_servicePath": "C:\\Windows\\System32\\svchost.exe",
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "unusual_service_path") is False

    def test_service_in_program_files_no_unusual_path(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "GoodSvc",
            "_servicePath": "C:\\Program Files\\Vendor\\vendor.exe",
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "unusual_service_path") is False

    def test_userland_autorun_fires_on_appdata(self):
        raw = {
            "_stateCategory": "autorun",
            "_driftAction": "added",
            "_driftItem": "HKCU\\...\\Run\\Evil",
            "_driftDetails": {
                "target": "C:\\Users\\alice\\AppData\\Local\\evil.exe"
            },
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "userland_autorun") is True
        assert raw.get("_userlandAutorun") is True

    def test_userland_autorun_fires_on_roaming(self):
        raw = {
            "_stateCategory": "autorun",
            "_driftAction": "added",
            "_driftItem": "HKCU\\...\\Run\\Evil",
            "_driftDetails": {
                "target": "C:\\Users\\alice\\AppData\\Roaming\\evil.exe"
            },
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "userland_autorun") is True

    def test_autorun_in_program_files_no_fire(self):
        raw = {
            "_stateCategory": "autorun",
            "_driftAction": "added",
            "_driftItem": "HKLM\\...\\Run\\LegitApp",
            "_driftDetails": {
                "target": "C:\\Program Files\\Vendor\\update.exe"
            },
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "userland_autorun") is False

    def test_script_scheduled_task_fires_on_powershell(self):
        raw = {
            "_stateCategory": "scheduled_task",
            "_driftAction": "added",
            "_driftItem": "\\EvilTask",
            "_driftDetails": {
                "actions": "powershell.exe -nop -w hidden -c 'iex ...'"
            },
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "script_scheduled_task") is True
        assert raw.get("_scriptScheduledTask") is True

    def test_script_scheduled_task_fires_on_cmd(self):
        raw = {
            "_stateCategory": "scheduled_task",
            "_driftAction": "added",
            "_driftItem": "\\EvilTask",
            "_driftDetails": {
                "actions": "cmd.exe /c evil.bat"
            },
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "script_scheduled_task") is True

    def test_benign_scheduled_task_no_fire(self):
        raw = {
            "_stateCategory": "scheduled_task",
            "_driftAction": "added",
            "_driftItem": "\\Microsoft\\Update",
            "_driftDetails": {
                "actions": "C:\\Program Files\\Updater\\updater.exe --check"
            },
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "script_scheduled_task") is False

    def test_privilege_escalation_drift_on_local_admin(self):
        raw = {
            "_stateCategory": "local_user",
            "_driftAction": "added",
            "_driftItem": "adminbackdoor",  # contains "admin"
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "privilege_escalation_drift") is True
        assert raw.get("_privilegeEscalation") is True


# ─── TestOperatorPrecedenceRegression ─────────────────────────────────────

class TestOperatorPrecedenceRegression:
    """The bug fix: `str(X or Y if cond else Z)` parsed as
    `str(X or (Y if cond else Z))` and produced the literal string "none"
    when both X and Y were None. Lock in the fix with explicit tests."""

    def test_service_with_no_path_does_not_produce_none_string(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "PathlessSvc",
            "_servicePath": None,
            "_driftDetails": None,
        }
        signals = check_state_drift(raw, _utc())
        # Should NOT fire unusual_service_path because there is no path to check
        assert _fired(signals, "unusual_service_path") is False
        # No signal label should contain the literal string 'none'
        for s in signals:
            assert "none" not in s.label.lower() or "pathless" in s.label.lower()

    def test_service_with_none_details_dict_does_not_produce_none_string(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "PathlessSvc",
            "_driftDetails": {"pathName": None},
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "unusual_service_path") is False

    def test_service_with_empty_string_path_no_fire(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "added",
            "_driftItem": "EmptyPathSvc",
            "_servicePath": "",
            "_driftDetails": {"pathName": ""},
        }
        signals = check_state_drift(raw, _utc())
        assert _fired(signals, "unusual_service_path") is False


# ─── TestNonAddedActions ──────────────────────────────────────────────────

class TestNonAddedActions:
    """Modifications and removals should NOT fire drift signals — only additions."""

    def test_removed_service_no_signal(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "removed",
            "_driftItem": "EvilSvc",
            "_servicePath": "C:\\Temp\\evil.exe",
        }
        signals = check_state_drift(raw, _utc())
        assert len(signals) == 0

    def test_modified_service_no_signal(self):
        raw = {
            "_stateCategory": "service",
            "_driftAction": "modified",
            "_driftItem": "EvilSvc",
        }
        signals = check_state_drift(raw, _utc())
        assert len(signals) == 0

    def test_missing_action_no_signal(self):
        raw = {
            "_stateCategory": "service",
            "_driftItem": "EvilSvc",
        }
        signals = check_state_drift(raw, _utc())
        assert len(signals) == 0

    def test_missing_category_no_signal(self):
        raw = {
            "_driftAction": "added",
            "_driftItem": "EvilSvc",
        }
        signals = check_state_drift(raw, _utc())
        assert len(signals) == 0
