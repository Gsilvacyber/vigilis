"""Regression: extract_suspicious_process must not crash when raw["process"]
is a dict instead of a string.

The dataset adapter (used for the public-data validation flow) sets
raw["process"] = {"processName": ..., "commandLine": ..., ...} for endpoint
alerts. Previously the endpoint extractor's keyword-context helpers called
.lower() on that dict, raising AttributeError mid-enrichment and surfacing
as ENRICHMENT_FAILED in the case detail.

These tests pin the dict shape that the dataset adapter actually produces.
"""
from __future__ import annotations

from datetime import datetime, timezone

from backend.app.services.enrichment.mappers.endpoint import (
    extract_suspicious_process,
)


def _utc() -> datetime:
    return datetime(2026, 4, 10, 14, 0, 0, tzinfo=timezone.utc)


def test_dict_shaped_process_does_not_crash():
    """The exact shape produced by dataset_adapter for endpoint alerts."""
    raw = {
        "process": {
            "processName": "powershell.exe",
            "commandLine": "powershell.exe -EncodedCommand <base64>",
            "parentProcess": "explorer.exe",
            "processId": 4242,
        },
        "file": {"fileName": "powershell.exe"},
    }
    signals = extract_suspicious_process(raw, "medium", _utc())
    assert signals, "extractor returned no signals on dict-shaped process"


def test_dict_shaped_process_keyword_context_still_detected():
    """Keywords inside the dict-nested commandLine should still reach the
    context-keyword check that drives signals like dc_target."""
    raw = {
        "process": {
            "processName": "evil.exe",
            "commandLine": "rubeus.exe asktgt /user:krbtgt",
        },
    }
    signals = extract_suspicious_process(raw, "high", _utc())
    fired_dc_target = any(
        s.name == "dc_target" and s.fired for s in signals
    )
    assert fired_dc_target, (
        "dc_target should fire on krbtgt keyword found inside dict-shaped "
        "process.commandLine"
    )


def test_string_shaped_process_unchanged():
    """The pre-existing string shape must continue to behave as before."""
    raw = {
        "process": "rubeus.exe",
        "commandLine": "rubeus.exe asktgt /user:krbtgt",
    }
    signals = extract_suspicious_process(raw, "high", _utc())
    fired_dc_target = any(
        s.name == "dc_target" and s.fired for s in signals
    )
    assert fired_dc_target, (
        "string-shaped process must still fire dc_target on the same keyword"
    )


def test_missing_process_field_does_not_crash():
    """Sparse alerts (no process info at all) should not crash either."""
    raw = {"file": {"fileName": "something.exe"}}
    signals = extract_suspicious_process(raw, "low", _utc())
    assert signals, "extractor crashed or returned no signals on sparse payload"
