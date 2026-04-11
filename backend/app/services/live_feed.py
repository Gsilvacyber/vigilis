"""Live Enrichment Feed generator.

Processes all sample raw alerts through the enrichment pipeline and
returns a list of enrichment results ordered by event time, ready for
the UI to animate as a real-time feed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.app.fixtures.demo_fixtures import SAMPLE_RAW_ALERTS
from backend.app.services.enrichment import enrich_debug


_EVENT_OFFSETS: dict[str, int] = {
    "identity.suspiciousSignIn": 0,
    "identity.passwordSpray": 35,
    "identity.mfaFatigue": 72,
    "identity.oauthConsentRisk": 110,
    "identity.privilegeElevation": 145,
    "endpoint.malwareDetection": 190,
    "endpoint.suspiciousProcess": 230,
    "email.forwardingRule": 275,
    "cloud.secretStoreAccessAnomaly": 320,
    "network.impossibleGeoAccess": 370,
}


def generate_feed() -> list[dict[str, Any]]:
    """Process all sample alerts and return ordered feed items."""
    items: list[dict[str, Any]] = []

    for alert_type, raw_alert in SAMPLE_RAW_ALERTS.items():
        severity = "medium"
        offset = _EVENT_OFFSETS.get(alert_type, 0)
        event_time = datetime(2026, 3, 30, 14, 0, 0, tzinfo=timezone.utc)

        debug = enrich_debug(alert_type, severity, raw_alert, event_time)

        signals = []
        for s in debug.all_signals:
            signals.append({
                "signal": s.name,
                "weight": s.weight,
                "fired": s.fired,
                "label": s.label,
            })

        identity = raw_alert.get("identity") or raw_alert.get("user") or {}
        device = raw_alert.get("device") or {}
        ips_raw = raw_alert.get("ips") or []
        ip_list = []
        for ip_ent in ips_raw:
            if isinstance(ip_ent, dict):
                ip_list.append(ip_ent.get("ipAddress", ""))
            elif isinstance(ip_ent, str):
                ip_list.append(ip_ent)

        items.append({
            "alertType": alert_type,
            "category": alert_type.split(".")[0],
            "severity": severity,
            "offsetSeconds": offset,
            "identity": {
                "upn": identity.get("upn", ""),
                "displayName": identity.get("displayName", ""),
                "privilegeTier": identity.get("privilegeTier"),
            },
            "device": device.get("hostname", ""),
            "ips": ip_list[:3],
            "signals": signals,
            "signalsFired": sum(1 for s in signals if s["fired"]),
            "signalsTotal": len(signals),
            "scoreBreakdown": {
                "severityBase": debug.severity_base,
                "signalBoost": debug.signal_boost,
                "finalScore": debug.result.confidence_score,
                "label": debug.result.confidence_label,
            },
            "recommendedPlaybook": debug.result.recommended_playbook[:3],
            "recommendedActions": debug.result.recommended_actions[:3],
            "enrichmentNotes": debug.result.enrichment_notes[:3],
        })

    items.sort(key=lambda x: x["offsetSeconds"])
    return items
