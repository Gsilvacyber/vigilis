"""DLP (Data Loss Prevention) alert type extractors."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.services.enrichment.base import (
    Signal,
    has_anomalous_ip,
    is_privileged_identity,
    is_after_hours,
    get_action_status_weight,
    has_data_exfil_context,
    has_insider_threat_context,
)
from backend.app.services.enrichment.weights import W


def extract_sensitive_data_exposure(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("pii_detected", W["pii_detected"],
               bool(raw.get("_piiDetected") or raw.get("_classificationLabel")),
               "PII/PHI/PCI data detected in unauthorized location"),
        Signal("classification_violation", W["classification_violation"],
               bool(raw.get("_classificationViolation") or raw.get("_dlpPolicy")),
               "Data classification policy violation"),
        Signal("data_exfiltration_context", W["data_exfiltration_context"],
               has_data_exfil_context(raw),
               "Data exfiltration indicators present"),
        Signal("insider_data_exfil", W["insider_data_exfil"],
               has_insider_threat_context(raw),
               "Insider threat indicators with data exposure"),
        Signal("classified_data", W["classified_data"],
               bool(raw.get("_documentLabels")),
               "Classified document labels detected"),
        Signal("privileged_account", W["privileged_account"],
               is_privileged_identity(raw),
               "Privileged account involved in data exposure"),
        Signal("after_hours", W["after_hours"],
               is_after_hours(event_time),
               "Data exposure occurred outside business hours"),
        Signal("resignation_on_file", W["resignation_on_file"],
               raw.get("_insiderResignation") is True,
               "User has resignation on file"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status"),
    ]


DLP_EXTRACTORS = {
    "dlp.sensitiveDataExposure": extract_sensitive_data_exposure,
}
