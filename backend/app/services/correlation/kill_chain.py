"""Kill-chain stage definitions and analysis."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


# ── Kill-chain stage definitions (ordered by attack progression) ─────────

KILL_CHAIN_STAGES = [
    "reconnaissance",
    "initial_access",
    "credential_access",
    "privilege_escalation",
    "execution",
    "defense_evasion",
    "persistence",
    "lateral_movement",
    "collection",
    "exfiltration",
]

_STAGE_ORDER = {s: i for i, s in enumerate(KILL_CHAIN_STAGES)}

_ALERT_TYPE_TO_STAGE: dict[str, str] = {
    "email.forwardingRule": "persistence",
    "email.phishingDetected": "initial_access",
    "identity.suspiciousSignIn": "initial_access",
    "identity.passwordSpray": "credential_access",
    "identity.mfaFatigue": "credential_access",
    "identity.oauthConsentRisk": "credential_access",
    "identity.privilegeElevation": "privilege_escalation",
    "endpoint.malwareDetection": "execution",
    "endpoint.suspiciousProcess": "execution",
    "cloud.secretStoreAccessAnomaly": "exfiltration",
    "cloud.iamPrivilegeEscalation": "privilege_escalation",
    "cloud.suspiciousApiCall": "execution",
    "network.impossibleGeoAccess": "lateral_movement",
    "network.dataExfiltration": "exfiltration",
    "identity.impossibleTravel": "initial_access",
    "identity.dormantAccountLogin": "initial_access",
    "identity.serviceAccountAbuse": "credential_access",
    "endpoint.ransomwareDetection": "execution",
    "endpoint.lateralMovement": "lateral_movement",
    "endpoint.credentialDumping": "credential_access",
    "endpoint.persistenceMechanism": "persistence",
    "endpoint.defenseEvasion": "defense_evasion",
    "email.businessEmailCompromise": "initial_access",
    "email.maliciousAttachment": "initial_access",
    "network.commandAndControl": "lateral_movement",
    "network.portScan": "reconnaissance",
    "network.dnsAnomaly": "exfiltration",
    "cloud.resourceHijacking": "execution",
    "cloud.dataExposure": "exfiltration",
    "dlp.sensitiveDataExposure": "collection",
}

_STAGE_LABELS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "initial_access": "Initial Access",
    "credential_access": "Credential Access",
    "privilege_escalation": "Privilege Escalation",
    "execution": "Execution",
    "defense_evasion": "Defense Evasion",
    "persistence": "Persistence",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
}


def get_stage(alert_type: str) -> str:
    return _ALERT_TYPE_TO_STAGE.get(alert_type, "execution")


def refine_cloud_stage(case: Any) -> str:
    """Inspect a cloud case's enrichment signals/notes to detect sub-stages.

    Default cloud mapping is broad ("exfiltration" or "execution").  This
    function inspects the enrichment payload looking for signal names that
    reveal a more specific kill-chain stage.
    """
    base = get_stage(case.alert_type)
    enrichment = case.enrichment or {}
    notes: list[str] = enrichment.get("enrichmentNotes", [])
    notes_text = " ".join(str(n).lower() for n in notes)

    signals_text = (case.description or "").lower() + " " + notes_text

    persistence_keywords = {
        "createaccesskey", "admin_consent_grant", "new_service_principal",
        "scheduled_task", "backdoor",
    }
    priv_esc_keywords = {
        "privilege_level_admin", "admin_role_grant", "iamprivilegeescalation",
        "role_elevation", "privilege_escalation",
    }
    exfil_keywords = {
        "data_exfiltration", "bulk_transfer", "data_download",
        "large_data_transfer",
    }

    for kw in persistence_keywords:
        if kw in signals_text:
            return "persistence"
    for kw in priv_esc_keywords:
        if kw in signals_text:
            return "privilege_escalation"
    for kw in exfil_keywords:
        if kw in signals_text:
            return "exfiltration"

    return base


def stage_order(stage: str) -> int:
    return _STAGE_ORDER.get(stage, 4)


# ── Kill chain gap analysis ──────────────────────────────────────────────

_EXPECTED_INTERMEDIATE: dict[tuple[str, str], list[str]] = {
    ("initial_access", "privilege_escalation"): ["credential_access"],
    ("initial_access", "execution"): ["credential_access"],
    ("initial_access", "exfiltration"): ["credential_access", "execution"],
    ("initial_access", "lateral_movement"): ["credential_access"],
    ("credential_access", "exfiltration"): ["execution"],
    ("credential_access", "lateral_movement"): ["privilege_escalation"],
    ("privilege_escalation", "exfiltration"): ["execution"],
    ("execution", "exfiltration"): ["collection"],
}


def analyze_kill_chain_gaps(present_stages: list[str]) -> list[dict[str, Any]]:
    """Analyze which kill-chain stages are present, missing, or expected.

    Returns ordered list of all relevant stages with status:
    - present: confirmed in the incident
    - missing: expected between present stages but not observed
    - not_applicable: outside the incident's scope
    """
    if not present_stages:
        return []

    present_set = set(present_stages)
    present_orders = sorted(stage_order(s) for s in present_stages)
    min_order, max_order = present_orders[0], present_orders[-1]

    missing_set: set[str] = set()
    for (start, end), intermediates in _EXPECTED_INTERMEDIATE.items():
        if start in present_set and end in present_set:
            for mid in intermediates:
                if mid not in present_set:
                    missing_set.add(mid)

    result = []
    for stage in KILL_CHAIN_STAGES:
        order = _STAGE_ORDER[stage]
        if stage in present_set:
            status = "present"
        elif stage in missing_set:
            status = "missing"
        elif min_order <= order <= max_order:
            status = "missing"
        else:
            continue  # outside scope

        result.append({
            "stage": stage,
            "label": _STAGE_LABELS[stage],
            "status": status,
            "order": order,
        })

    return result


# ── Temporal kill chain validation ──────────────────────────────────────


@dataclass
class StageEvent:
    stage: str
    event_time: datetime
    case_id: str
    alert_type: str


def validate_temporal_order(stage_events: list[StageEvent]) -> dict[str, Any]:
    """Validate that kill chain stages occur in chronological order.

    Returns:
        {
            "valid": True/False,
            "anomalies": [{"expected_before": stage_a, "actual_before": stage_b, ...}],
            "stage_timeline": [{"stage": str, "time": str, "case_id": str}],
            "stage_deltas": {"stage_a->stage_b": seconds}
        }
    """
    if len(stage_events) < 2:
        return {"valid": True, "anomalies": [], "stage_timeline": [], "stage_deltas": {}}

    # Sort by event time
    sorted_events = sorted(stage_events, key=lambda e: e.event_time)

    # Build timeline of first occurrence per stage
    first_occurrence: dict[str, StageEvent] = {}
    for evt in sorted_events:
        if evt.stage not in first_occurrence:
            first_occurrence[evt.stage] = evt

    # Check temporal ordering against kill chain order
    anomalies: list[dict[str, str]] = []
    stage_order_map = {s: i for i, s in enumerate(KILL_CHAIN_STAGES)}

    timeline_entries = sorted(first_occurrence.values(), key=lambda e: e.event_time)
    for i in range(len(timeline_entries) - 1):
        curr = timeline_entries[i]
        next_evt = timeline_entries[i + 1]
        curr_order = stage_order_map.get(curr.stage, 99)
        next_order = stage_order_map.get(next_evt.stage, 99)
        if curr_order > next_order:
            anomalies.append({
                "expected_before": next_evt.stage,
                "actual_before": curr.stage,
                "expected_time": curr.event_time.isoformat(),
                "actual_time": next_evt.event_time.isoformat(),
            })

    # Compute deltas between consecutive stages
    stage_deltas: dict[str, float] = {}
    for i in range(len(timeline_entries) - 1):
        curr = timeline_entries[i]
        next_evt = timeline_entries[i + 1]
        key = f"{curr.stage}->{next_evt.stage}"
        delta = (next_evt.event_time - curr.event_time).total_seconds()
        stage_deltas[key] = delta

    stage_timeline = [
        {"stage": e.stage, "time": e.event_time.isoformat(), "case_id": str(e.case_id)}
        for e in timeline_entries
    ]

    return {
        "valid": len(anomalies) == 0,
        "anomalies": anomalies,
        "stage_timeline": stage_timeline,
        "stage_deltas": stage_deltas,
    }
