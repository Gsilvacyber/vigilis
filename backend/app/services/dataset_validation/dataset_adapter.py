"""Map rows from darkknight25/Advanced_SIEM_Dataset to SOCAI raw alert format.

The dataset has event_type + action. We map to SOCAI's 10 alert types.
Unmappable event types (ai, iot) are skipped.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

# event_type + action -> SOCAI alert type
_TYPE_MAP: dict[tuple[str, str], str] = {
    # auth
    ("auth", "failed"): "identity.suspiciousSignIn",
    ("auth", "locked"): "identity.passwordSpray",
    ("auth", "bypass"): "identity.suspiciousSignIn",
    ("auth", "success"): "identity.suspiciousSignIn",
    ("auth", "challenge"): "identity.mfaFatigue",
    ("auth", "timeout"): "identity.suspiciousSignIn",
    # endpoint
    ("endpoint", "file_access"): "endpoint.malwareDetection",
    ("endpoint", "memory_injection"): "endpoint.malwareDetection",
    ("endpoint", "driver_load"): "endpoint.malwareDetection",
    ("endpoint", "powershell_exec"): "endpoint.suspiciousProcess",
    ("endpoint", "wmi_exec"): "endpoint.suspiciousProcess",
    ("endpoint", "process_start"): "endpoint.suspiciousProcess",
    ("endpoint", "process_stop"): "endpoint.suspiciousProcess",
    ("endpoint", "service_install"): "endpoint.suspiciousProcess",
    ("endpoint", "registry_change"): "endpoint.suspiciousProcess",
    ("endpoint", "persistence_mechanism"): "endpoint.suspiciousProcess",
    ("endpoint", "scheduled_task"): "endpoint.suspiciousProcess",
    # network - only events with plausible geo/access relevance
    ("network", "data_exfiltration"): "network.impossibleGeoAccess",
    ("network", "covert_channel"): "network.impossibleGeoAccess",
    ("network", "beaconing"): "network.impossibleGeoAccess",
    ("network", "protocol_anomaly"): "network.impossibleGeoAccess",
    # skip: connection, latency_spike, disconnection, bandwidth_usage (operational, not geo)
    # cloud
    ("cloud", "permission_escalation"): "identity.privilegeElevation",
    ("cloud", "api_abuse"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "config_change"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "storage_access"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "lambda_execution"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "container_escape"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "crypto_mining"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "shadow_it"): "cloud.secretStoreAccessAnomaly",
    ("cloud", "instance_creation"): "cloud.secretStoreAccessAnomaly",
    # firewall - only quarantine has clear enrichment value
    ("firewall", "quarantine"): "endpoint.malwareDetection",
    # skip: deny, drop, allow, inspect, log-only (operational, no enrichment value)
    # ids_alert -> map by description keywords
}

_IDS_KEYWORD_MAP: list[tuple[str, str]] = [
    ("credential stuffing", "identity.passwordSpray"),
    ("password spray", "identity.passwordSpray"),
    ("brute force", "identity.passwordSpray"),
    ("phishing", "identity.suspiciousSignIn"),
    ("suspicious login", "identity.suspiciousSignIn"),
    ("lateral movement", "identity.suspiciousSignIn"),
    ("malware", "endpoint.malwareDetection"),
    ("ransomware", "endpoint.malwareDetection"),
    ("fileless", "endpoint.suspiciousProcess"),
    ("privilege escalation", "identity.privilegeElevation"),
    ("data exfiltration", "email.forwardingRule"),
    ("sql injection", "cloud.secretStoreAccessAnomaly"),
    ("xss", "cloud.secretStoreAccessAnomaly"),
    ("command injection", "endpoint.suspiciousProcess"),
    # skip: dns tunnel, port scan, ddos, man-in-the-middle (no good SOCAI type match)
]


def resolve_alert_type(row: dict[str, Any]) -> Optional[str]:
    """Map a dataset row to a SOCAI alert type. Returns None if unmappable."""
    et = row["event_type"]
    action = row.get("action") or ""

    if et in ("ai", "iot"):
        return None

    mapped = _TYPE_MAP.get((et, action))
    if mapped:
        return mapped

    if et == "ids_alert":
        desc = (row.get("description") or "").lower()
        for keyword, alert_type in _IDS_KEYWORD_MAP:
            if keyword in desc:
                return alert_type
        return None

    return None


def _sev_map(sev: str) -> str:
    """Map dataset severity to SOCAI severity."""
    return {
        "emergency": "critical",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
    }.get(sev, "medium")


def row_to_raw_alert(row: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Convert a dataset row into a SOCAI-compatible raw alert dict.

    Returns None if the row cannot be mapped.
    """
    alert_type = resolve_alert_type(row)
    if alert_type is None:
        return None

    meta = row.get("advanced_metadata") or {}
    ba = row.get("behavioral_analytics") or {}
    geo = meta.get("geo_location", "Unknown")
    sev = _sev_map(row.get("severity", "medium"))

    raw: dict[str, Any] = {}

    if alert_type.startswith("identity."):
        risk_score = meta.get("risk_score", 0) or 0
        has_freq_anomaly = bool(ba.get("frequency_anomaly"))
        has_seq_anomaly = bool(ba.get("sequence_anomaly"))
        deviation = ba.get("baseline_deviation", 0) or 0

        risk_level = sev
        if risk_score > 60 or deviation > 0.6:
            risk_level = "high"
        elif risk_score > 40 or deviation > 0.4:
            risk_level = "medium"

        priv = "standard"
        if risk_score > 70:
            priv = "admin"
        elif risk_score > 50:
            priv = "privileged"

        mfa = "enabled"
        if risk_score > 60 and has_freq_anomaly:
            mfa = "disabled"
        elif risk_score > 50:
            mfa = "not_registered"

        raw["identity"] = {
            "identityType": "user",
            "userId": row.get("user") or "unknown",
            "upn": f"{row.get('user', 'unknown')}@dataset.local",
            "displayName": row.get("user") or "Unknown",
            "riskLevel": risk_level,
            "privilegeTier": priv,
            "mfaStatus": mfa,
        }

        ips = []
        if row.get("src_ip"):
            role = "anomalous" if (has_freq_anomaly or risk_score > 50) else "observed"
            ips.append({"role": role, "ipAddress": row["src_ip"], "geo": {"country": geo}})
        if row.get("dst_ip") and row["dst_ip"] != "N/A" and has_seq_anomaly:
            dst_country = "US" if geo != "US" else "UK"
            ips.append({"role": "observed", "ipAddress": row["dst_ip"], "geo": {"country": dst_country}})
        if ips:
            raw["ips"] = ips

        if has_freq_anomaly or not ba.get("frequency_anomaly", True):
            raw["device"] = {
                "deviceId": f"d-{(row.get('process_id') or 0) % 500}",
                "hostname": f"WS-{(row.get('process_id') or 0) % 500}",
                "managed": not has_freq_anomaly,
                "os": "Windows",
            }

        if row.get("action") == "locked":
            raw["bulkTarget"] = {
                "count": max(10, int(risk_score)),
                "successCount": 1 if has_seq_anomaly else 0,
            }
        if row.get("action") == "challenge":
            raw["mfaPrompts"] = {
                "totalPrompts": max(3, int(risk_score / 10)),
                "deniedPrompts": max(2, int(risk_score / 15)),
                "eventualSuccess": has_seq_anomaly,
            }
        if alert_type == "identity.privilegeElevation":
            raw["identity"]["privilegeTier"] = "admin"
            raw["identity"]["newPrivilegeTier"] = "admin"
            target_user = f"target-{row.get('user', 'unknown')}"
            raw["roleChange"] = {
                "newRole": "Global Administrator",
                "actorId": row.get("user") or "system",
                "targetId": target_user,
            }
            raw["actor"] = {
                "identityType": "user",
                "userId": row.get("user") or "system",
                "upn": f"{row.get('user', 'system')}@dataset.local",
            }
            raw["identity"]["userId"] = target_user
            raw["identity"]["upn"] = f"{target_user}@dataset.local"

    if alert_type.startswith("endpoint."):
        raw["identity"] = {
            "identityType": "user",
            "userId": row.get("user") or "unknown",
            "upn": f"{row.get('user', 'unknown')}@dataset.local",
            "displayName": row.get("user") or "Unknown",
        }
        raw["device"] = {
            "deviceId": meta.get("device_hash", "d-unknown")[:12],
            "hostname": f"HOST-{(row.get('process_id') or 0) % 1000}",
            "managed": not ba.get("frequency_anomaly", False) if ba else True,
            "os": "Windows",
        }
        obj = row.get("object") or "unknown.exe"
        if alert_type == "endpoint.malwareDetection":
            raw["file"] = {
                "fileName": obj,
                "filePath": f"C:\\Users\\{row.get('user', 'unknown')}\\{obj}",
                "signed": not ba.get("frequency_anomaly", False) if ba else True,
                "prevalence": "rare" if meta.get("risk_score", 0) > 50 else "common",
            }
        if alert_type == "endpoint.suspiciousProcess":
            parent = row.get("parent_process") or "explorer.exe"
            action = row.get("action") or ""
            raw["process"] = {
                "processName": obj if "exec" in action else f"{action}.exe",
                "parentProcess": parent,
                "commandLine": f"{action} /encoded" if "powershell" in action else f"{action} {obj}",
                "processId": row.get("process_id") or 0,
            }
            if "powershell" in action:
                raw["process"]["commandLine"] = "powershell.exe -EncodedCommand <base64>"
                raw["process"]["processName"] = "powershell.exe"

    if alert_type.startswith("network.") or alert_type == "network.impossibleGeoAccess":
        risk_score = meta.get("risk_score", 0) or 0
        action = row.get("action") or ""
        inherently_suspicious = action in (
            "data_exfiltration", "covert_channel", "beaconing",
        )
        has_behavioral_evidence = bool(
            ba.get("sequence_anomaly") or ba.get("frequency_anomaly")
        )
        is_suspicious = inherently_suspicious or has_behavioral_evidence or risk_score > 60

        raw["identity"] = {
            "identityType": "user",
            "userId": row.get("user") or "network-system",
            "upn": f"{row.get('user', 'system')}@dataset.local",
            "displayName": row.get("user") or "Network System",
        }
        raw["device"] = {
            "deviceId": "net-device",
            "hostname": "NET-GW",
            "managed": True,
            "os": "Linux",
        }
        ips = []
        if row.get("src_ip"):
            role = "anomalous" if is_suspicious else "observed"
            ips.append({"role": role, "ipAddress": row["src_ip"], "geo": {"country": geo}})
        if row.get("dst_ip") and row["dst_ip"] != "N/A":
            if has_behavioral_evidence and geo != "US":
                dst_country = "US"
            elif inherently_suspicious and risk_score > 50 and geo != "US":
                dst_country = "US"
            else:
                dst_country = geo
            ips.append({"role": "observed", "ipAddress": row["dst_ip"], "geo": {"country": dst_country}})
        if not ips:
            ips.append({"role": "observed", "ipAddress": "0.0.0.0", "geo": {"country": geo}})
        raw["ips"] = ips

    if alert_type.startswith("cloud.") or alert_type == "cloud.secretStoreAccessAnomaly":
        raw["identity"] = {
            "identityType": "servicePrincipal" if not row.get("user") else "user",
            "userId": row.get("user") or "svc-unknown",
            "upn": f"{row.get('user', 'svc-unknown')}@dataset.local",
            "displayName": row.get("user") or "Service Principal",
        }
        raw["app"] = {
            "appId": f"app-{row.get('cloud_service', 'unknown')}",
            "displayName": row.get("cloud_service") or "Unknown Cloud App",
            "firstSeen": False,
        }
        if meta.get("risk_score", 0) > 50:
            raw["app"]["firstSeen"] = True
            raw["identity"]["privilegeTier"] = "admin"
        raw["secretAccess"] = {
            "vaultName": row.get("resource_id") or "default-vault",
            "secretName": f"secret-{row.get('action', 'unknown')}",
            "accessTime": row.get("timestamp", "").isoformat() if hasattr(row.get("timestamp", ""), "isoformat") else str(row.get("timestamp", "")),
        }

    if alert_type == "email.forwardingRule":
        raw["identity"] = {
            "identityType": "user",
            "userId": row.get("user") or "unknown",
            "upn": f"{row.get('user', 'unknown')}@dataset.local",
            "displayName": row.get("user") or "Unknown",
            "privilegeTier": "admin" if meta.get("risk_score", 0) > 60 else "standard",
        }
        raw["forwardingRule"] = {
            "destination": f"external-{row.get('user', 'unknown')}@external.com",
            "isExternal": True,
            "ruleCreatedAt": str(row.get("timestamp", "")),
        }

    return {
        "alertType": alert_type,
        "severity": sev,
        "rawAlert": raw,
        "datasetMeta": {
            "eventId": row.get("event_id"),
            "eventType": row.get("event_type"),
            "action": row.get("action"),
            "datasetRiskScore": meta.get("risk_score"),
            "datasetConfidence": meta.get("confidence"),
            "geo": geo,
            "description": row.get("description"),
            "behavioralDeviation": ba.get("baseline_deviation") if ba else None,
            "frequencyAnomaly": ba.get("frequency_anomaly") if ba else None,
            "sequenceAnomaly": ba.get("sequence_anomaly") if ba else None,
        },
    }
