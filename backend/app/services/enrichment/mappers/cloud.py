from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.services.enrichment.weights import W
from backend.app.services.enrichment.base import (
    Signal,
    get_action_status_weight,
    has_anomalous_ip,
    has_code_security_context,
    has_container_escape_context,
    has_data_exfil_context,
    has_dns_tunnel_context,
    has_external_ip,
    has_insider_threat_context,
    has_iot_ot_context,
    has_persistence_context,
    has_physical_safety_context,
    has_supply_chain_context,
    is_after_hours,
    is_ir_response,
    is_privileged_identity,
)

_KNOWN_PUBLISHERS = frozenset({"Microsoft", "Google", "Amazon", "HashiCorp"})

_SENSITIVE_SCOPES = frozenset({
    "Secrets.Get", "Secrets.List", "Keys.Get", "Keys.List",
    "Certificates.Get", "Storage.Read",
})


def _has_app_context(app: dict[str, Any]) -> bool:
    return bool(app.get("appId") or app.get("name"))


def _accesses_sensitive_scopes(app: dict[str, Any]) -> bool:
    scopes = set(app.get("scopes") or [])
    return bool(scopes & _SENSITIVE_SCOPES)


def _has_exfiltration_context(raw: dict[str, Any]) -> bool:
    """Check if additional context mentions data exfiltration."""
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    exfil_keywords = ["exfiltrat", "transfer", "dropbox", "mega.nz", "pastebin",
                      "outbound", "upload", "leaked", "dlp", "data loss",
                      "mining pool", "monero", "cryptomin"]
    return any(kw in combined for kw in exfil_keywords)


def extract_secret_store_anomaly(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    app = raw.get("app") or {}
    identity = raw.get("identity") or {}
    publisher = (app.get("publisher") or "").strip()
    has_app = _has_app_context(app)
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("data_exfiltration_context", W["data_exfiltration_context"], _has_exfiltration_context(raw),
               "Alert context indicates data exfiltration or unauthorized transfer"),
        Signal("privileged_accessor", W["privileged_accessor"], is_privileged_identity(raw),
               "Secret store accessed by privileged account"),
        Signal("sensitive_scopes", W["sensitive_scopes"], _accesses_sensitive_scopes(app),
               "Accessing sensitive secret/key scopes"),
        Signal("new_app", W["new_app"],
               has_app and app.get("firstSeenInTenantAt") is None,
               "Accessing application not previously seen in tenant"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Secret access from external anomalous IP"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Secret store accessed outside business hours"),
        Signal("unknown_publisher", W["unknown_publisher"],
               has_app and (not publisher or publisher not in _KNOWN_PUBLISHERS),
               "Application publisher not recognized"),
        Signal("service_principal_access", W["service_principal_access"],
               identity.get("identityType") in ("service_principal", "managed_identity"),
               "Access performed by service principal or managed identity"),
        Signal("external_ip", W["external_ip"], has_external_ip(raw),
               "Secret access from external IP address"),
        Signal("insider_data_exfil", W["insider_data_exfil"], has_data_exfil_context(raw),
               "Context indicates data exfiltration — bulk transfer, personal account, or physical media"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat indicators — resignation, unauthorized access, or no change ticket"),
        Signal("persistence", W["persistence"], has_persistence_context(raw),
               "Persistence mechanism — OAuth token, service principal, or certificate credential"),
        Signal("resignation_on_file", W["resignation_on_file"], raw.get("_insiderResignation") is True,
               "User has resignation on file — data exfiltration risk elevated"),
        Signal("bulk_transfer", W["bulk_transfer"],
               (raw.get("_transferSizeMB") or 0) > 500,
               f"Bulk data transfer detected ({raw.get('_transferSizeMB',0)}MB)"),
        Signal("high_item_count", W["high_item_count"],
               (raw.get("_itemCount") or 0) > 50,
               f"High volume: {raw.get('_itemCount',0)} items accessed/transferred"),
        Signal("classified_data", W["classified_data"],
               _has_classified_labels(raw.get("_documentLabels")),
               "Accessing classified or confidential documents"),
        Signal("access_anomaly", W["access_anomaly"],
               (raw.get("_accessDeviationPct") or 0) > 300,
               f"Access deviation {raw.get('_accessDeviationPct',0)}% above baseline"),
        Signal("financial_impact", W["financial_impact"],
               (raw.get("_financialImpact") or 0) > 0,
               f"Financial impact confirmed: ${raw.get('_financialImpact',0):,.0f}"),
        Signal("source_high_risk", W["source_high_risk"], (raw.get("_sourceRiskScore") or 0) >= 80,
               f"Source system risk score: {raw.get('_sourceRiskScore',0)}"),
        Signal("noise_flag", W["noise_flag"], raw.get("_isNoise") is True,
               "Source system flagged as noise — likely baseline activity"),
        Signal("ir_response", W["ir_response"], is_ir_response(raw),
               "Defensive/IR response action — not a threat"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        Signal("code_secret_exposed", W["code_secret_exposed"], has_code_security_context(raw),
               "Secret or credential exposed in code repository"),
        Signal("supply_chain_attack", W["supply_chain_attack"], has_supply_chain_context(raw),
               "Supply chain attack — malicious modification to distribution or pipeline"),
        Signal("dns_tunnel", W["dns_tunnel"], has_dns_tunnel_context(raw),
               "DNS tunneling or covert channel exfiltration detected"),
        Signal("container_escape", W["container_escape"], has_container_escape_context(raw),
               "Kubernetes container escape or cluster compromise"),
        Signal("iot_ot_attack", W["iot_ot_attack"], has_iot_ot_context(raw),
               "IoT/OT/ICS data access — SCADA/historian/industrial systems"),
        Signal("physical_safety_risk", W["physical_safety_risk"], has_physical_safety_context(raw),
               "Physical safety system data accessed — potential operational impact"),
        # Catch-all: ensures every secretStoreAccessAnomaly case has at least 1 signal
        Signal("cloud_activity", W.get("cloud_activity", 1),
               True,
               "Cloud event detected"),
    ]


def _has_classified_labels(labels: list | None) -> bool:
    if not labels:
        return False
    text = " ".join(str(l).lower() for l in labels)
    return any(kw in text for kw in ["confidential", "secret", "pii", "classified",
                                      "restricted", "legal", "privileged", "internal"])


def extract_resource_hijacking(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    _org_tz = raw.get("_orgTimezone") or None
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{ctx} {alert_name}"
    mining_keywords = ["mining", "cryptomin", "monero", "xmrig", "coinhive",
                       "stratum", "mining pool", "coin miner", "crypto miner"]
    return [
        Signal("mining_context", W["mining_context"],
               any(kw in combined for kw in mining_keywords),
               "Crypto mining or resource hijacking indicators detected"),
        Signal("crypto_mining_detected", W["crypto_mining_detected"],
               bool(raw.get("_cryptoMiningDetected") or raw.get("_miningProcess")),
               "Crypto mining process or connection confirmed"),
        Signal("container_escape", W["container_escape"],
               has_container_escape_context(raw),
               "Container escape detected — attacker may control host resources"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Resource access from anomalous IP address"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Resource hijacking detected outside business hours"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        # Catch-all: ensures every resourceHijacking case has at least 1 signal
        Signal("cloud_activity", W.get("cloud_activity", 1),
               True,
               "Cloud event detected"),
    ]


def extract_data_exposure(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("public_bucket_detected", W["public_bucket_detected"],
               bool(raw.get("_publicBucketDetected") or raw.get("_publicAccessEnabled")),
               "Public cloud storage bucket or container detected"),
        Signal("storage_misconfiguration", W["storage_misconfiguration"],
               bool(raw.get("_storageMisconfiguration") or raw.get("_aclMisconfigured")),
               "Cloud storage access control misconfiguration"),
        Signal("data_exfiltration_context", W["data_exfiltration_context"],
               has_data_exfil_context(raw),
               "Data exfiltration indicators present with exposed storage"),
        Signal("classified_data", W["classified_data"],
               _has_classified_labels(raw.get("_documentLabels")),
               "Classified or sensitive data in exposed storage"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        # Catch-all: ensures every dataExposure case has at least 1 signal
        Signal("cloud_activity", W.get("cloud_activity", 1),
               True,
               "Cloud event detected"),
    ]


def extract_iam_privilege_escalation(
    raw: dict[str, Any], severity: str, event_time: datetime,
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("admin_role_grant", W["admin_role_grant"],
               raw.get("_newPrivilegeTier") in ("admin", "privileged") or raw.get("_isAdminGroupMember") is True,
               "Admin-level IAM role or policy attached"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "IAM escalation from anomalous IP"),
        Signal("no_change_ticket", W.get("no_change_ticket", 12),
               raw.get("_hasChangeTicket") is False,
               "No change ticket for IAM privilege change"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "IAM escalation outside business hours"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Already-privileged account gaining more privileges"),
        Signal("persistence", W["persistence"], has_persistence_context(raw),
               "Persistence mechanism alongside privilege escalation"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status"),
        # Catch-all: ensures every iamPrivilegeEscalation case has at least 1 signal
        Signal("cloud_activity", W.get("cloud_activity", 1),
               True,
               "Cloud event detected"),
    ]


def extract_suspicious_api_call(
    raw: dict[str, Any], severity: str, event_time: datetime,
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    _org_tz = raw.get("_orgTimezone") or None
    return [
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Suspicious API call from anomalous IP"),
        Signal("data_exfiltration_context", W["data_exfiltration_context"],
               has_data_exfil_context(raw),
               "API call involves data access or exfiltration indicators"),
        Signal("bulk_transfer", W["bulk_transfer"],
               (raw.get("_transferSizeMB") or 0) > 500,
               "Large data transfer via API"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Suspicious API activity outside business hours"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Privileged identity making suspicious API calls"),
        Signal("service_principal_access", W["service_principal_access"],
               raw.get("_callerType") in ("ServicePrincipal", "Application"),
               "Service principal making anomalous API calls"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status"),
        # Catch-all: ensures every suspiciousApiCall case has at least 1 signal
        Signal("cloud_activity", W.get("cloud_activity", 1),
               True,
               "Cloud event detected"),
    ]


CLOUD_EXTRACTORS = {
    "cloud.secretStoreAccessAnomaly": extract_secret_store_anomaly,
    "cloud.iamPrivilegeEscalation": extract_iam_privilege_escalation,
    "cloud.suspiciousApiCall": extract_suspicious_api_call,
    "cloud.resourceHijacking": extract_resource_hijacking,
    "cloud.dataExposure": extract_data_exposure,
}
