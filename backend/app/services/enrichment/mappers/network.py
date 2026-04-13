from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.services.enrichment.weights import W
from backend.app.services.enrichment.base import (
    Signal,
    get_action_status_weight,
    has_anomalous_ip,
    has_c2_beaconing_context,
    has_data_exfil_context,
    has_dns_tunnel_context,
    has_insider_threat_context,
    has_iot_ot_context,
    has_lateral_movement_context,
    has_physical_safety_context,
    has_ransomware_context,
    has_supply_chain_context,
    is_after_hours,
    is_ir_response,
    is_privileged_identity,
    multi_country_ips,
)


def _has_successful_auth(raw: dict[str, Any]) -> bool:
    if raw.get("authResult") == "success":
        return True
    identity = raw.get("identity") or {}
    return identity.get("riskLevel") in ("high", "critical")


def extract_impossible_geo(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("multi_country_access", W["multi_country_access"], multi_country_ips(raw),
               "Authentication from multiple countries"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Access from anomalous IP address"),
        Signal("privileged_account", W["privileged_account"], is_privileged_identity(raw),
               "Privileged account involved in impossible travel"),
        Signal("successful_auth", W["successful_auth"], _has_successful_auth(raw),
               "Authentication was successful despite geographic anomaly"),
        # DNS tunneling / covert channel signals
        Signal("dns_tunnel", W["dns_tunnel"], has_dns_tunnel_context(raw),
               "DNS tunneling or covert channel detected"),
        Signal("data_exfiltration", W["data_exfiltration"], has_data_exfil_context(raw),
               "Data exfiltration indicators in network context"),
        Signal("bulk_transfer", W["bulk_transfer"],
               (raw.get("_transferSizeMB") or 0) > 500,
               f"Large data transfer: {raw.get('_transferSizeMB',0)}MB"),
        Signal("high_item_count", W["high_item_count"],
               (raw.get("_itemCount") or 0) > 100,
               f"High request volume: {raw.get('_itemCount',0)}"),
        Signal("source_high_risk", W["source_high_risk"], (raw.get("_sourceRiskScore") or 0) >= 80,
               f"Source system risk score: {raw.get('_sourceRiskScore',0)}"),
        Signal("supply_chain", W["supply_chain"], has_supply_chain_context(raw),
               "Supply chain or distribution compromise"),
        Signal("concurrent_sessions", W["concurrent_sessions"], bool(raw.get("_sessionIPs")),
               "Concurrent sessions from different locations"),
        Signal("impossible_travel_distance", W["impossible_travel_distance"],
               (raw.get("_distanceKm") or 0) > 1000,
               f"Impossible travel: {raw.get('_distanceKm',0)}km"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement — infection spreading to additional hosts"),
        Signal("iot_ot_attack", W["iot_ot_attack"], has_iot_ot_context(raw),
               "IoT/OT/ICS network attack — industrial protocol anomaly"),
        Signal("ot_protocol_write", W["ot_protocol_write"], raw.get("_otProtocolWrite") is True,
               "OT protocol write command — Modbus/CIP write to industrial controller"),
        Signal("physical_security_compromised", W["physical_security_compromised"], raw.get("_physicalSecurityCompromised") is True,
               "Physical security systems compromised — badge readers, cameras, door controls"),
        Signal("multiple_devices_compromised", W["multiple_devices_compromised"],
               (raw.get("_devicesCompromised") or 0) > 3,
               f"Multiple devices compromised: {raw.get('_devicesCompromised',0)}"),
        Signal("physical_safety_risk", W["physical_safety_risk"], has_physical_safety_context(raw),
               "Physical safety system at risk — potential equipment damage"),
        Signal("ransomware_chain", W["ransomware_chain"], has_ransomware_context(raw),
               "Ransomware attack chain indicators detected"),
        Signal("c2_beaconing", W["c2_beaconing"], has_c2_beaconing_context(raw),
               "Command and control beaconing pattern detected"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        # Noise / IR reduction
        Signal("noise_flag", W["noise_flag"], raw.get("_isNoise") is True,
               "Source flagged as noise — baseline activity"),
        Signal("ir_response", W["ir_response"], is_ir_response(raw),
               "Defensive/IR response action — not a threat"),
        # Catch-all: ensures every impossibleGeo case has at least 1 signal
        Signal("network_activity", W.get("network_activity", 1),
               True,
               "Network event detected"),
    ]


def extract_command_and_control(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("c2_beaconing", W["c2_beaconing"], has_c2_beaconing_context(raw),
               "Command and control beaconing pattern detected"),
        Signal("dns_tunnel", W["dns_tunnel"], has_dns_tunnel_context(raw),
               "DNS tunneling or covert C2 channel detected"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "C2 communication from anomalous IP address"),
        Signal("known_malicious_ip", W["known_malicious_ip"],
               bool(raw.get("_knownMaliciousIP") or raw.get("_threatIntelMatch")),
               "Destination IP matches known malicious infrastructure"),
        Signal("after_hours", W["after_hours"],
               is_after_hours(event_time, raw.get("_orgTimezone")),
               "C2 communication detected outside business hours"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        # Catch-all: ensures every commandAndControl case has at least 1 signal
        Signal("network_activity", W.get("network_activity", 1),
               True,
               "Network event detected"),
    ]


def extract_port_scan(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("port_scan_detected", W["port_scan_detected"],
               bool(raw.get("_portScanDetected") or raw.get("_scanActivity")),
               "Port scanning activity detected on network"),
        Signal("scan_volume", W["scan_volume"],
               (raw.get("_portsScanned") or 0) > 100,
               f"High scan volume: {raw.get('_portsScanned', 0)} ports scanned"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Port scan originating from anomalous IP address"),
        Signal("after_hours", W["after_hours"],
               is_after_hours(event_time, raw.get("_orgTimezone")),
               "Port scanning detected outside business hours"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        # Catch-all: ensures every portScan case has at least 1 signal
        Signal("network_activity", W.get("network_activity", 1),
               True,
               "Network event detected"),
    ]


def extract_dns_anomaly(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("dns_tunnel", W["dns_tunnel"], has_dns_tunnel_context(raw),
               "DNS tunneling or covert channel exfiltration detected"),
        Signal("data_exfiltration", W["data_exfiltration"], has_data_exfil_context(raw),
               "Data exfiltration indicators in DNS traffic"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "DNS queries directed to anomalous IP address"),
        Signal("bulk_transfer", W["bulk_transfer"],
               (raw.get("_transferSizeMB") or 0) > 500,
               f"High-volume DNS data transfer: {raw.get('_transferSizeMB', 0)}MB"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        # Catch-all: ensures every dnsAnomaly case has at least 1 signal
        Signal("network_activity", W.get("network_activity", 1),
               True,
               "Network event detected"),
    ]


def extract_data_exfiltration(
    raw: dict[str, Any], severity: str, event_time: datetime,
) -> list[Signal]:
    """Dedicated extractor for network.dataExfiltration — includes after_hours,
    bytes-aware bulk_transfer, and insider threat signals that the generic
    impossible_geo extractor lacks."""
    _action_w, _action_desc = get_action_status_weight(raw)
    _org_tz = raw.get("_orgTimezone") or None

    # Convert bytes to MB for volume-based signals
    _raw_bytes = raw.get("bytes") or raw.get("_bytes") or 0
    try:
        _mb = int(float(_raw_bytes)) / 1048576 if _raw_bytes else 0
    except (ValueError, TypeError):
        _mb = 0
    if not _mb:
        _mb = raw.get("_transferSizeMB") or 0

    return [
        Signal("data_exfiltration", W["data_exfiltration"], has_data_exfil_context(raw),
               "Data exfiltration indicators in network context"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time, _org_tz),
               "Data transfer occurred outside business hours"),
        Signal("bulk_transfer", W["bulk_transfer"], _mb > 100,
               f"Large data transfer: {_mb:.0f}MB" if _mb else "Large data transfer"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Access from anomalous IP address"),
        Signal("insider_data_exfil", W["insider_data_exfil"], has_insider_threat_context(raw),
               "Insider threat indicators with data exfiltration"),
        Signal("sensitive_subnet", W.get("sensitive_subnet", 8),
               any(raw.get("_additionalContext", "").startswith(p) for p in ("10.200.", "10.100.", "10.50."))
               or any(str((ip.get("ipAddress") or "") if isinstance(ip, dict) else ip).startswith(p)
                      for ip in (raw.get("ips") or []) for p in ("10.200.", "10.100.", "10.50.")),
               "Source IP in sensitive subnet"),
        Signal("resignation_on_file", W["resignation_on_file"],
               raw.get("_insiderResignation") is True,
               "User has resignation on file — heightened exfiltration risk"),
        Signal("c2_beaconing", W["c2_beaconing"], has_c2_beaconing_context(raw),
               "C2 beaconing pattern in data exfiltration"),
        Signal("dns_tunnel", W["dns_tunnel"], has_dns_tunnel_context(raw),
               "DNS tunneling detected alongside exfiltration"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        Signal("noise_flag", W["noise_flag"], raw.get("_isNoise") is True,
               "Source flagged as noise"),
        Signal("ir_response", W["ir_response"], is_ir_response(raw),
               "Defensive/IR response action"),
        # Catch-all: ensures every dataExfiltration case has at least 1 signal
        Signal("network_activity", W.get("network_activity", 1),
               True,
               "Network event detected"),
    ]


NETWORK_EXTRACTORS = {
    "network.impossibleGeoAccess": extract_impossible_geo,
    "network.dataExfiltration": extract_data_exfiltration,
    "network.commandAndControl": extract_command_and_control,
    "network.portScan": extract_port_scan,
    "network.dnsAnomaly": extract_dns_anomaly,
}
