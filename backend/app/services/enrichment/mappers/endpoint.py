from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.services.enrichment.weights import W
from backend.app.services.enrichment.base import (
    Signal,
    get_action_status_weight,
    has_ad_attack_context,
    has_anomalous_ip,
    has_c2_beaconing_context,
    has_container_escape_context,
    has_data_exfil_context,
    has_dns_tunnel_context,
    has_domain_admin_context,
    has_domain_admin_context_tiered,
    has_insider_threat_context,
    has_iot_ot_context,
    has_lateral_movement_context,
    has_persistence_context,
    has_physical_safety_context,
    has_ransomware_context,
    has_supply_chain_context,
    is_after_hours,
    is_privileged_identity,
    is_service_account,
)

_LOLBINS = frozenset({
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "msbuild.exe", "installutil.exe",
})

# Known hacking tools — if the process name or context mentions these, it's a threat
_KNOWN_ATTACK_TOOLS = frozenset({
    "dnscat2", "dnscat", "iodine", "dns2tcp",  # DNS tunneling
    "mimikatz", "rubeus", "impacket", "sharphound", "bloodhound",  # AD attack
    "cobalt strike", "cobaltstrike", "beacon",  # C2 frameworks
    "metasploit", "meterpreter",  # exploit frameworks
    "psexec", "crackmapexec", "evil-winrm",  # lateral movement
    "nmap", "masscan",  # recon
})

# System binaries that should only exist in system paths — if found elsewhere, masquerading
_SYSTEM_BINARIES = frozenset({
    "svchost.exe", "csrss.exe", "lsass.exe", "services.exe",
    "smss.exe", "winlogon.exe", "explorer.exe", "taskhost.exe",
})
_SYSTEM_PATHS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\")

_SUSPICIOUS_PATHS = ("\\temp\\", "\\tmp\\", "\\downloads\\",
                     "\\appdata\\", "\\programdata\\", "\\public\\")

_SERVER_HOSTNAMES = ("dc-", "srv-", "server-", "ad-", "sql-", "db-", "file-")

# Known bad hashes (sample — in production this would be a threat intel feed)
_KNOWN_BAD_HASHES = frozenset({
    "e3b0c44298fc1c149afbf4c8996fb924",  # empty file hash often used in test malware
})


def _is_unsigned(raw: dict[str, Any]) -> bool:
    f = raw.get("file") or {}
    signer = (f.get("signer") or "").strip()
    return not signer or signer.lower() == "unknown"


def _suspicious_path(raw: dict[str, Any]) -> bool:
    f = raw.get("file") or {}
    path = (f.get("filePath") or "").lower()
    return any(p in path for p in _SUSPICIOUS_PATHS)


def _is_server(raw: dict[str, Any]) -> bool:
    device = raw.get("device") or {}
    hostname = (device.get("hostname") or "").lower()
    return any(hostname.startswith(p) for p in _SERVER_HOSTNAMES)


def _has_context_keywords(raw: dict[str, Any], keywords: list[str]) -> bool:
    """Check if additional context, alert name, description, or command line
    contains any of the keywords.

    NOTE: For Sysmon-sourced events, the detection data lives in `commandLine`
    and `process` rather than `_additionalContext`. We concatenate all of these
    so keyword detection works regardless of source.
    """
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    cmdline = (raw.get("commandLine") or raw.get("_commandLine") or "").lower()
    process = (raw.get("process") or raw.get("_processName") or "").lower()
    combined = f"{ctx} {alert_name} {desc} {cmdline} {process}"
    return any(kw in combined for kw in keywords)


def _is_masquerading(raw: dict[str, Any]) -> bool:
    """Detect process name masquerading — system binary name in non-system path."""
    f = raw.get("file") or {}
    name = (f.get("fileName") or "").lower()
    path = (f.get("filePath") or "").lower()
    # Check for system binary names in wrong locations
    for sysbin in _SYSTEM_BINARIES:
        base = sysbin.replace(".exe", "")
        # Match svchost32.exe, svchost_.exe, etc. (close but not exact)
        if base in name and name != sysbin:
            return True
        # Exact name but wrong path
        if name == sysbin and path and not any(sp in path for sp in _SYSTEM_PATHS):
            return True
    return False


def _has_known_attack_tool(raw: dict[str, Any]) -> bool:
    """Check if process name, file path, or context mentions a known attack tool."""
    f = raw.get("file") or {}
    name = (f.get("fileName") or "").lower()
    path = (f.get("filePath") or "").lower()
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    combined = f"{name} {path} {ctx} {alert_name}"
    return any(tool in combined for tool in _KNOWN_ATTACK_TOOLS)


def _has_known_bad_hash(raw: dict[str, Any]) -> bool:
    f = raw.get("file") or {}
    sha = (f.get("sha256") or "").lower().strip()
    md5 = (f.get("md5") or "").lower().strip()
    return sha in _KNOWN_BAD_HASHES or md5 in _KNOWN_BAD_HASHES


def _is_lolbin(raw: dict[str, Any]) -> bool:
    f = raw.get("file") or {}
    name = (f.get("fileName") or "").lower()
    return name in _LOLBINS


# ---------------------------------------------------------------------------
# endpoint.malwareDetection
# ---------------------------------------------------------------------------

def extract_malware_detection(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    f = raw.get("file") or {}
    device = raw.get("device") or {}
    return [
        Signal("known_bad_hash", W["known_bad_hash"], _has_known_bad_hash(raw),
               "File hash matches known malicious indicator"),
        Signal("rare_file", W["rare_file"],
               f.get("prevalence") in ("rare", "unknown"),
               "Detected file has rare or unknown prevalence"),
        Signal("unsigned_binary", W["unsigned_binary"], _is_unsigned(raw),
               "Binary is unsigned or has unknown signer"),
        Signal("suspicious_path", W["suspicious_path"], _suspicious_path(raw),
               "File located in suspicious directory (Downloads, Temp, AppData)"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "Malware detected on a server — higher blast radius"),
        Signal("unmanaged_device", W["unmanaged_device"],
               device.get("managed") is False,
               "Malware found on unmanaged device"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Malware executed under privileged account"),
        Signal("ransomware_context", W["ransomware_context"],
               _has_context_keywords(raw, ["ransomware", "ransom", "encrypt", "waveshaper", "yara"]),
               "Alert context indicates ransomware or destructive malware"),
        Signal("mining_context", W["mining_context"],
               _has_context_keywords(raw, ["mining", "monero", "xmrig", "cryptomin", "coinhive"]),
               "Cryptomining activity detected"),
        Signal("insider_data_exfil", W["insider_data_exfil"], has_data_exfil_context(raw),
               "Data exfiltration via endpoint — USB, bulk copy, or personal account"),
        Signal("insider_threat", W["insider_threat"], has_insider_threat_context(raw),
               "Insider threat indicators detected in alert context"),
        Signal("supply_chain_attack", W["supply_chain_attack"], has_supply_chain_context(raw),
               "Supply chain attack — malicious modification to software distribution"),
        Signal("dns_tunnel", W["dns_tunnel"], has_dns_tunnel_context(raw),
               "DNS tunneling tool or covert channel detected"),
        Signal("masquerading", W["masquerading"], _is_masquerading(raw),
               "Process masquerading as system binary — name mimics legitimate process"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known attack tool detected (dnscat2, mimikatz, cobalt strike, etc.)"),
        Signal("container_escape", W["container_escape"], has_container_escape_context(raw),
               "Kubernetes container escape or cluster compromise detected"),
        Signal("iot_ot_attack", W["iot_ot_attack"], has_iot_ot_context(raw),
               "IoT/OT/ICS attack — industrial control system compromise"),
        Signal("physical_safety_risk", W["physical_safety_risk"], has_physical_safety_context(raw),
               "Physical safety system at risk — potential equipment damage or harm"),
        Signal("cve_exploited", W["cve_exploited"], raw.get("_cveExploited") is True,
               "Known CVE exploited on target device"),
        Signal("program_hash_mismatch", W["program_hash_mismatch"], raw.get("_programHashMismatch") is True,
               "PLC/controller program modified — hash does not match baseline"),
        Signal("unpatched_device", W["unpatched_device"], (raw.get("_unpatchedDays") or 0) > 30,
               f"Device unpatched for {raw.get('_unpatchedDays',0)} days"),
        Signal("ransomware_chain", W["ransomware_chain"], has_ransomware_context(raw),
               "Ransomware attack indicators — encryption, shadow deletion, or extortion"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        Signal("resignation_on_file", W["resignation_on_file"], raw.get("_insiderResignation") is True,
               "User has resignation on file — malware/exfil risk elevated"),
        Signal("bulk_transfer", W["bulk_transfer"],
               (raw.get("_transferSizeMB") or 0) > 500,
               f"Bulk data transfer: {raw.get('_transferSizeMB',0)}MB"),
        Signal("high_item_count", W["high_item_count"],
               (raw.get("_itemCount") or 0) > 50,
               f"High volume: {raw.get('_itemCount',0)} items"),
    ]


# ---------------------------------------------------------------------------
# endpoint.suspiciousProcess
# ---------------------------------------------------------------------------

def extract_suspicious_process(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    f = raw.get("file") or {}
    name = (f.get("fileName") or "").lower()
    return [
        Signal("living_off_the_land", W["living_off_the_land"], _is_lolbin(raw),
               f"LOLBin detected: {name}" if _is_lolbin(raw) else "Known LOLBin used"),
        Signal("powershell_on_server", W["powershell_on_server"],
               "powershell" in name and _is_server(raw),
               "PowerShell execution on server — potential lateral movement tool"),
        Signal("unsigned_binary", W["unsigned_binary"], _is_unsigned(raw) and not _is_lolbin(raw),
               "Process binary is unsigned"),
        Signal("suspicious_path", W["suspicious_path"], _suspicious_path(raw),
               "Process executed from suspicious path"),
        Signal("server_execution", W["server_execution"], _is_server(raw) and not _is_lolbin(raw),
               "Suspicious process on server infrastructure"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Process executed under privileged account"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack technique (BloodHound, GPO modification, WMI persistence)"),
        Signal("domain_admin_context", W["domain_admin_context"], has_domain_admin_context(raw),
               "Domain Admin level activity — domain-wide impact possible",
               tier=has_domain_admin_context_tiered(raw)[1] if has_domain_admin_context(raw) else "inferred"),
        Signal("dc_target", W["dc_target"],
               _has_context_keywords(raw, ["domain controller", "dc-primary", "dc-secondary", "krbtgt"]),
               "Activity targeting domain controller infrastructure"),
        Signal("supply_chain_process", W["supply_chain_process"], has_supply_chain_context(raw),
               "Supply chain attack — malicious code injection or pipeline compromise"),
        Signal("dns_tunnel_process", W["dns_tunnel_process"], has_dns_tunnel_context(raw),
               "DNS tunneling tool detected — covert C2 or exfiltration channel"),
        Signal("masquerading", W["masquerading"], _is_masquerading(raw),
               "Process masquerading as system binary"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known attack tool detected"),
        Signal("container_escape", W["container_escape"], has_container_escape_context(raw),
               "Container escape or Kubernetes cluster compromise"),
        Signal("iot_ot_attack", W["iot_ot_attack"], has_iot_ot_context(raw),
               "IoT/OT/ICS attack detected in process context"),
        Signal("physical_safety_risk", W["physical_safety_risk"], has_physical_safety_context(raw),
               "Physical safety system at risk"),
        Signal("ransomware_chain", W["ransomware_chain"], has_ransomware_context(raw),
               "Ransomware attack chain — credential dump, lateral movement, or GPO deployment"),
        # Phase 3 additions — action status, service account, C2, lateral movement
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        Signal("service_account_process", W["service_account_process"], is_service_account(raw),
               "Suspicious process executed under service account — potential credential compromise"),
        Signal("c2_beaconing", W["c2_beaconing"], has_c2_beaconing_context(raw),
               "Command and control beaconing pattern detected"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement detected — infection spreading to additional hosts"),
    ]


# ---------------------------------------------------------------------------
# endpoint.ransomwareDetection
# ---------------------------------------------------------------------------

def extract_ransomware_detection(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    f = raw.get("file") or {}
    device = raw.get("device") or {}
    return [
        Signal("shadow_copy_deletion", W["shadow_copy_deletion"],
               _has_context_keywords(raw, ["vssadmin", "shadow", "delete shadows", "bcdedit"]),
               "Shadow copy deletion detected — active ransomware indicator"),
        Signal("mass_file_encryption", W["mass_file_encryption"],
               _has_context_keywords(raw, ["encrypt", "encrypted files", "mass encryption", "file extension change"]),
               "Mass file encryption activity detected"),
        Signal("ransomware_chain", W["ransomware_chain"], has_ransomware_context(raw),
               "Ransomware attack chain indicators present"),
        Signal("ransomware_context", W["ransomware_context"],
               _has_context_keywords(raw, ["ransomware", "ransom note", "ransom demand", "extortion"]),
               "Ransomware family or ransom note detected"),
        Signal("ransomware_extortion", W["ransomware_extortion"],
               _has_context_keywords(raw, ["extortion", "double extortion", "data leak site"]),
               "Ransomware extortion — data leak or double extortion threat"),
        Signal("known_bad_hash", W["known_bad_hash"], _has_known_bad_hash(raw),
               "File hash matches known ransomware indicator"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "Ransomware detected on server — critical blast radius"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Ransomware executed under privileged account"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement detected — ransomware spreading to additional hosts"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known attack tool detected in ransomware chain"),
        Signal("suspicious_path", W["suspicious_path"], _suspicious_path(raw),
               "Ransomware payload executed from suspicious directory"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Ransomware activity detected outside business hours"),
    ]


# ---------------------------------------------------------------------------
# endpoint.lateralMovement
# ---------------------------------------------------------------------------

def extract_lateral_movement(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    device = raw.get("device") or {}
    return [
        Signal("remote_service_abuse", W["remote_service_abuse"],
               _has_context_keywords(raw, ["psexec", "wmi", "winrm", "smbexec", "dcom", "remote service"]),
               "Remote service abuse detected — PsExec, WMI, or WinRM used for lateral movement"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement pattern detected across hosts"),
        Signal("internal_pivot_detected", W["internal_pivot_detected"],
               _has_context_keywords(raw, ["pivot", "internal pivot", "east-west", "host hopping"]),
               "Internal pivot detected — attacker moving between hosts"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known lateral movement tool detected (PsExec, CrackMapExec, etc.)"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Lateral movement using privileged credentials"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "Lateral movement targeting server infrastructure"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Anomalous source IP for lateral movement activity"),
        Signal("c2_beaconing", W["c2_beaconing"], has_c2_beaconing_context(raw),
               "C2 beaconing detected — lateral movement may be orchestrated"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack context in lateral movement chain"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Lateral movement detected outside business hours"),
        Signal("service_account_process", W["service_account_process"], is_service_account(raw),
               "Lateral movement using service account credentials"),
        Signal("multiple_devices_compromised", W["multiple_devices_compromised"],
               _has_context_keywords(raw, ["multiple hosts", "multiple devices", "spread", "propagat"]),
               "Multiple devices compromised in lateral movement campaign"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
    ]


# ---------------------------------------------------------------------------
# endpoint.credentialDumping
# ---------------------------------------------------------------------------

def extract_credential_dumping(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    f = raw.get("file") or {}
    return [
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "Active Directory attack — credential dumping via LSASS, DCSync, or Kerberoasting"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known credential dumping tool detected (mimikatz, rubeus, impacket)"),
        Signal("domain_admin_context", W["domain_admin_context"], has_domain_admin_context(raw),
               "Domain Admin credentials targeted — domain-wide compromise possible",
               tier=has_domain_admin_context_tiered(raw)[1] if has_domain_admin_context(raw) else "inferred"),
        Signal("dc_target", W["dc_target"],
               _has_context_keywords(raw, ["domain controller", "dcsync", "krbtgt", "ntds.dit"]),
               "Domain controller targeted for credential extraction"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Credential dumping targeting privileged account"),
        Signal("masquerading", W["masquerading"], _is_masquerading(raw),
               "Process masquerading detected during credential dumping"),
        Signal("suspicious_path", W["suspicious_path"], _suspicious_path(raw),
               "Credential dumping tool executed from suspicious path"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "Credential dumping on server — all cached credentials at risk"),
        Signal("lateral_movement", W["lateral_movement"], has_lateral_movement_context(raw),
               "Lateral movement following credential dump — attacker using stolen credentials"),
        Signal("living_off_the_land", W["living_off_the_land"], _is_lolbin(raw),
               "LOLBin used for credential access (comsvcs.dll, procdump, etc.)"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Credential dumping detected outside business hours"),
        Signal("service_account_process", W["service_account_process"], is_service_account(raw),
               "Credential dumping executed under service account"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
    ]


# ---------------------------------------------------------------------------
# endpoint.persistenceMechanism
# ---------------------------------------------------------------------------

def extract_persistence_mechanism(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    f = raw.get("file") or {}
    return [
        Signal("persistence_mechanism", W["persistence_mechanism"], has_persistence_context(raw),
               "Persistence mechanism detected — scheduled task, service, or registry modification"),
        Signal("living_off_the_land", W["living_off_the_land"], _is_lolbin(raw),
               "LOLBin used to establish persistence (schtasks, sc, reg)"),
        Signal("suspicious_path", W["suspicious_path"], _suspicious_path(raw),
               "Persistence payload located in suspicious directory"),
        Signal("unsigned_binary", W["unsigned_binary"], _is_unsigned(raw),
               "Persistence mechanism uses unsigned binary"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Persistence established under privileged account"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "Persistence mechanism on server infrastructure"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known attack tool used to establish persistence"),
        Signal("masquerading", W["masquerading"], _is_masquerading(raw),
               "Persistence binary masquerading as system process"),
        Signal("insider_persistence", W["insider_persistence"],
               _has_context_keywords(raw, ["insider", "backdoor", "unauthorized access"]),
               "Insider persistence — backdoor or unauthorized access mechanism"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Persistence mechanism created outside business hours"),
        Signal("service_account_process", W["service_account_process"], is_service_account(raw),
               "Persistence established under service account"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
    ]


# ---------------------------------------------------------------------------
# endpoint.defenseEvasion
# ---------------------------------------------------------------------------

def extract_defense_evasion(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    _action_w, _action_desc = get_action_status_weight(raw)
    f = raw.get("file") or {}
    return [
        Signal("av_disabled", W["av_disabled"],
               _has_context_keywords(raw, ["av disabled", "antivirus disabled", "tamper protection", "edr disabled",
                                           "defender disabled", "real-time protection"]),
               "Antivirus or EDR protection disabled"),
        Signal("log_cleared", W["log_cleared"],
               _has_context_keywords(raw, ["log cleared", "event log", "wevtutil", "clear-eventlog", "1102"]),
               "Event logs cleared — evidence destruction detected"),
        Signal("defense_evasion_detected", W["defense_evasion_detected"],
               _has_context_keywords(raw, ["amsi bypass", "etw patch", "process injection", "dll injection",
                                           "process hollowing", "unhooking"]),
               "Defense evasion technique detected — AMSI bypass, ETW patching, or process injection"),
        Signal("masquerading", W["masquerading"], _is_masquerading(raw),
               "Process masquerading as system binary to evade detection"),
        Signal("living_off_the_land", W["living_off_the_land"], _is_lolbin(raw),
               "LOLBin used for defense evasion"),
        Signal("unsigned_binary", W["unsigned_binary"], _is_unsigned(raw),
               "Unsigned binary used in evasion technique"),
        Signal("suspicious_path", W["suspicious_path"], _suspicious_path(raw),
               "Evasion tool executed from suspicious path"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "Defense evasion by privileged account — elevated access to disable controls"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "Defense evasion on server — security controls compromised on critical infrastructure"),
        Signal("known_attack_tool", W["known_attack_tool"], _has_known_attack_tool(raw),
               "Known attack tool used for defense evasion"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Defense evasion detected outside business hours"),
        Signal("anomalous_ip", W["anomalous_ip"], has_anomalous_ip(raw),
               "Defense evasion activity from anomalous IP address"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
    ]


# ---------------------------------------------------------------------------
# Phase 2 new alert type extractors (stubs — real signals come from translator)
# ---------------------------------------------------------------------------
# These extractors are minimal because the Phase 2 data sources (PowerShell
# Script Block Logging, Sysmon EID 10/17-21, Windows Security Event Log) all
# land their detection in structured fields (`_lsassAccess`, `_wmiPersistence`,
# `_namedPipeActivity`, `_accountCreated`, etc.) via `sysmon_translator`.
# The extractors below just fire base signals that read those fields — the
# tier-aware helpers in base.py do the real work.

def extract_powershell_execution(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    """PowerShell Script Block Logging (EventID 4104) events.

    All the detection happens in sysmon_translator via the 62 MITRE patterns
    that match command line text. The command line field is populated with
    `ScriptBlockText[:2000]` by the PSBL exporter.
    """
    _action_w, _action_desc = get_action_status_weight(raw)
    return [
        Signal("encoded_command", W.get("encoded_command", 18),
               raw.get("_encodedCommand") is True,
               "PowerShell encoded/obfuscated command detected"),
        Signal("download_cradle", W.get("download_cradle", 18),
               raw.get("_downloadCradle") is True,
               "PowerShell download-and-execute cradle"),
        Signal("lolbin_abuse", W.get("lolbin_abuse", 15),
               raw.get("_lolbinAbuse") is True,
               "LOLBin abuse detected in PowerShell"),
        Signal("process_injection", W["process_injection"],
               raw.get("_processInjection") is True,
               "Process injection API calls detected"),
        Signal("ransomware_chain", W["ransomware_chain"],
               has_ransomware_context(raw),
               "Ransomware attack chain indicators"),
        Signal("action_status", _action_w, _action_w != 0,
               _action_desc or "Action status scoring"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "PowerShell executed outside business hours"),
    ]


def extract_lsass_access(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    """Sysmon EID 10 events targeting LSASS — the credential dumping signal.

    The translator's event-ID fork sets `_lsassAccess=True` and MITRE T1003.001.
    The ransomware/AD attack tier-aware helpers in base.py read this field.
    """
    return [
        Signal("lsass_access", W["lsass_access"],
               raw.get("_lsassAccess") is True,
               "Process accessing LSASS memory — credential dumping indicator"),
        Signal("ransomware_chain", W["ransomware_chain"],
               has_ransomware_context(raw),
               "LSASS access combined with ransomware indicators"),
        Signal("ad_attack", W["ad_attack"], has_ad_attack_context(raw),
               "AD attack context with LSASS access"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "LSASS access under privileged account"),
        Signal("server_target", W["server_target"], _is_server(raw),
               "LSASS access on server — higher blast radius"),
    ]


def extract_pipe_activity(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    """Sysmon EIDs 17/18 — named pipe create/connect events.

    Translator sets `_namedPipeActivity=True` and optionally `_lateralMovementPipe=True`
    when the pipe name matches PsExec/Impacket patterns.
    """
    return [
        Signal("named_pipe_activity", W["named_pipe_activity"],
               raw.get("_namedPipeActivity") is True,
               "Named pipe activity detected"),
        Signal("lateral_movement_pipe", W["lateral_movement_pipe"],
               raw.get("_lateralMovementPipe") is True,
               "Named pipe matches known lateral movement tool pattern"),
        Signal("known_attack_tool", W["known_attack_tool"],
               _has_known_attack_tool(raw),
               "Known attack tool in pipe context"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Pipe activity outside business hours"),
    ]


def extract_wmi_persistence(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    """Sysmon EIDs 19/20/21 — WMI Event Filter/Consumer/Binding.

    WMI permanent event subscriptions are the primary MITRE T1546.003
    persistence technique. Legitimate use is extremely rare — fire hard.
    """
    return [
        Signal("wmi_persistence", W["wmi_persistence"],
               raw.get("_wmiPersistence") is True,
               "WMI permanent event subscription — persistence mechanism"),
        Signal("persistence_mechanism", W["persistence_mechanism"],
               has_persistence_context(raw),
               "Persistence mechanism context"),
        Signal("privileged_user", W["privileged_user"], is_privileged_identity(raw),
               "WMI persistence under privileged account"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "WMI persistence created outside business hours"),
    ]


def extract_mass_file_create(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    """Phase 1.2 aggregated mass_file_create events.

    Fires when the export script collapsed 3+ file-create events from the same
    (process, directory, user) into a single synthesized alert. This is the
    ransomware mass-encryption signal.
    """
    file_count = int(raw.get("_fileCreateCount") or 0)
    return [
        Signal("mass_file_create", W["mass_file_create"],
               file_count > 3,
               f"Mass file create detected: {file_count} files written"),
        Signal("shadow_copy_deletion", W["shadow_copy_deletion"],
               raw.get("_shadowCopyDeletion") is True,
               "Shadow copy deletion combined with mass file create"),
        Signal("ransomware_chain", W["ransomware_chain"],
               has_ransomware_context(raw),
               "Ransomware chain indicators"),
        Signal("after_hours", W["after_hours"], is_after_hours(event_time),
               "Mass file create outside business hours"),
    ]


def extract_state_drift(
    raw: dict[str, Any], severity: str, event_time: datetime
) -> list[Signal]:
    """Phase 3 state drift events.

    Real signals come from `check_state_drift()` in entity_graph.py, which
    inspects the structured `_stateCategory` / `_driftAction` fields set by
    the state snapshot exporter and fires verified-tier signals like
    `unusual_service_path`, `userland_autorun`, `script_scheduled_task`.
    """
    return [
        Signal("state_drift", W["state_drift"],
               bool(raw.get("_stateCategory")),
               f"State drift: {raw.get('_stateCategory','unknown')} "
               f"{raw.get('_driftAction','changed')}"),
        Signal("unusual_service_path", W["unusual_service_path"],
               raw.get("_unusualServicePath") is True,
               "Service executable in non-standard path"),
        Signal("userland_autorun", W["userland_autorun"],
               raw.get("_userlandAutorun") is True,
               "Autorun entry points to userland AppData path"),
        Signal("script_scheduled_task", W["script_scheduled_task"],
               raw.get("_scriptScheduledTask") is True,
               "Scheduled task runs shell/script interpreter"),
    ]


ENDPOINT_EXTRACTORS = {
    "endpoint.malwareDetection": extract_malware_detection,
    "endpoint.suspiciousProcess": extract_suspicious_process,
    "endpoint.ransomwareDetection": extract_ransomware_detection,
    "endpoint.lateralMovement": extract_lateral_movement,
    "endpoint.credentialDumping": extract_credential_dumping,
    "endpoint.persistenceMechanism": extract_persistence_mechanism,
    "endpoint.defenseEvasion": extract_defense_evasion,
    # Phase 2 new types
    "endpoint.powershellExecution": extract_powershell_execution,
    "endpoint.lsassAccess": extract_lsass_access,
    "endpoint.pipeActivity": extract_pipe_activity,
    "endpoint.wmiPersistence": extract_wmi_persistence,
    "endpoint.massFileCreate": extract_mass_file_create,
    # Phase 3 state drift
    "endpoint.stateDrift": extract_state_drift,
}
