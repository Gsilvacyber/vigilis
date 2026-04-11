from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class Signal:
    name: str
    weight: int
    fired: bool
    label: str
    tier: str = "inferred"  # "verified", "inferred", or "observed"


@dataclass
class EnrichmentResult:
    confidence_score: int
    confidence_label: str
    confidence_explanation: list[dict[str, Any]]
    recommended_playbook: list[dict[str, Any]]
    recommended_actions: list[dict[str, Any]]
    enrichment_notes: list[str]
    asset_tier: str = "standard"
    user_risk_tier: str = "standard_user"


@dataclass
class EnrichmentDebug:
    result: EnrichmentResult
    all_signals: list[Signal]
    severity_base: int
    signal_boost: int


# ---------------------------------------------------------------------------
# Shared signal-detection helpers used across multiple mappers
# ---------------------------------------------------------------------------

import ipaddress as _ipaddress
import re as _re


# ── Private IP detection ──────────────────────────────────────────────
_PRIVATE_NETWORKS = [
    _ipaddress.ip_network("10.0.0.0/8"),
    _ipaddress.ip_network("172.16.0.0/12"),
    _ipaddress.ip_network("192.168.0.0/16"),
    _ipaddress.ip_network("127.0.0.0/8"),
    _ipaddress.ip_network("169.254.0.0/16"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        addr = _ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except (ValueError, TypeError):
        return False


_INVALID_GEO = frozenset({
    "unknown", "", "none", "n/a", "null", "private", "reserved", "internal",
    # Common misaligned CSV values that leak into geo fields
    "allowed", "blocked", "new", "detected", "terminated", "quarantined",
    "standard", "admin", "privileged", "root", "service_account",
    "passed", "denied", "bypassed", "not required", "enabled", "disabled",
    # MITRE tactics that leak into wrong columns
    "initial access", "credential access", "execution", "persistence",
    "privilege escalation", "defense evasion", "discovery", "lateral movement",
    "collection", "exfiltration", "command and control", "impact",
})


def _is_real_country(country: str | None) -> bool:
    """Return True only for real, known country names (not 'unknown', empty, etc)."""
    if not country:
        return False
    c = country.strip().lower()
    return c not in _INVALID_GEO


# ── Privilege detection from username patterns ────────────────────────
_ADMIN_PATTERNS = _re.compile(
    r"(^admin[@.\b_-]|[\._-]admin[@.\b_-]|^root[@.\b_-]|^administrator[@.\b_-]"
    r"|^cfo[@.\b_-]|^cto[@.\b_-]|^ceo[@.\b_-]|^ciso[@.\b_-]|^coo[@.\b_-]|^vp[@.\b_-]"
    r"|^dir[-_.]|^svp[@.]|global[_-]admin|domain[_-]admin"
    r"|^da-|^ea-|privileged"
    r"|sysadmin|secadmin|netadmin|infra.?admin|sec.?ops.?admin)",
    _re.IGNORECASE,
)
_SERVICE_PATTERNS = _re.compile(
    r"(^svc[-_.]|^service[-_.]|^sa[-_.]|^app[-_.]|^bot[-_.]|^sys[-_.])",
    _re.IGNORECASE,
)


def infer_privilege_tier(raw: dict[str, Any]) -> str | None:
    """Auto-detect privilege tier from identity data."""
    identity = raw.get("identity") or {}
    # If already set, use it
    existing = identity.get("privilegeTier")
    if existing and existing not in ("unknown", "standard", ""):
        return existing
    # Check UPN/display name for patterns
    upn = identity.get("upn") or ""
    display = identity.get("displayName") or ""
    combined = f"{upn} {display}"
    if _ADMIN_PATTERNS.search(combined):
        return "admin"
    if _SERVICE_PATTERNS.search(upn):
        return "service"
    # Check for C-suite titles in display name
    title_lower = display.lower()
    if any(t in title_lower for t in ("chief ", "officer", "director", "vice president", "vp ")):
        return "admin"
    return None


def has_anomalous_ip(raw: dict[str, Any]) -> bool:
    """Check if any NON-PRIVATE IP has anomalous role."""
    for ip in (raw.get("ips") or raw.get("ipAddresses") or []):
        if isinstance(ip, dict) and ip.get("role") == "anomalous":
            ip_addr = ip.get("ipAddress", "")
            # Skip private IPs — they're internal and not anomalous
            if _is_private_ip(ip_addr):
                continue
            return True
    return False


def has_external_ip(raw: dict[str, Any]) -> bool:
    """Check if any external (non-private) IP exists."""
    for ip in (raw.get("ips") or raw.get("ipAddresses") or []):
        if isinstance(ip, dict):
            ip_addr = ip.get("ipAddress", "")
            if ip_addr and not _is_private_ip(ip_addr) and ip_addr != "0.0.0.0":
                return True
    return False


def multi_country_ips(raw: dict[str, Any]) -> bool:
    """Check for IPs from 2+ REAL countries (ignores 'unknown' geo)."""
    countries: set[str] = set()
    for ip in (raw.get("ips") or raw.get("ipAddresses") or []):
        if isinstance(ip, dict):
            geo = ip.get("geo") or {}
            c = geo.get("country")
            if _is_real_country(c):
                countries.add(c)
    return len(countries) >= 2


def is_privileged_identity(raw: dict[str, Any]) -> bool:
    """Check if identity is privileged — uses auto-detection if tier not set."""
    identity = raw.get("identity") or {}
    tier = identity.get("privilegeTier")
    # If source tool explicitly says "standard", trust it — don't regex override
    if tier == "standard":
        return False
    if tier in ("privileged", "admin"):
        return True
    # Also check AD group membership field (more reliable than regex)
    if raw.get("_isAdminGroupMember") is True:
        return True
    # Only use regex as last resort
    inferred = infer_privilege_tier(raw)
    return inferred == "admin"


def is_service_account(raw: dict[str, Any]) -> bool:
    """Check if identity is a service account."""
    identity = raw.get("identity") or {}
    tier = identity.get("privilegeTier")
    if tier in ("service", "service_account"):
        return True
    upn = identity.get("upn") or ""
    return bool(_SERVICE_PATTERNS.search(upn))


def is_after_hours(event_time: datetime, org_timezone: str | None = None) -> bool:
    """Check if event occurred outside business hours (10pm-6am in org timezone)."""
    if org_timezone:
        try:
            from zoneinfo import ZoneInfo
            local_time = event_time.astimezone(ZoneInfo(org_timezone))
            return local_time.hour < 6 or local_time.hour >= 22
        except (KeyError, ImportError):
            pass  # Fall back to UTC
    return event_time.hour < 6 or event_time.hour >= 22


def _is_after_hours_context(raw: dict, event_time=None) -> bool:
    """Check if activity occurred outside business hours (10pm-6am).

    Combines keyword detection from alert text with event_time checking.
    """
    desc = str(raw).lower()
    if any(kw in desc for kw in ["after-hours", "after hours", "off-hours", "night ", "midnight", "2 am", "1 am", "3 am"]):
        return True
    if event_time and hasattr(event_time, 'hour'):
        h = event_time.hour
        if h >= 22 or h < 6:
            return True
    return False


def has_insider_threat_context(raw: dict[str, Any]) -> bool:
    """Check if alert context indicates insider threat indicators."""
    fired, _ = has_insider_threat_context_tiered(raw)
    return fired


def has_insider_threat_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check insider threat indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "observed" if structured fields confirm insider status (resignation flag,
        account disabled, termination date)
      - "inferred" if only keyword matching triggered
    """
    # OBSERVED path: structured fields from HR integration or source tool
    if raw.get("_insiderResignation") is True:
        return True, "observed"
    if raw.get("_accountDisabled") is True:
        return True, "observed"
    if raw.get("_terminationDate"):
        return True, "observed"
    # User risk level explicitly set to "insider"
    identity = raw.get("identity") or {}
    if isinstance(identity, dict) and identity.get("riskLevel") in ("insider", "departing"):
        return True, "observed"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    indicators = [
        "resignation", "departing", "termination", "notice period",
        "personal account", "personal onedrive", "personal github",
        "usb", "removable media", "bulk download", "bulk clone",
        "mass download", "mass export", "data staging",
        "no change ticket", "no itsm", "unauthorized",
        "outside corporate control", "post-termination",
        "persistent backdoor", "certificate credential",
        "hidden rule", "hidden inbox",
        "shadow it", "unsanctioned app", "personal device",
        "personal email", "gmail", "yahoo", "hotmail",
        "after hours", "weekend access", "off-hours",
        "elevated access", "privilege abuse", "role change",
        "large volume", "anomalous volume", "spike in activity",
    ]
    if any(ind in combined for ind in indicators):
        return True, "inferred"

    return False, "inferred"


def has_data_exfil_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates active data exfiltration."""
    fired, _ = has_data_exfil_context_tiered(raw)
    return fired


# Known personal/consumer cloud storage domains (exact destination match)
_PERSONAL_CLOUD_DOMAINS = frozenset({
    "dropbox.com", "mega.nz", "mega.io", "wetransfer.com",
    "sendanywhere.com", "protonmail.com", "tutanota.com",
    "drive.google.com", "onedrive.live.com", "icloud.com",
    "box.com", "pcloud.com", "mediafire.com", "zippyshare.com",
    "anonfiles.com", "filebin.net", "transfer.sh",
    "pastebin.com", "hastebin.com", "ghostbin.com",
})


def has_data_exfil_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check data exfiltration indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "observed" if structured fields (transfer size, DLP policy, destination
        domain, USB flag) from source tool confirm exfil
      - "inferred" if only keyword matching triggered
    """
    # OBSERVED path: structured fields from source tool
    observed_hits = 0

    # Check 1: transfer size threshold
    mb = raw.get("_transferSizeMB") or 0
    try:
        mb = int(float(mb))
    except (ValueError, TypeError):
        mb = 0
    if mb >= 100:
        observed_hits += 1

    # Check 2: item count threshold
    item_count = raw.get("_itemCount") or 0
    try:
        item_count = int(item_count)
    except (ValueError, TypeError):
        item_count = 0
    if item_count >= 50:
        observed_hits += 1

    # Check 3: destination domain is a known personal cloud service
    dest_domain = (
        raw.get("_destinationDomain") or raw.get("_dstDomain")
        or raw.get("destinationDomain") or ""
    )
    if isinstance(dest_domain, str):
        dest_domain = dest_domain.lower().strip()
        if any(d in dest_domain for d in _PERSONAL_CLOUD_DOMAINS):
            observed_hits += 2  # strong signal

    # Check 4: DLP policy violation flag from source tool
    if raw.get("_dlpPolicy") or raw.get("_classificationViolation") is True:
        observed_hits += 1

    # Check 5: USB / removable media flag
    device = raw.get("device") or {}
    if isinstance(device, dict) and device.get("removableMedia") is True:
        observed_hits += 1
    if raw.get("_usbDetected") is True or raw.get("_removableMedia") is True:
        observed_hits += 1

    # Check 6: bytes field at exfil threshold
    raw_bytes = raw.get("bytes") or raw.get("bytes_sent") or raw.get("bytesSent") or 0
    try:
        raw_bytes = int(float(raw_bytes)) if raw_bytes else 0
    except (ValueError, TypeError):
        raw_bytes = 0
    if raw_bytes >= 104857600:  # 100 MB
        observed_hits += 1

    if observed_hits >= 2:
        return True, "observed"

    # INFERRED path: keyword fallback (need 2+ indicators)
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    indicators = [
        "exfiltrat", "copied to", "synced to", "cloned to",
        "transferred", "downloaded", "exported", "upload",
        "personal onedrive", "personal github", "protonmail",
        "personal dropbox", "personal cloud", "personal storage",
        "dropbox", "mega.nz",
        "usb drive", "removable", "bulk", "mass file",
        "outside corporate", "ip theft",
        "gb", "mb", "500mb", "100mb",
        "sharepoint", "onedrive", "airdrop", "wetransfer",
        "google drive", "cloud storage", "zip", "archive", "compress",
        "sensitive", "confidential", "restricted",
    ]
    if sum(1 for ind in indicators if ind in combined) >= 2:
        return True, "inferred"

    return False, "inferred"


def has_persistence_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates persistence mechanisms."""
    fired, _ = has_persistence_context_tiered(raw)
    return fired


# MITRE ATT&CK Persistence tactic technique IDs
_PERSISTENCE_MITRE_TECHNIQUES = frozenset({
    "T1053",       # Scheduled Task/Job
    "T1053.005",   # Scheduled Task
    "T1053.003",   # Cron
    "T1543",       # Create or Modify System Process
    "T1543.003",   # Windows Service
    "T1543.001",   # Launch Agent (macOS)
    "T1547",       # Boot or Logon Autostart Execution
    "T1547.001",   # Registry Run Keys / Startup Folder
    "T1547.004",   # Winlogon Helper DLL
    "T1098",       # Account Manipulation
    "T1098.001",   # Additional Cloud Credentials
    "T1098.003",   # Additional Cloud Roles
    "T1136",       # Create Account
    "T1136.001",   # Local Account
    "T1136.002",   # Domain Account
    "T1546",       # Event Triggered Execution
    "T1546.003",   # Windows Management Instrumentation Event Subscription
    "T1176",       # Browser Extensions
    "T1554",       # Compromise Client Software Binary
})


def has_persistence_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check persistence indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "verified" if MITRE ATT&CK persistence technique IDs from source tool
      - "observed" if structured fields (service create, scheduled task, OAuth
        consent) from source tool confirm persistence
      - "inferred" if only keyword matching triggered
    """
    # VERIFIED path: MITRE ATT&CK technique IDs
    mitre = raw.get("mitre") or raw.get("_mitre") or {}
    if isinstance(mitre, dict):
        techniques = set(mitre.get("techniques") or mitre.get("technique_ids") or [])
    elif isinstance(mitre, list):
        techniques = set(mitre)
    else:
        techniques = set()
    if raw.get("_mitreTechnique"):
        techniques.add(str(raw.get("_mitreTechnique")))
    if raw.get("mitreTechniqueId"):
        techniques.add(str(raw.get("mitreTechniqueId")))

    if techniques & _PERSISTENCE_MITRE_TECHNIQUES:
        return True, "verified"

    # OBSERVED path: structured fields from source tool
    if raw.get("_serviceCreated") is True or raw.get("_newService") is True:
        return True, "observed"
    if raw.get("_scheduledTaskCreated") is True or raw.get("_newScheduledTask") is True:
        return True, "observed"
    if raw.get("_registryAutorun") is True or raw.get("_runKeyAdded") is True:
        return True, "observed"
    # OAuth consent with offline_access (persistence via token)
    app = raw.get("app") or {}
    if isinstance(app, dict):
        scopes = app.get("scopes") or []
        if isinstance(scopes, list) and any("offline_access" in str(s).lower() for s in scopes):
            return True, "observed"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    indicators = [
        "service principal", "certificate", "oauth token",
        "offline_access", "persist", "backdoor",
        "survives", "post-termination", "hidden rule",
        "mfa exclusion", "conditional access",
        "scheduled task", "cron", "startup", "registry run key", "autorun",
        "browser extension", "service install", "new service", "daemon",
    ]
    if any(ind in combined for ind in indicators):
        return True, "inferred"

    return False, "inferred"


def has_ad_attack_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates Active Directory attack techniques."""
    fired, _ = has_ad_attack_context_tiered(raw)
    return fired


# MITRE ATT&CK technique IDs for Active Directory attacks
_AD_MITRE_TECHNIQUES = frozenset({
    "T1003.006",  # OS Credential Dumping: DCSync
    "T1558.001",  # Steal or Forge Kerberos Tickets: Golden Ticket
    "T1558.002",  # Steal or Forge Kerberos Tickets: Silver Ticket
    "T1558.003",  # Steal or Forge Kerberos Tickets: Kerberoasting
    "T1558.004",  # Steal or Forge Kerberos Tickets: AS-REP Roasting
    "T1550.002",  # Use Alternate Authentication Material: Pass the Hash
    "T1550.003",  # Use Alternate Authentication Material: Pass the Ticket
    "T1484.001",  # Domain Policy Modification: Group Policy Modification
    "T1003",      # OS Credential Dumping (general)
    "T1003.001",  # LSASS Memory
    "T1069.002",  # Permission Groups Discovery: Domain Groups
    "T1087.002",  # Account Discovery: Domain Account
})

# Known AD attack tool process names (exact match on file.fileName)
_AD_ATTACK_TOOLS = frozenset({
    "mimikatz.exe", "mimikatz",
    "rubeus.exe", "rubeus",
    "sharphound.exe", "sharphound",
    "bloodhound.exe", "bloodhound",
    "impacket", "secretsdump.py", "wmiexec.py", "psexec.py",
    "kerbrute.exe", "kerbrute",
    "certify.exe",  # AD CS exploitation
})


def has_ad_attack_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check AD attack indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "verified" if MITRE technique IDs or exact tool process names match
      - "inferred" if only keyword matching triggered
    """
    # VERIFIED path: MITRE ATT&CK technique IDs from source tool
    mitre = raw.get("mitre") or raw.get("_mitre") or {}
    if isinstance(mitre, dict):
        techniques = set(mitre.get("techniques") or mitre.get("technique_ids") or [])
    elif isinstance(mitre, list):
        techniques = set(mitre)
    else:
        techniques = set()
    # Also check top-level flat fields
    if raw.get("_mitreTechnique"):
        techniques.add(str(raw.get("_mitreTechnique")))
    if raw.get("mitreTechniqueId"):
        techniques.add(str(raw.get("mitreTechniqueId")))

    if techniques & _AD_MITRE_TECHNIQUES:
        return True, "verified"

    # VERIFIED path: exact match of process name against known AD attack tool list
    f = raw.get("file") or {}
    if isinstance(f, dict):
        proc_name = (f.get("fileName") or "").strip().lower()
        if proc_name and proc_name in _AD_ATTACK_TOOLS:
            return True, "verified"
        # Also check common variations (strip .exe)
        if proc_name and proc_name.replace(".exe", "") in _AD_ATTACK_TOOLS:
            return True, "verified"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    indicators = [
        "dcsync", "dc sync", "golden ticket", "silver ticket",
        "kerberoast", "as-rep roast", "pass-the-hash", "pass the hash",
        "forged", "krbtgt", "mimikatz", "impacket", "rubeus",
        "bloodhound", "sharphound", "domain compromise",
        "honey token", "honeytoken", "canary",
        "gpo modified", "disable defender", "disable antivirus",
        "scheduled task created on domain controller",
        "ms-drsr", "domain replication",
    ]
    if any(ind in combined for ind in indicators):
        return True, "inferred"

    return False, "inferred"


def has_dormant_account_context(raw: dict[str, Any]) -> bool:
    """Check if alert involves a dormant/inactive account."""
    ctx = (raw.get("_additionalContext") or "").lower()
    pwd_age = raw.get("_passwordAgeDays") or 0
    return pwd_age > 180 or any(kw in ctx for kw in ["dormant", "inactive", "days dormant", "days of inactivity"])


def has_domain_admin_context(raw: dict[str, Any]) -> bool:
    """Check if context involves domain admin compromise."""
    fired, _ = has_domain_admin_context_tiered(raw)
    return fired


def has_domain_admin_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check if context involves domain admin compromise with tier awareness.

    Returns (fired, tier) where tier is:
      - "observed" if structured fields (boolean/enum) confirm admin status
      - "inferred" if only keyword matching triggered
    """
    # OBSERVED path: structured boolean/enum fields from source tool
    is_admin = raw.get("_isAdminGroupMember") is True
    identity = raw.get("identity") or {}
    priv = identity.get("privilegeTier")
    if is_admin:
        return True, "observed"
    if priv == "admin":
        return True, "observed"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    if any(kw in ctx for kw in [
        "domain admin", "enterprise admin", "schema admin",
        "golden ticket", "krbtgt", "full domain", "domain compromise",
    ]):
        return True, "inferred"

    return False, "inferred"


def is_ir_response(raw: dict[str, Any]) -> bool:
    """Check if this alert is an IR/defensive response action, not a threat.

    WHY THIS EXISTS: Security team actions (disabling keys, deploying SCPs,
    killing sessions) generate alerts that describe the attack they're responding
    to. Without this filter, text like "key disabled — CloudFront still compromised"
    triggers attack signals from the description, scoring the IR action at 100.

    DETECTION METHOD: Checks alert name for IR keywords, category field for
    "Detection Response", and context for high-confidence IR phrases.

    KNOWN LIMITATION: Alerts with both IR AND attack context (e.g., "admin
    terminated session but attacker still active") are harder to classify.
    Currently we prioritize alert name over context text.
    """
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"

    # Strong IR indicators — if the alert NAME itself indicates response, it's IR
    strong_ir = any(ind in alert_name for ind in [
        "ir response", "key disabled", "session terminated",
        "emergency lockdown", "scp created", "containment",
        "detection response", "remediation",
    ])
    if strong_ir:
        return True

    # Category-based detection
    cat = raw.get("_category", "")
    if cat in ("detection response", "system event", "system - baseline"):
        return True

    # Context-based with high-confidence IR phrases
    ir_phrases = [
        "correct ir step", "correct response", "security team responding",
        "security team disabled", "admin revoke", "admin terminated",
    ]
    return any(phrase in combined for phrase in ir_phrases)


def has_ransomware_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates ransomware attack chain."""
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    return any(kw in combined for kw in [
        "ransomware", "ransom", "encrypted files", "encryption",
        "mass file", "mass encryption", ".locked", "decrypt",
        "ransom note", "how_to_decrypt", "extortion",
        "shadow copies", "vssadmin delete", "backup deletion",
        "cobalt strike", "beacon", "beaconing", "c2 channel",
        "macro execution", "excel spawned", "office spawned",
        "gpo modified", "group policy", "mass deployment",
        "lsass", "credential dumping", "pass-the-ticket",
        "psexec lateral", "smb scanning",
        "monero", "payment deadline", "data exfil claimed",
    ])


def has_c2_beaconing_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates command and control beaconing."""
    fired, _ = has_c2_beaconing_context_tiered(raw)
    return fired


# Known C2 framework process names (exact match)
_C2_FRAMEWORK_TOOLS = frozenset({
    "beacon.exe", "beacon",
    "cobaltstrike", "cobaltstrike.exe",
    "meterpreter", "meterpreter.exe",
    "metasploit", "msfconsole",
    "empire", "empire.exe",
    "covenant", "grunt.exe",
    "sliver", "sliver.exe",
    "havoc", "havoc.exe",
    "mythic",
    "brute_ratel", "brc4",
    "pupy", "pupy.exe",
    "poshc2",
})


def has_c2_beaconing_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check C2 beaconing indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "verified" if known C2 framework process name OR structured beacon
        interval metrics from source tool (NDR like Darktrace/Zeek) confirm C2
      - "inferred" if only keyword matching triggered
    """
    # VERIFIED path: known C2 framework process names
    f = raw.get("file") or {}
    if isinstance(f, dict):
        proc_name = (f.get("fileName") or "").strip().lower()
        if proc_name in _C2_FRAMEWORK_TOOLS:
            return True, "verified"
    proc_field = str(raw.get("process") or raw.get("_processName") or "").lower()
    if proc_field:
        base = proc_field.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if base in _C2_FRAMEWORK_TOOLS:
            return True, "verified"

    # OBSERVED path: structured beaconing metrics from NDR/flow tools
    # Beaconing = repeated connections to same destination at regular intervals
    if raw.get("_beaconingDetected") is True or raw.get("_periodicConnection") is True:
        return True, "observed"

    # Interval regularity score (some NDR tools provide this 0-1)
    interval_score = raw.get("_beaconIntervalScore") or raw.get("_periodicityScore")
    try:
        interval_score = float(interval_score) if interval_score else 0
    except (ValueError, TypeError):
        interval_score = 0
    if interval_score >= 0.8:
        return True, "observed"

    # Connection count to same destination in short window
    conn_count = raw.get("_connectionsToSameDest") or raw.get("_repeatedConnections") or 0
    try:
        conn_count = int(conn_count)
    except (ValueError, TypeError):
        conn_count = 0
    if conn_count >= 20:
        return True, "observed"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    if any(kw in combined for kw in [
        "beacon", "beaconing", "c2 channel", "c2 server",
        "command and control", "cobalt strike",
        "team server", "interval", "jitter",
        "repeated connection", "rare external",
        "callback", "heartbeat", "check-in", "checkin", "phone home",
        "staging", "payload download", "dropper",
        "periodic", "regular interval", "malleable",
    ]):
        return True, "inferred"

    return False, "inferred"


def has_iot_ot_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates ICS/OT/IoT attack targeting industrial systems."""
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    return any(kw in combined for kw in [
        "modbus", "opc-ua", "opc ua", "ethernet/ip", "profinet", "bacnet",
        "dnp3", "s7comm", "cip service", "cip program",
        "plc", "dcs", "rtu", "hmi", "scada", "historian",
        "ics", "industrial control", "ot network", "operational technology",
        "ladder logic", "program download", "firmware",
        "safety system", "emergency stop", "emergency shutdown", "interlock",
        "sil2", "sil3", "sil 2", "sil 3", "safety integrity",
        "production line", "manufacturing", "plant floor",
        "badge reader", "access control panel", "door control",
        "ip camera", "camera compromised", "physical security",
        "vlan misconfiguration", "ot segment", "it-ot bridge",
    ])


def has_physical_safety_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates risk to physical safety systems or human safety."""
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    return any(kw in combined for kw in [
        "safety system", "emergency stop", "emergency shutdown",
        "sil2", "sil3", "sil 2", "sil 3", "safety integrity level",
        "safety interlock", "pressure relief", "physical damage",
        "equipment protection", "safety controller",
        "ladder logic modif", "program hash", "baseline hash",
        "hash match", "hashMatch=false",
        "production disruption", "uncontrolled restart",
    ])


def has_container_escape_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates Kubernetes container escape or cluster compromise."""
    fired, _ = has_container_escape_context_tiered(raw)
    return fired


# Known container escape / K8s attack tool process names
_K8S_ATTACK_TOOLS = frozenset({
    "kubectl", "kubectl.exe",
    "crictl", "ctr",  # container runtime CLIs
    "nsenter",  # namespace escape
    "peirates",  # k8s pentesting tool
    "kube-hunter", "kubesploit",
    "etcdctl",  # etcd CLI — direct cluster state manipulation
    "kdigger",  # k8s context discovery
})


def has_container_escape_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check container escape indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "observed" if structured K8s security context fields from source tool
        (Falco, Sysdig, Aqua, Trivy) confirm escape conditions
      - "inferred" if only keyword matching triggered
    """
    # OBSERVED path: structured K8s security context fields
    # These come from container security tools that parse pod specs
    observed_hits = 0
    reasons = []

    if raw.get("_containerPrivileged") is True or raw.get("_privilegedContainer") is True:
        observed_hits += 2  # strong signal
        reasons.append("privileged container")

    if raw.get("_hostPid") is True or raw.get("_hostPID") is True:
        observed_hits += 2
        reasons.append("hostPID=true")

    if raw.get("_hostNetwork") is True:
        observed_hits += 1
        reasons.append("hostNetwork=true")

    if raw.get("_hostIPC") is True:
        observed_hits += 1
        reasons.append("hostIPC=true")

    # Dangerous Linux capabilities
    caps = raw.get("_capabilities") or raw.get("_linuxCapabilities") or []
    if isinstance(caps, list):
        dangerous_caps = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN"}
        matched = dangerous_caps & {str(c).upper().replace("CAP_", "") for c in caps}
        if matched:
            observed_hits += 2
            reasons.append(f"dangerous caps: {','.join(matched)}")

    # Sensitive volume mounts (docker socket, host root, etcd data)
    mounts = raw.get("_volumeMounts") or raw.get("_mounts") or []
    if isinstance(mounts, list):
        sensitive_paths = {"/var/run/docker.sock", "/var/lib/etcd", "/etc/kubernetes", "/"}
        for m in mounts:
            if isinstance(m, str) and m in sensitive_paths:
                observed_hits += 2
                reasons.append(f"sensitive mount: {m}")
                break
            if isinstance(m, dict):
                path = m.get("hostPath") or m.get("path") or ""
                if path in sensitive_paths:
                    observed_hits += 2
                    reasons.append(f"sensitive mount: {path}")
                    break

    # Known K8s attack tool in process field
    f = raw.get("file") or {}
    if isinstance(f, dict):
        proc_name = (f.get("fileName") or "").strip().lower()
        if proc_name in _K8S_ATTACK_TOOLS:
            observed_hits += 1
            reasons.append(f"attack tool: {proc_name}")

    if observed_hits >= 2:
        return True, "observed"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    if any(kw in combined for kw in [
        "container escape", "host pid", "host_pid", "privileged container",
        "privileged=true", "sys_admin", "cluster admin", "clusteradmin",
        "service account token", "kubectl", "daemonset",
        "etcd", "ca.key", "certificate authority private",
        "kubernetes secret", "secrets dump", "all namespaces",
        "cluster compromise", "cluster takeover",
        "host-level access", "container boundary",
        "nodes compromised", "ca key",
    ]):
        return True, "inferred"

    return False, "inferred"


def has_lateral_movement_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates lateral movement / propagation to other hosts."""
    fired, _ = has_lateral_movement_context_tiered(raw)
    return fired


def has_lateral_movement_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check lateral movement context with tier awareness.

    Returns (fired, tier) where tier is:
      - "verified" if entity graph confirms user on 3+ hosts (DB-backed)
      - "inferred" if only keyword matching triggered
    """
    # VERIFIED path: entity graph multi-host detection
    # If the user has been seen on 3+ distinct hosts recently, that's
    # confirmed lateral movement from our OWN data
    try:
        identity = raw.get("identity") or {}
        upn = ""
        if isinstance(identity, dict):
            upn = (identity.get("upn") or "").strip().lower()
        if upn and upn not in ("unknown", "unknown@upload", ""):
            from backend.app.core.db import get_session
            from backend.app.db.models import EntityRelationship
            from sqlmodel import select
            with get_session() as session:
                user_hosts = session.exec(
                    select(EntityRelationship).where(
                        EntityRelationship.entity_a_type == "user",
                        EntityRelationship.entity_a_value == upn,
                        EntityRelationship.entity_b_type == "host",
                    )
                ).all()
                distinct_hosts = {r.entity_b_value for r in user_hosts}
                if len(distinct_hosts) >= 3:
                    return True, "verified"
    except Exception:
        pass  # Fall through to keyword check

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    if any(kw in combined for kw in [
        "lateral", "propagat", "second workstation", "second host",
        "second internal", "additional host", "another host",
        "spread", "worm", "same pattern",
        "identical pattern", "same destination", "same domain",
        "usb propagat", "shared drive propagat",
        "multiple host", "both workstation", "additional machine",
        "rdp from compromised", "rdp lateral", "rdp pivot",
        "ssh from compromised", "ssh lateral", "ssh pivot",
        "remote desktop lateral", "winrm lateral", "winrm remote",
        "dcom lateral", "dcom remote exec",
        "pass-the-ticket", "pass the ticket",
        "admin share", "c$", "admin$", "ipc$",
    ]):
        return True, "inferred"

    return False, "inferred"


def has_dns_tunnel_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates DNS tunneling or covert channel exfiltration."""
    fired, _ = has_dns_tunnel_context_tiered(raw)
    return fired


# Known DNS tunneling tool process names (exact match)
_DNS_TUNNEL_TOOLS = frozenset({
    "dnscat2", "dnscat2.exe", "dnscat",
    "dns2tcp", "dns2tcp.exe",
    "iodine", "iodine.exe", "iodined",
    "dnsteal", "dnsteal.py",
    "reqrypt",
    "ozymandns",
})


def has_dns_tunnel_context_tiered(raw: dict[str, Any]) -> tuple[bool, str]:
    """Check DNS tunneling indicators with tier awareness.

    Returns (fired, tier) where tier is:
      - "verified" if known tunneling tool process name OR DNS metrics from
        source tool (high query rate, large TXT records) confirm tunneling
      - "inferred" if only keyword matching triggered
    """
    # VERIFIED path: known DNS tunneling tool process names
    f = raw.get("file") or {}
    if isinstance(f, dict):
        proc_name = (f.get("fileName") or "").strip().lower()
        if proc_name in _DNS_TUNNEL_TOOLS:
            return True, "verified"
        # Also check the process field (Sysmon style)
    proc_field = str(raw.get("process") or raw.get("_processName") or "").lower()
    if proc_field:
        base = proc_field.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if base in _DNS_TUNNEL_TOOLS:
            return True, "verified"

    # OBSERVED path: DNS query metrics from source tool (NDR, DNS logs)
    # High query rate is a strong tunneling indicator
    qpm = raw.get("_dnsQueriesPerMinute") or raw.get("_dnsQueryRate") or 0
    try:
        qpm = int(float(qpm))
    except (ValueError, TypeError):
        qpm = 0
    if qpm >= 100:
        return True, "verified"  # >100 queries/min to same domain = tunneling

    # Large DNS payload (TXT record > 200 bytes strongly suggests tunneling)
    payload_size = raw.get("_dnsPayloadSize") or raw.get("_dnsTxtSize") or 0
    try:
        payload_size = int(payload_size)
    except (ValueError, TypeError):
        payload_size = 0
    if payload_size >= 200:
        return True, "verified"

    # Excessive subdomain length (encoded data in subdomain)
    qname = raw.get("_dnsQueryName") or raw.get("domain") or ""
    if isinstance(qname, str) and qname:
        # Count the first label length
        first_label = qname.split(".")[0] if "." in qname else qname
        if len(first_label) >= 40:
            return True, "verified"

    # INFERRED path: keyword fallback
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    if any(kw in combined for kw in [
        "dns tunnel", "dns tunneling", "dnscat", "dns2tcp", "iodine",
        "covert channel", "covert dns", "dns exfil",
        "dns txt", "base64", "encoded subdomain",
        "dns payload", "high frequency dns", "queries per minute",
        "sinkhole", "dns volume", "dns anomaly",
        "dns data exfil",
    ]):
        return True, "inferred"

    return False, "inferred"


def has_code_security_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates code security findings (secret scanning, SAST).

    WHY: Code scanning tools (GitHub Advanced Security, Semgrep, Snyk) produce
    findings that lack runtime context — no IP, no device, no user session.
    These findings score lower than runtime alerts (typically 50-70 vs 80-100)
    because a "hardcoded key found in code" is a posture finding, not proof
    of active exploitation. The code_secret_exposed signal adds 22 points
    to acknowledge the finding without over-scoring.

    KNOWN GAP (5% of rating): Multi-file scanning results (e.g., "14 secrets
    found across 3 repos") have user="multiple" which gets filtered to
    unknown@upload, losing identity enrichment. The files_affected count is
    extracted to _itemCount but high_item_count signal requires user context
    to fire in the cloud mapper. Score ceiling for these: ~62/100.
    """
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    return any(kw in combined for kw in [
        "secret detected", "secret found", "hardcoded credential",
        "hardcoded api key", "hardcoded password", "credential pattern",
        "public repo", "public commit", "secret scanning",
        "semgrep", "committed to", "aws access key",
        "stripe key", "api key exposed", "credential exposure",
        "confirmed valid", "confirmed active",
    ])


def has_supply_chain_context(raw: dict[str, Any]) -> bool:
    """Check if context indicates supply chain attack."""
    ctx = (raw.get("_additionalContext") or "").lower()
    alert_name = (raw.get("_sourceAlertName") or "").lower()
    desc = (raw.get("description") or raw.get("_description") or "").lower()
    combined = f"{ctx} {alert_name} {desc}"
    return any(kw in combined for kw in [
        "supply chain", "malicious redirect", "malicious apk",
        "malicious update", "backdoor", "reverse shell",
        "modified distribution", "cloudfront", "cdn modified",
        "container image modified", "ecr modified",
        "log injection", "ci pipeline", "workflow",
        "poisoned", "trojanized", "compromised package",
        "mobile users", "serve malware",
    ])


def get_action_status_weight(raw: dict[str, Any]) -> tuple[int, str]:
    """Return (weight, description) based on the alert action status.

    WHY: A blocked attack is noise management. An allowed attack is an active
    incident. This asymmetry is one of the highest-impact single factors in
    SOC triage. Most tools treat this as binary; Vigilis uses a 6-level
    spectrum that matches how analysts actually think about alert urgency.

    Returns negative weight for blocked/contained, positive for allowed/active.
    """
    status = str(raw.get("_alertStatus") or "").lower().strip()

    _ACTION_WEIGHTS: dict[str, tuple[int, str]] = {
        # Active — went through, incident is live
        "allowed": (20, "Action was allowed — active incident, not blocked"),
        "new": (18, "New detection — not yet acted on, potentially active"),
        "detected": (15, "Detected but not blocked — may be actively executing"),
        "alert only": (12, "Monitoring mode only — tool saw it but took no action"),
        "alert": (12, "Alert generated — no automated response"),
        "logged": (10, "Logged only — no prevention applied"),
        # Partially contained
        "quarantined": (5, "Quarantined mid-execution — partial containment"),
        # Contained — impact prevented or stopped
        "blocked": (-8, "Blocked before impact — noise, not active incident"),
        "terminated": (-5, "Process/session terminated — contained"),
        "session killed": (-5, "Session killed by admin — contained"),
        "denied": (-6, "Access denied — attack prevented"),
        "prevented": (-8, "Attack prevented by security control"),
        "critical - immediate escalation": (10, "Source flagged for immediate escalation"),
    }

    for key, (weight, desc) in _ACTION_WEIGHTS.items():
        if key in status:
            return weight, desc

    # Unknown status — no weight adjustment
    return 0, ""


def get_ip_countries(raw: dict[str, Any]) -> list[str]:
    """Get list of real countries from IPs."""
    countries = []
    for ip in (raw.get("ips") or raw.get("ipAddresses") or []):
        if isinstance(ip, dict):
            geo = ip.get("geo") or {}
            c = geo.get("country")
            if _is_real_country(c):
                countries.append(c)
    return countries
