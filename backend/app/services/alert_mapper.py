"""Auto-maps common SIEM export fields into Vigilis's rawAlert schema.

Handles:
- Splunk-style exports (src_ip, dest_ip, user, action, severity, etc.)
- Microsoft Sentinel / Defender (UserPrincipalName, IPAddress, DeviceName, etc.)
- Generic CSV with column-name heuristics
- Already-conforming Vigilis rawAlert JSON (pass-through)
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_ALERT_TYPE_KEYWORDS: dict[str, list[str]] = {
    "identity.suspiciousSignIn": [
        "sign-in", "signin", "login", "logon", "authentication",
        "brute force", "suspicious login", "anomalous login",
        "auth after spray", "failed auth", "successful auth",
        "suspicious sign-in", "login_failure", "login_success",
        "account_lockout", "auth_warning", "new device",
        "authentication from", "session terminated",
        "anonymous proxy", "credential submitted", "credential submission",
        "password reset", "mfa phone", "mfa changed",
        "impossible travel", "concurrent session",
        "session killed", "session revoked",
        "dormant account", "inactive account", "days dormant",
        "honey token", "honeytoken", "canary",
        "ntlm authentication", "ntlm bypass",
    ],
    "identity.passwordSpray": [
        "password spray", "credential stuffing", "multiple failed",
        "spray", "multiple target accounts", "brute force against",
        "as-rep roasting", "asrep roasting", "kerberoasting",
        "kerberos", "tgs-req", "as-req", "rc4-hmac",
        "credential dumping", "dcsync", "dc sync",
        "pass-the-hash", "pass the hash", "pth",
        "golden ticket", "silver ticket", "forged ticket",
        "impacket", "getnpusers", "rubeus", "mimikatz",
        "ntlm hash", "offline crack",
    ],
    "identity.mfaFatigue": [
        "mfa fatigue", "multi-factor fatigue", "2fa fatigue",
        "push fatigue", "push denied", "mfa push",
        "mfa_fatigue", "mfa_push_denied", "mfa denial",
    ],
    "identity.oauthConsentRisk": [
        "oauth", "consent", "app permission", "application consent",
        "consent grant", "unverified publisher", "oauth token",
        "bulk download", "sharepoint download", "onedrive download",
    ],
    "identity.privilegeElevation": [
        "privilege escalation", "privilege_escalation",
        "role assignment", "admin grant", "role grant",
        "global administrator", "new_role", "admin role",
        "role change", "permission change",
        "krbtgt", "krbtgt password reset",
        "domain replication", "ms-drsr",
        "cve exploit", "firmware exploit", "rce on device",
        "root on printer", "root on camera", "root rce",
    ],
    "endpoint.malwareDetection": [
        "malware", "virus", "trojan", "ransomware", "threat detected",
        "reputation low", "unsigned executable", "binary reputation",
        "malware_download", "threat_list_hit", "file_write",
        "yara", "waveshaper", "cryptominer", "mining pool",
        "monero", "xmrig", "coinhive",
        "ransomware staging", "encryption routine",
        "impact", "ransom note", "encrypted files",
    ],
    "endpoint.suspiciousProcess": [
        "suspicious process", "powershell", "lolbin", "process execution",
        "encoded command", "suspicious command", "encoded",
        "child process", "beacon", "process_creation",
        "registry_modification", "file_modification",
        "postinstall hook", "reverse shell", "rat ",
        "scheduled task", "persistence", "crontab",
        "dll injection", "process hollowing",
        "wmi", "wmiprvse", "psexec", "wmic",
        "group policy", "gpo modified", "disable defender",
        "disable antivirus", "antispyware",
        "ldap reconnaissance", "bloodhound", "sharphound",
        "directory enumeration", "domain admin",
        "sensitive group", "enterprise admin",
        "dnscat", "dnscat2", "masquerading", "svchost32",
        "dropper", "fake update", "typosquat",
        # Kubernetes / container
        "shell spawn", "shell in container", "container escape",
        "kubectl", "daemonset", "privileged pod",
        "host pid", "host network", "sys_admin",
        "etcd", "etcdctl", "ca.key", "certificate authority",
        "crypto miner", "xmrig",
        # IoT/OT / ICS
        "plc programming", "ladder logic", "firmware modif",
        "modbus write", "cip program download",
        "engineering workstation", "hmi workstation",
        # Phase 8 — service account and C2 classification keywords
        "service account", "svc_", "credential compromise", "token theft",
        "c2", "command and control", "callback", "heartbeat",
    ],
    "email.forwardingRule": [
        "forwarding", "mail rule", "inbox rule", "email rule",
        "mail flow", "external forwarding",
        "phishing", "phishing_detected", "spearphish", "spear-phish",
        "malicious attachment", "malicious url", "malicious email",
        "impersonation", "impersonating", "email delivered",
        "phish", "social engineering",
        "wire transfer", "wire request", "wire confirmation",
        "bec", "business email compromise", "ceo fraud", "cfo fraud",
        "invoice fraud", "payment fraud", "banking details",
        "lookalike domain", "lookalike", "typosquat",
        "urgent wire", "urgent payment", "urgent transfer",
    ],
    "cloud.secretStoreAccessAnomaly": [
        "key vault", "secret", "credential access", "secret store",
        "certificate", "keyvault", "vault access", "secret retrieval",
        "anomalous_api_call", "api anomaly",
        "data_exfiltration", "data exfiltration", "exfiltration",
        "large_upload", "large transfer", "bulk transfer",
        "dropbox", "mega.nz", "pastebin",
        "outbound data", "unauthorized transfer",
        "hardcoded api key", "leaked credential", "git commit",
        "dlp violation", "data loss",
        "banking portal", "bank of america", "wire transfer confirmation",
        "payment record", "accounts payable", "sharepoint finance",
        "financial impact", "wire recall",
        # Code security / secret scanning
        "secret detected", "secret scanning", "hardcoded credential",
        "hardcoded password", "hardcoded_api_key", "hardcoded_password",
        "aws_access_key", "credential pattern", "semgrep",
        "secret found", "public repository", "credential exposure",
        "key exposed", "secret confirmed", "secret valid",
        "stripe key", "api key committed", "key committed",
        # Kubernetes secrets
        "kubernetes secret", "k8s secret", "service account token",
        "secrets enumeration", "secrets dump",
        "cluster admin", "clusteradmin",
        # IoT/OT data access
        "scada historian", "opc-ua read", "ics protocol",
        "production metrics", "operational data",
        "historian server", "valve position", "temperature setpoint",
        # Phase 8 — key/secret access classification keywords
        "key rotation", "key access", "secret access", "vault secret",
    ],
    "network.impossibleGeoAccess": [
        "impossible travel", "impossible_travel", "impossible geo",
        "location anomaly", "atypical travel", "geographic login",
        "covert channel", "suspicious_domain", "blocked_connection",
        "allowed_connection", "network_connection",
        "outbound connection", "uncategorized domain",
        "c2", "command and control", "malicious ip",
        "syn scan", "port scan", "nmap",
        # DNS tunneling / covert channels
        "dns tunnel", "dns tunneling", "dns exfil", "dns data exfil",
        "dnscat", "dnscat2", "iodine", "dns2tcp",
        "dns txt", "txt query", "dns query", "high frequency dns",
        "covert dns", "dns payload", "sinkhole",
        "base64 subdomain", "encoded subdomain",
        "dns volume", "dns anomaly",
        # IoT/OT network
        "modbus tcp", "ethernet/ip", "opc-ua", "bacnet", "profinet",
        "industrial protocol", "ics scanning", "ot scanning",
        "vlan misconfiguration", "badge reader", "camera compromised",
        "access control panel", "door control",
        "smb scanning", "internal scanning",
    ],
    "identity.impossibleTravel": [
        "impossible travel", "impossible_travel", "simultaneous login",
        "concurrent session", "concurrent_sessions", "multiple locations",
        "geographic anomaly", "geo anomaly", "location conflict",
        "two countries", "travel alert", "velocity check",
        "distance anomaly", "simultaneous access",
    ],
    "identity.dormantAccountLogin": [
        "dormant account", "dormant_account", "inactive account",
        "inactive_account", "stale account", "unused account",
        "days dormant", "last login 90", "last login 180",
        "reactivated account", "account reactivation",
        "abandoned account", "long inactive",
    ],
    "identity.serviceAccountAbuse": [
        "service account", "svc_", "svc-", "sa_", "sa-",
        "service principal", "managed identity", "service identity",
        "interactive logon service", "service account interactive",
        "non-standard host", "unusual service login",
        "service credential", "application identity",
        "service account compromise", "token theft service",
    ],
    "endpoint.ransomwareDetection": [
        "ransomware", "ransom note", "encrypted files",
        "encryption routine", "file extension change",
        "mass encryption", "shadow copy", "vssadmin delete",
        "bcdedit", "wbadmin delete", "ransom demand",
        "ransomware staging", "crypto locker", "file encryption",
        "backup deletion", "recovery disabled",
        "bitlocker abuse", "ransomware payload",
    ],
    "endpoint.lateralMovement": [
        "lateral movement", "lateral_movement", "psexec",
        "wmic", "wmiprvse", "wmi execution",
        "remote execution", "pass-the-hash", "pass the hash",
        "pass-the-ticket", "pass the ticket", "pth ",
        "admin share", "c$", "admin$", "ipc$",
        "remote service", "rdp lateral", "rdp pivot",
        "ssh lateral", "winrm lateral", "dcom lateral",
        "remote process", "scheduled task remote",
    ],
    "endpoint.credentialDumping": [
        "credential dumping", "credential dump", "cred dump",
        "mimikatz", "lsass", "lsass.exe", "procdump lsass",
        "dcsync", "dc sync", "ntds.dit",
        "sam database", "security account manager",
        "hashdump", "hash dump", "secretsdump",
        "rubeus", "impacket", "getnpusers",
        "kerberoasting", "kerberoast", "as-rep roasting",
    ],
    "endpoint.persistenceMechanism": [
        "persistence", "persistence mechanism", "scheduled task",
        "schtasks", "crontab", "cron job", "at job",
        "registry run key", "registry autorun",
        "startup folder", "startup item",
        "service creation", "new service",
        "wmi subscription", "wmi event",
        "logon script", "boot autostart",
        "dll side loading", "dll hijack",
    ],
    "endpoint.defenseEvasion": [
        "defense evasion", "disable defender", "disable antivirus",
        "tamper protection", "antispyware",
        "clear event log", "clear logs", "log deletion",
        "wevtutil cl", "wevtutil clear",
        "timestomp", "timestamp modification",
        "process injection", "process hollowing",
        "dll injection", "reflective loading",
        "amsi bypass", "etw patching",
        "disable firewall", "disable logging",
    ],
    "email.businessEmailCompromise": [
        "bec", "business email compromise", "ceo fraud",
        "cfo fraud", "executive impersonation",
        "wire transfer", "wire request", "wire confirmation",
        "urgent wire", "urgent payment", "urgent transfer",
        "invoice fraud", "payment fraud", "banking details",
        "lookalike domain", "typosquat",
        "impersonation", "reply-to mismatch",
        "vendor fraud", "supplier fraud",
    ],
    "email.maliciousAttachment": [
        "malicious attachment", "malicious file",
        "macro enabled", "macro detected", "vba macro",
        "suspicious attachment", "dangerous attachment",
        "executable attachment", "script attachment",
        "zip attachment", "archive attachment",
        "office macro", "powershell attachment",
        "embedded object", "ole object",
        "pdf exploit", "rtf exploit",
    ],
    "network.commandAndControl": [
        "command and control", "c2 server", "c2 channel",
        "c2 callback", "c2 beacon", "beaconing",
        "beacon interval", "heartbeat", "callback",
        "cobalt strike", "metasploit", "empire",
        "sliver", "havoc", "brute ratel",
        "reverse shell", "reverse tcp",
        "staged payload", "stager",
    ],
    "network.portScan": [
        "port scan", "port scanning", "portscan",
        "syn scan", "syn_scan", "tcp scan",
        "nmap", "masscan", "zmap",
        "service discovery", "network reconnaissance",
        "host discovery", "ping sweep",
        "vulnerability scan", "vuln scan",
        "network enumeration",
    ],
    "network.dnsAnomaly": [
        "dns tunnel", "dns tunneling", "dns exfil",
        "dns data exfil", "dns anomaly",
        "dnscat", "dnscat2", "iodine", "dns2tcp",
        "dga", "domain generation algorithm",
        "dns query volume", "high frequency dns",
        "nxdomain", "excessive nxdomain",
        "txt query anomaly", "dns payload",
        "covert dns", "base64 subdomain",
    ],
    "cloud.resourceHijacking": [
        "crypto mining", "cryptomining", "cryptominer",
        "resource hijacking", "compute abuse",
        "unauthorized instance", "unauthorized vm",
        "xmrig", "coinhive", "mining pool",
        "monero", "bitcoin mining",
        "gpu abuse", "spot instance abuse",
        "lambda abuse", "serverless abuse",
    ],
    "cloud.dataExposure": [
        "public bucket", "public blob", "public storage",
        "s3 public", "s3 acl", "bucket policy",
        "storage misconfiguration", "data exposure",
        "publicly accessible", "open storage",
        "anonymous access", "unauthenticated access",
        "blob public", "gcs public",
        "data leak", "unprotected data",
    ],
    "dlp.sensitiveDataExposure": [
        "dlp violation", "dlp alert", "dlp policy",
        "data loss prevention", "data classification",
        "sensitive data", "confidential data",
        "pii violation", "pii detected", "pii exposure",
        "phi violation", "hipaa violation",
        "pci violation", "credit card data",
        "ssn detected", "social security",
        "classified document", "restricted data",
    ],
    # ── Phase 2 new alert types ──────────────────────────────────────────
    "identity.logonSuccess": [
        "logon success", "successful logon", "4624",
        "interactive logon", "remote interactive logon", "rdp logon",
        "network logon",
    ],
    "identity.accountCreation": [
        "account created", "new account", "4720",
        "user account created", "local user created", "new-localuser",
        "net user /add",
    ],
    "endpoint.powershellExecution": [
        "powershell script block", "powershell 4104", "script block logging",
        "script block", "obfuscated powershell", "encoded powershell",
        "powershell download cradle", "iex download", "invoke-expression download",
    ],
    "endpoint.lsassAccess": [
        "lsass access", "lsass dump", "lsass memory", "credential dumping",
        "sekurlsa", "mimikatz sekurlsa", "procdump lsass",
        "comsvcs minidump", "sysmon 10",
    ],
    "endpoint.pipeActivity": [
        "named pipe", "pipe created", "pipe connected",
        "psexesvc", "paexec pipe", "crackmapexec pipe",
        "sysmon 17", "sysmon 18", "mojo pipe",
    ],
    "endpoint.wmiPersistence": [
        "wmi event filter", "wmi event consumer", "wmi binding",
        "wmi persistence", "wmi subscription", "permanent wmi",
        "sysmon 19", "sysmon 20", "sysmon 21",
    ],
    "endpoint.massFileCreate": [
        "mass file create", "mass file write", "bulk file creation",
        "multiple files written", "file create storm", "ransomware encryption",
    ],
    "endpoint.stateDrift": [
        "state drift", "configuration drift", "autorun added",
        "new scheduled task", "new service", "new installed program",
        "state snapshot", "baseline drift",
    ],
}

# Fields whose *values* are the strongest classification signal.
# These are checked first for a fast-path exact match.
_EVENT_TYPE_FIELDS = {
    "event_type", "eventtype", "action", "category",
    "metadata.event_type", "metadata.product_event_type",
    # OCSF (Open Cybersecurity Schema Framework)
    "activity_name", "class_name", "type_name", "category_name",
    # LEEF (Log Event Extended Format)
    "cat", "devEventClassId", "sev",
    # CEF (Common Event Format)
    "deviceEventClassId", "name",
    # Elastic Common Schema
    "event.category", "event.type", "event.action",
}

# Direct mapping from event_type values → alert types (fast-path)
_EVENT_TYPE_MAP: dict[str, str] = {
    "login_failure": "identity.suspiciousSignIn",
    "login_success": "identity.suspiciousSignIn",
    "account_lockout": "identity.suspiciousSignIn",
    "auth_warning": "identity.suspiciousSignIn",
    "password_spray": "identity.passwordSpray",
    "credential_stuffing": "identity.passwordSpray",
    "mfa_fatigue": "identity.mfaFatigue",
    "mfa_push_denied": "identity.mfaFatigue",
    "oauth_consent": "identity.oauthConsentRisk",
    "privilege_escalation": "identity.privilegeElevation",
    "malware_download": "endpoint.malwareDetection",
    "malware_detected": "endpoint.malwareDetection",
    "threat_list_hit": "endpoint.malwareDetection",
    "file_write": "endpoint.malwareDetection",
    "process_creation": "endpoint.suspiciousProcess",
    "process_execution": "endpoint.suspiciousProcess",
    "suspicious_process": "endpoint.suspiciousProcess",
    "benign_process": "endpoint.suspiciousProcess",
    "registry_modification": "endpoint.suspiciousProcess",
    "file_modification": "endpoint.suspiciousProcess",
    "suspicious_signin": "identity.suspiciousSignIn",
    "failed_login": "identity.suspiciousSignIn",
    "brute_force": "identity.suspiciousSignIn",
    "mfa_denial": "identity.mfaFatigue",
    "consent_grant": "identity.oauthConsentRisk",
    "role_change": "identity.privilegeElevation",
    "admin_elevation": "identity.privilegeElevation",
    "malware": "endpoint.malwareDetection",
    "trojan": "endpoint.malwareDetection",
    "process_injection": "endpoint.suspiciousProcess",
    "email_forwarding": "email.forwardingRule",
    "forwarding_rule": "email.forwardingRule",
    "mail_rule": "email.forwardingRule",
    "secret_access": "cloud.secretStoreAccessAnomaly",
    "key_vault": "cloud.secretStoreAccessAnomaly",
    "api_abuse": "cloud.secretStoreAccessAnomaly",
    "geo_anomaly": "network.impossibleGeoAccess",
    "createaccesskey": "cloud.secretStoreAccessAnomaly",
    "create_access_key": "cloud.secretStoreAccessAnomaly",
    "email_forwarding_rule": "email.forwardingRule",
    "phishing_detected": "email.phishingDetected",
    "phishing": "email.phishingDetected",
    "spear_phishing": "email.phishingDetected",
    "anomalous_api_call": "cloud.secretStoreAccessAnomaly",
    "data_exfiltration": "network.dataExfiltration",
    "large_data_transfer": "network.dataExfiltration",
    "large_upload": "network.dataExfiltration",
    "impossible_travel": "network.impossibleGeoAccess",
    "suspicious_domain": "network.impossibleGeoAccess",
    "blocked_connection": "network.impossibleGeoAccess",
    "allowed_connection": "network.impossibleGeoAccess",
    "network_connection": "network.impossibleGeoAccess",
    "service_restart": "identity.suspiciousSignIn",
    # identity.impossibleTravel
    "impossible_travel_alert": "identity.impossibleTravel",
    "concurrent_session_alert": "identity.impossibleTravel",
    "geo_velocity_violation": "identity.impossibleTravel",
    # identity.dormantAccountLogin
    "dormant_account_login": "identity.dormantAccountLogin",
    "inactive_account_login": "identity.dormantAccountLogin",
    "stale_account_access": "identity.dormantAccountLogin",
    # identity.serviceAccountAbuse
    "service_account_abuse": "identity.serviceAccountAbuse",
    "service_account_interactive": "identity.serviceAccountAbuse",
    "svc_interactive_logon": "identity.serviceAccountAbuse",
    # endpoint.ransomwareDetection
    "ransomware_detected": "endpoint.ransomwareDetection",
    "ransomware_alert": "endpoint.ransomwareDetection",
    "shadow_copy_deleted": "endpoint.ransomwareDetection",
    "mass_encryption": "endpoint.ransomwareDetection",
    # endpoint.lateralMovement
    "lateral_movement_detected": "endpoint.lateralMovement",
    "remote_execution": "endpoint.lateralMovement",
    "psexec_execution": "endpoint.lateralMovement",
    "wmi_remote": "endpoint.lateralMovement",
    # endpoint.credentialDumping
    "credential_dumping": "endpoint.credentialDumping",
    "credential_dump": "endpoint.credentialDumping",
    "lsass_access": "endpoint.credentialDumping",
    "dcsync_detected": "endpoint.credentialDumping",
    # endpoint.persistenceMechanism
    "persistence_detected": "endpoint.persistenceMechanism",
    "scheduled_task_created": "endpoint.persistenceMechanism",
    "registry_autorun": "endpoint.persistenceMechanism",
    "service_installed": "endpoint.persistenceMechanism",
    # endpoint.defenseEvasion
    "defense_evasion": "endpoint.defenseEvasion",
    "av_disabled": "endpoint.defenseEvasion",
    "log_cleared": "endpoint.defenseEvasion",
    "tamper_protection_disabled": "endpoint.defenseEvasion",
    # email.businessEmailCompromise
    "bec_detected": "email.businessEmailCompromise",
    "wire_fraud": "email.businessEmailCompromise",
    "ceo_impersonation": "email.businessEmailCompromise",
    "invoice_fraud": "email.businessEmailCompromise",
    # email.maliciousAttachment
    "malicious_attachment": "email.maliciousAttachment",
    "macro_detected": "email.maliciousAttachment",
    "suspicious_attachment": "email.maliciousAttachment",
    # network.commandAndControl
    "c2_detected": "network.commandAndControl",
    "c2_callback": "network.commandAndControl",
    "beacon_detected": "network.commandAndControl",
    "cobalt_strike": "network.commandAndControl",
    # network.portScan
    "port_scan": "network.portScan",
    "port_scan_detected": "network.portScan",
    "network_scan": "network.portScan",
    "host_discovery": "network.portScan",
    # network.dnsAnomaly
    "dns_tunnel": "network.dnsAnomaly",
    "dns_anomaly": "network.dnsAnomaly",
    "dga_detected": "network.dnsAnomaly",
    "dns_exfiltration": "network.dnsAnomaly",
    # cloud.resourceHijacking
    "crypto_mining": "cloud.resourceHijacking",
    "resource_hijacking": "cloud.resourceHijacking",
    "unauthorized_compute": "cloud.resourceHijacking",
    # cloud.dataExposure
    "public_bucket": "cloud.dataExposure",
    "data_exposure": "cloud.dataExposure",
    "storage_misconfiguration": "cloud.dataExposure",
    # dlp.sensitiveDataExposure
    "dlp_violation": "dlp.sensitiveDataExposure",
    "dlp_alert": "dlp.sensitiveDataExposure",
    "pii_detected": "dlp.sensitiveDataExposure",
    "classification_violation": "dlp.sensitiveDataExposure",
}

_IDENTITY_FIELDS = {
    "userprincipalname", "upn", "user", "username", "user_name",
    "user_upn", "user_email", "account", "principal",
    "account_name", "accountname", "email", "src_user",
    "actor", "actor_user", "actor_user_upn",
    "initiatedby", "caller", "key_owner_user", "auth_user",
    "userdisplay", "owner", "identity",
    # Nested dot-notation paths (from flattened JSON)
    "user.name", "user.email", "user.upn", "user.principal",
    "actor.name", "actor.email",
    # UDM / Google SecOps paths
    "principal.user.email_addresses", "principal.user.userid",
    "target.user.email_addresses", "target.user.userid",
}
_PROCESS_FIELDS = {
    "process", "command_line", "commandline", "cmd", "cmdline",
    "process_name", "processname", "parent_process", "parentprocess",
    "parent_command_line", "image", "process_path", "image_path",
    # UDM / Google SecOps paths
    "target.process.command_line", "target.process.file.full_path",
    "principal.process.command_line", "principal.process.file.full_path",
}
_FILE_PATH_FIELDS = {
    "file_path", "filepath", "full_path", "filename", "file_name",
    "path", "file", "target_filename",
    # UDM / Google SecOps paths
    "target.file.full_path", "principal.file.full_path",
}
_GEO_FIELDS = {
    "country", "country_or_region", "region", "city", "geo",
    "location", "geoip", "geo_country", "geo_city", "src_country", "dest_country",
    "current_country", "prev_country",
    # UDM / Google SecOps paths
    "principal.location.country_or_region", "target.location.country_or_region",
}
_EMAIL_METADATA_FIELDS = {
    "mailfrom", "mailto", "mail_from", "mail_to", "recipient",
    "sender", "from", "to", "cc", "bcc", "subject", "email_subject",
    # UDM / Google SecOps paths
    "network.email.mailfrom", "network.email.to", "network.email.subject",
}
_IP_FIELDS = {
    "ipaddress", "ip_address", "ip", "src_ip", "source_ip",
    "sourceip", "clientip", "client_ip", "remoteip",
    "origin.addr", "origin_addr", "originaddr", "sender_ip",
    "attacker_ip", "remote_addr", "remote.addr",
    "actor_ip", "ssh_source_ip",
    "client_addr", "clientaddr",
    # Nested dot-notation paths (from flattened JSON)
    "network.src_ip", "network.ip", "network.source_ip",
    "network.client_ip", "source.ip",
    # UDM / Google SecOps paths
    "principal.ip", "target.ip", "src.ip",
}
_DEST_IP_FIELDS = {
    "dest_ip", "destination_ip", "destip", "dst_ip",
    "target_ip", "dst.ip", "dest.addr",
}
_DEVICE_FIELDS = {
    "device", "devicename", "device_name", "hostname", "host", "computer",
    "computername", "machine", "machinename", "workstation",
    "asset_tag", "asset", "computer_name", "endpoint",
    "endpoint_name", "asset_name",
    # Kubernetes / container fields
    "node", "pod_name", "container_name", "namespace",
    "cluster", "instance_id",
    # UDM / Google SecOps paths
    "principal.hostname", "target.hostname", "src.hostname",
}
_SEVERITY_FIELDS = {
    "severity", "priority", "risk_level", "risklevel",
    "alertseverity", "threat_level", "risk_band", "risk_score",
    "eventseverity", "event_severity",
    # UDM / Google SecOps paths
    "securityresult.severity", "securityresult.alertseverity",
}
_ALERT_NAME_FIELDS = {
    "alertname", "alert_name", "alert", "title", "name",
    "rulename", "rule_name", "detection", "description",
    "event_type", "eventtype", "category", "action",
    "det_name", "detection_name", "signature", "alerttitle",
    "story", "summary",
    # Nested dot-notation paths (from flattened JSON)
    "event.type", "event.action", "event.category",
    "alert.name", "alert.title",
    # UDM / Google SecOps paths
    "metadata.event_type", "metadata.product_event_type",
    "metadata.description", "securityresult.summary",
    "securityresult.description",
}


def _lower_keys(d: dict[str, Any]) -> dict[str, Any]:
    return {k.lower().strip(): v for k, v in d.items()}


# ── Grouping helpers ─────────────────────────────────────────────────────

_TIMESTAMP_FIELDS = {
    "timestamp", "time", "eventtime", "event_time", "datetime",
    "timegenerated", "created", "when", "occurred",
    "metadata.event_timestamp", "_time",
}


def extract_event_time(row: dict[str, Any]) -> datetime | None:
    """Extract a parseable timestamp from a row, or None."""
    # Try known timestamp field names first
    for k, v in row.items():
        key = k.lower().strip()
        leaf = key.rsplit(".", 1)[-1] if "." in key else key
        if key in _TIMESTAMP_FIELDS or leaf in _TIMESTAMP_FIELDS:
            if v and str(v).strip() not in ("", "null", "none"):
                parsed = _try_parse_timestamp(str(v).strip())
                if parsed:
                    return parsed
    # Fallback: scan all values for ISO-like timestamps
    for v in row.values():
        if isinstance(v, str) and "T" in v and len(v) > 15:
            parsed = _try_parse_timestamp(v.strip())
            if parsed:
                return parsed
    return None


def _try_parse_timestamp(s: str) -> datetime | None:
    """Try common timestamp formats, return datetime or None."""
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def extract_alert_type_category(alert_type: str) -> str:
    """Get the category prefix: 'identity.mfaFatigue' -> 'identity'."""
    return alert_type.split(".")[0] if "." in alert_type else alert_type


def _find_field(row: dict[str, Any], candidates: set[str]) -> str | None:
    """Find first matching field value with priority ordering.

    Priority: UDM dot-notation fields (principal.*, target.*, metadata.*)
              > top-level fields > additional.* / raw_log.* fields.
    This ensures structured SIEM data always wins over arbitrary extras.
    """
    # Tier 1: UDM / structured dot-notation fields
    for k, v in row.items():
        key = k.lower().strip()
        if "." in key and not key.startswith(("additional.", "raw_log.")):
            if key in candidates and v:
                return str(v).strip()
            leaf = key.rsplit(".", 1)[1]
            if leaf in candidates and v:
                return str(v).strip()

    # Tier 2: Top-level fields (not dot-notation)
    for k, v in row.items():
        key = k.lower().strip()
        if "." not in key and key in candidates and v:
            return str(v).strip()

    # Tier 3: additional.* / raw_log.* (lowest priority)
    for k, v in row.items():
        key = k.lower().strip()
        if key.startswith(("additional.", "raw_log.")):
            if key in candidates and v:
                return str(v).strip()
            leaf = key.rsplit(".", 1)[1]
            if leaf in candidates and v:
                return str(v).strip()

    return None


def _extract_event_type_from_nested(row: dict[str, Any]) -> str | None:
    """Walk nested dicts to find event_type / action fields.

    When JSON rows are *not* pre-flattened (e.g. {"metadata": {"event_type": ...}}),
    the fast-path in guess_alert_type cannot see the leaf field.  This helper
    recursively searches up to three levels deep so the mapper works regardless
    of whether the caller flattened first.

    Supports SIEM-standard nested structures:
      - ``{"event": {"category": "..."}}``  (Elastic Common Schema)
      - ``{"metadata": {"event_type": "..."}}``  (Splunk/Sentinel)
      - ``{"security_result": {"summary": "..."}}``  (OCSF/UDM)
    """
    _LEAF_NAMES = {
        "event_type", "eventtype", "action", "category",
        # OCSF
        "activity_name", "class_name", "type_name", "category_name",
        # LEEF
        "cat", "deveventclassid", "sev",
        # CEF
        "deviceeventclassid", "name",
        # Elastic Common Schema
        "type", "action",
    }
    for k, v in row.items():
        if isinstance(v, dict):
            for inner_k, inner_v in v.items():
                if inner_k.lower().strip() in _LEAF_NAMES and inner_v:
                    return str(inner_v).strip()
                # Third level: e.g. {"security_result": {"detail": {"action": "..."}}}
                if isinstance(inner_v, dict):
                    for deep_k, deep_v in inner_v.items():
                        if deep_k.lower().strip() in _LEAF_NAMES and deep_v:
                            return str(deep_v).strip()
    return None


def guess_alert_type(row: dict[str, Any]) -> str:
    """Best-effort alert type classification from a row's fields and values.

    Strategy (in priority order):
    1. Fast-path: if an ``event_type`` / ``action`` column exists, map it
       directly via ``_EVENT_TYPE_MAP``.
    1b. Nested fast-path: look inside nested dicts (e.g. metadata.event_type)
       for event_type fields that were not flattened by the caller.
    2. Keyword scoring: search *values* (weight 3) and column names that
       have a non-empty value (weight 1).  Column names with empty/null
       values are excluded so that CSV headers like ``raw_log.mfa_used``
       don't pollute every row.
    """
    # ── Fast-path: direct event_type mapping ──────────────────────────
    for k, v in row.items():
        if k.lower().strip() in _EVENT_TYPE_FIELDS and v:
            mapped = _EVENT_TYPE_MAP.get(str(v).lower().strip())
            if mapped:
                return mapped

    # ── Nested fast-path: look inside nested dicts for event_type ────
    nested_et = _extract_event_type_from_nested(row)
    if nested_et:
        mapped = _EVENT_TYPE_MAP.get(nested_et.lower().strip())
        if mapped:
            return mapped

    # ── Operation-based classification ──────────────────────────────
    # Check operation/category fields for specific actions
    _OP_FIELDS = {"operation", "category", "action_type", "event_category"}
    _OP_MAP: dict[str, str] = {
        # AD / Kerberos operations
        "discovery": "endpoint.suspiciousProcess",
        "system event": "endpoint.suspiciousProcess",
        "detection": "identity.suspiciousSignIn",
        # Identity operations
        "new-inboxrule": "email.forwardingRule",
        "set-inboxrule": "email.forwardingRule",
        "mfa phone update": "identity.suspiciousSignIn",
        "self-service password reset": "identity.suspiciousSignIn",
        "filesyncdownloadedfull": "cloud.secretStoreAccessAnomaly",
        "gitclone": "cloud.secretStoreAccessAnomaly",
        "filecopiedtoremovablemedia": "cloud.secretStoreAccessAnomaly",
        "messageexport": "cloud.secretStoreAccessAnomaly",
        "session terminated": "identity.suspiciousSignIn",
        # Categories
        "email threat": "email.forwardingRule",
        "credential access": "identity.suspiciousSignIn",
        "financial fraud": "cloud.secretStoreAccessAnomaly",
        "data loss prevention": "cloud.secretStoreAccessAnomaly",
        "cloud app anomaly": "cloud.secretStoreAccessAnomaly",
        "correlated detection": "cloud.secretStoreAccessAnomaly",
        "detection response": "network.impossibleGeoAccess",  # IR actions go to network (scored down by IR signal)
        "exfiltration": "cloud.secretStoreAccessAnomaly",
        "network threat": "network.impossibleGeoAccess",
        "endpoint detection": "endpoint.suspiciousProcess",
        "command and control": "network.impossibleGeoAccess",
        "identity threat": "identity.suspiciousSignIn",
        "collection": "cloud.secretStoreAccessAnomaly",
        "network - baseline": "network.impossibleGeoAccess",
        # Kubernetes / container categories
        "privilege escalation": "identity.privilegeElevation",
        "cloud misconfiguration": "cloud.secretStoreAccessAnomaly",
        "persistence": "endpoint.suspiciousProcess",
        "lateral movement": "network.impossibleGeoAccess",
        "impact": "endpoint.malwareDetection",
        "system - baseline": "network.impossibleGeoAccess",
    }
    for k, v in row.items():
        if k.lower().strip() in _OP_FIELDS and v:
            mapped = _OP_MAP.get(str(v).lower().strip())
            if mapped:
                return mapped

    # ── MITRE tactic hint (if present) — boosts the right category ────
    _MITRE_TACTIC_HINTS: dict[str, str] = {
        "initial access": "identity.suspiciousSignIn",
        "credential access": "identity.passwordSpray",
        "privilege escalation": "identity.privilegeElevation",
        "execution": "endpoint.suspiciousProcess",
        "persistence": "endpoint.suspiciousProcess",
        "lateral movement": "network.impossibleGeoAccess",
        "collection": "cloud.secretStoreAccessAnomaly",
        "exfiltration": "cloud.secretStoreAccessAnomaly",
        "command and control": "network.impossibleGeoAccess",
        "impact": "endpoint.malwareDetection",
        "defense evasion": "endpoint.suspiciousProcess",
        "discovery": "endpoint.suspiciousProcess",
    }
    mitre_hint = None
    for k, v in row.items():
        if k.lower().strip() in ("mitre_tactic", "tactic", "attack_tactic") and v:
            mitre_hint = _MITRE_TACTIC_HINTS.get(str(v).lower().strip())
            break

    # ── Keyword scoring with value-weighted approach ──────────────────
    key_parts: list[str] = []   # column names (only when value present)
    val_parts: list[str] = []   # actual values (high weight)

    for k, v in row.items():
        has_value = v is not None and str(v).strip() not in ("", "null", "none")
        if has_value:
            key_parts.append(k.lower())
            val_parts.append(str(v).lower())

    key_text = " ".join(key_parts)
    val_text = " ".join(val_parts)

    best_type = "identity.suspiciousSignIn"
    best_score = 0
    for alert_type, keywords in _ALERT_TYPE_KEYWORDS.items():
        score = 0
        for kw in keywords:
            if kw in val_text:
                score += 3          # value match = strong signal
            elif kw in key_text:
                score += 1          # key match = weak signal
        # MITRE tactic boost: if this alert type matches the MITRE hint, add bonus
        if mitre_hint and alert_type == mitre_hint:
            score += 2
        if score > best_score:
            best_score = score
            best_type = alert_type

    # If keyword scoring found nothing strong and MITRE hint exists, use it
    if best_score < 3 and mitre_hint:
        return mitre_hint

    return best_type


def map_row_to_raw_alert(
    row: dict[str, Any],
    alert_type_override: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Convert an arbitrary SIEM row into (alertType, rawAlert).

    Returns a tuple of (detected_or_overridden alert type, Vigilis rawAlert dict).
    """
    if _looks_like_vigilis_format(row):
        at = alert_type_override or row.get("alertType") or "identity.suspiciousSignIn"
        return at, row

    alert_type = alert_type_override or guess_alert_type(row)

    upn = _find_field(row, _IDENTITY_FIELDS)
    # Use cross-alert resolved user if primary identity is missing
    if not upn and row.get("_resolved_user"):
        upn = row["_resolved_user"]
    ip = _find_field(row, _IP_FIELDS)
    dest_ip = _find_field(row, _DEST_IP_FIELDS)
    device = _find_field(row, _DEVICE_FIELDS)
    severity_raw = _find_field(row, _SEVERITY_FIELDS)
    alert_name = _find_field(row, _ALERT_NAME_FIELDS)

    raw: dict[str, Any] = {}

    # Filter placeholder user values.
    # WHY: Some alerts use "[multiple]", "SYSTEM", or "multiple" as user fields
    # when the alert targets many users (e.g., Semgrep scanning 3 repos) or is a
    # system event. Treating these as real users breaks grouping (all "[multiple]"
    # cases merge into one) and enrichment (privilege detection fails on "SYSTEM").
    # KNOWN LIMITATION: Filtering "SYSTEM" means Windows SYSTEM-level events lose
    # their identity context. This is acceptable because SYSTEM events are device-
    # anchored, not user-anchored — the device field provides the grouping key.
    _INVALID_USERS = {"[multiple]", "multiple", "system", "n/a", "none", "unknown", ""}
    if upn and upn.strip().lower().strip("[]") in _INVALID_USERS:
        upn = None

    raw["identity"] = {
        "identityType": "user",
        "upn": upn or "unknown@upload",
        "displayName": (upn.split("@")[0] if upn and "@" in upn else upn) or "unknown",
    }

    ips: list[dict[str, Any]] = []
    if ip:
        # Determine role based on whether IP is private/internal
        import ipaddress as _ipa
        try:
            _addr = _ipa.ip_address(ip)
            _is_priv = _addr.is_private or _addr.is_loopback or _addr.is_reserved
        except (ValueError, TypeError):
            _is_priv = False
        ip_role = "observed" if _is_priv else "anomalous"
        ips.append({"role": ip_role, "ipAddress": ip, "geo": {"country": "unknown"}})
    if dest_ip:
        ips.append({"role": "observed", "ipAddress": dest_ip, "geo": {"country": "unknown"}})
    if not ips:
        ips.append({"role": "observed", "ipAddress": "0.0.0.0", "geo": {"country": "unknown"}})
    raw["ips"] = ips

    managed = device is not None
    # Check explicit managed flags from additional fields
    managed_val = _get_additional(row, "managed", "device_managed")
    if managed_val is not None:
        managed = _to_bool(managed_val)
    raw["device"] = {"hostname": device or "unknown-host", "managed": managed}

    if alert_name:
        raw["_sourceAlertName"] = alert_name

    # ── Mine extra columns for enrichment context ──────────────────────
    # entity_value as fallback identity/IP
    entity_type = _get_additional(row, "entity_type")
    entity_value = _get_additional(row, "entity_value")
    if entity_value and entity_type:
        et = str(entity_type).lower()
        ev = str(entity_value)
        if et in ("user", "account") and raw["identity"].get("upn") in (None, "unknown@upload"):
            raw["identity"]["upn"] = ev
            raw["identity"]["displayName"] = ev.split("@")[0] if "@" in ev else ev
        elif et in ("ip", "ipaddress") and not ip:
            raw["ips"].insert(0, {"role": "anomalous", "ipAddress": ev, "geo": {"country": "unknown"}})

    # additional_context for descriptions
    add_ctx = _get_additional(row, "additional_context", "context", "notes", "details",
                              "analyst_note", "description", "comment")
    if add_ctx:
        raw["_additionalContext"] = str(add_ctx)

    # MITRE ATT&CK
    mitre_tactic = _get_additional(row, "mitre_tactic", "tactic", "attack_tactic")
    mitre_technique = _get_additional(row, "mitre_technique", "technique", "attack_technique")
    if mitre_tactic or mitre_technique:
        raw["mitre"] = {"tactic": str(mitre_tactic or ""), "technique": str(mitre_technique or "")}

    # Alert status (Allowed/Blocked/New)
    alert_status = _get_additional(row, "status", "alert_status", "action_result")
    if alert_status:
        raw["_alertStatus"] = str(alert_status)

    # Auth method
    auth_method = _get_additional(row, "auth_method", "authentication_method", "authMethod")
    if auth_method:
        raw["identity"]["authMethod"] = str(auth_method)

    # Source SIEM
    source_siem = _get_additional(row, "source", "data_source", "siem", "source_tool")
    if source_siem:
        raw["_sourceSiem"] = str(source_siem)

    # Category field (for IR response detection)
    category = _get_additional(row, "category", "alert_category", "event_category")
    if category:
        raw["_category"] = str(category).lower().strip()

    # ── Structured insider threat fields ───────────────────────────────
    # Resignation flag
    resign = _get_additional(row, "user_resignation_on_file", "resignation_on_file",
                              "departing_employee", "notice_period")
    if resign is not None and _to_bool(resign):
        raw["_insiderResignation"] = True

    # Access deviation percentage
    dev_pct = _get_additional(row, "access_deviation_pct", "deviation_pct",
                               "anomaly_score", "risk_score")
    if dev_pct is not None:
        try:
            raw["_accessDeviationPct"] = int(dev_pct)
        except (ValueError, TypeError):
            pass

    # Document/file classification labels
    doc_labels = _get_additional(row, "document_labels", "file_labels",
                                  "data_labels", "classification", "repos_classification")
    if doc_labels:
        if isinstance(doc_labels, list):
            raw["_documentLabels"] = doc_labels
        else:
            raw["_documentLabels"] = [s.strip() for s in str(doc_labels).split(",")]

    # Change ticket absence (unauthorized change indicator)
    ticket = _get_additional(row, "change_ticket_id", "ticket_id", "itsm_ticket",
                              "change_request")
    if ticket is not None:
        raw["_hasChangeTicket"] = str(ticket).upper() not in ("NONE", "N/A", "", "NULL")

    # Hidden rule flag
    hidden = _get_additional(row, "rule_hidden", "hidden_rule", "is_hidden")
    if hidden is not None:
        raw["_ruleHidden"] = _to_bool(hidden)

    # Bulk transfer volume
    size_mb = _get_additional(row, "total_size_mb", "size_mb", "data_size_mb")
    size_gb = _get_additional(row, "total_size_gb", "size_gb", "data_size_gb")
    size_bytes = _get_additional(row, "bytes_sent", "bytesSent", "bytes_out",
                                 "bytes", "total_bytes", "byte_count",
                                 "raw_log.bytes_sent", "network.sent_bytes")
    if size_gb is not None:
        try: raw["_transferSizeMB"] = int(float(size_gb) * 1024)
        except (ValueError, TypeError): pass
    elif size_mb is not None:
        try: raw["_transferSizeMB"] = int(size_mb)
        except (ValueError, TypeError): pass
    elif size_bytes is not None:
        try: raw["_transferSizeMB"] = int(float(size_bytes) / (1024 * 1024))
        except (ValueError, TypeError): pass
    # Also preserve raw bytes for extractors that check it directly
    if row.get("bytes") and "_transferSizeMB" not in raw:
        try:
            raw["bytes"] = str(row["bytes"])
            raw["_transferSizeMB"] = int(float(row["bytes"]) / (1024 * 1024))
        except (ValueError, TypeError):
            pass

    # File/item count
    file_count = _get_additional(row, "files_downloaded", "files_copied",
                                  "repos_cloned", "messages_exported", "files_count",
                                  "files_affected", "documents_accessed", "activity_count",
                                  "instance_count", "secret_count", "connection_count")
    if file_count is not None:
        try: raw["_itemCount"] = int(file_count)
        except (ValueError, TypeError): pass

    # Device compliance
    compliance = _get_additional(row, "device_compliance", "compliant", "is_compliant")
    if compliance is not None:
        raw["_deviceCompliant"] = _to_bool(compliance)

    # ── IoT/OT structured fields ─────────────────────────────────────
    cve = _get_additional(row, "cveExploited", "cve_exploited", "cve")
    if cve and str(cve).upper() not in ("NONE", "N/A", "FALSE", ""):
        raw["_cveExploited"] = True

    priv_gained = _get_additional(row, "privilegeGained", "privilege_gained")
    if priv_gained and str(priv_gained).lower() not in ("none", "n/a", ""):
        raw["_privilegeGained"] = str(priv_gained).lower()

    patch_age = _get_additional(row, "patchAge", "patch_age")
    if patch_age:
        # Parse "14months" or "420" (days)
        age_str = str(patch_age).lower().replace("months", "").replace("days", "").strip()
        try:
            age_val = int(age_str)
            if "month" in str(patch_age).lower():
                age_val = age_val * 30
            raw["_unpatchedDays"] = age_val
        except (ValueError, TypeError):
            pass

    safety_level = _get_additional(row, "safetyIntegrityLevel", "safety_integrity_level", "sil")
    if safety_level:
        raw["_safetyLevel"] = str(safety_level)

    modbus_func = _get_additional(row, "modbusFunction", "modbus_function")
    if modbus_func and "write" in str(modbus_func).lower():
        raw["_otProtocolWrite"] = True

    prog_hash = _get_additional(row, "programHash", "program_hash")
    base_hash = _get_additional(row, "baselineHash", "baseline_hash")
    hash_match = _get_additional(row, "hashMatch", "hash_match")
    if hash_match is not None and str(hash_match).lower() == "false":
        raw["_programHashMismatch"] = True
    elif prog_hash and base_hash and str(prog_hash) != str(base_hash):
        raw["_programHashMismatch"] = True

    cams = _get_additional(row, "camerasCompromised", "cameras_compromised", "deviceCount")
    if cams:
        try:
            raw["_devicesCompromised"] = int(cams)
        except (ValueError, TypeError):
            pass

    doors = _get_additional(row, "doorsControlled", "doors_controlled")
    if doors:
        raw["_physicalSecurityCompromised"] = True

    device_type = _get_additional(row, "deviceType", "device_type")
    if device_type:
        raw["_deviceType"] = str(device_type)

    # ── Operation / action context (future-proofing) ──────────────────
    operation = _get_additional(row, "operation", "action_type", "event_action")
    if operation:
        raw["_operation"] = str(operation).lower().strip()

    # Credential submission detection
    cred_type = _get_additional(row, "credential_type", "credential_submitted")
    if cred_type:
        raw["_credentialSubmission"] = str(cred_type)

    # Financial context
    financial_impact = _get_additional(row, "financial_impact_confirmed",
                                        "wire_amount", "fraud_amount", "amount")
    if financial_impact:
        try: raw["_financialImpact"] = float(str(financial_impact).replace(",","").replace("$",""))
        except (ValueError, TypeError): pass
    financial_pending = _get_additional(row, "financial_impact_pending")
    if financial_pending:
        try: raw["_financialPending"] = float(str(financial_pending).replace(",","").replace("$",""))
        except (ValueError, TypeError): pass

    # Lookalike domain detection
    lookalike = _get_additional(row, "lookalike_score", "domain_similarity")
    if lookalike:
        try: raw["_lookalikeScore"] = float(lookalike)
        except (ValueError, TypeError): pass
    domain_age = _get_additional(row, "domain_age_days")
    if domain_age:
        try: raw["_domainAgeDays"] = int(domain_age)
        except (ValueError, TypeError): pass

    # Risk score from source system
    src_risk = _get_additional(row, "risk_score", "url_risk_score", "anomaly_score")
    if src_risk:
        try: raw["_sourceRiskScore"] = int(src_risk)
        except (ValueError, TypeError): pass

    # Session fields for impossible travel
    s1_ip = _get_additional(row, "session_1_ip")
    s2_ip = _get_additional(row, "session_2_ip")
    if s1_ip and s2_ip:
        raw["_sessionIPs"] = [str(s1_ip), str(s2_ip)]
    s1_geo = _get_additional(row, "session_1_geo")
    s2_geo = _get_additional(row, "session_2_geo")
    if s1_geo and s2_geo:
        raw["_sessionGeos"] = [str(s1_geo), str(s2_geo)]
    dist_km = _get_additional(row, "distance_km")
    if dist_km:
        try: raw["_distanceKm"] = int(dist_km)
        except (ValueError, TypeError): pass

    # Noise flag
    noise_flag = _get_additional(row, "noise")
    if noise_flag is not None and _to_bool(noise_flag):
        raw["_isNoise"] = True

    # ── Active Directory context ─────────────────────────────────────
    priv_acct = _get_additional(row, "privileged_account", "is_privileged",
                                 "admin_account")
    if priv_acct is not None and _to_bool(priv_acct):
        raw["identity"]["privilegeTier"] = "admin"

    admin_group = _get_additional(row, "admin_group_member", "domain_admin",
                                   "is_admin")
    if admin_group is not None and _to_bool(admin_group):
        raw["identity"]["privilegeTier"] = "admin"
        raw["_isAdminGroupMember"] = True

    auth_proto = _get_additional(row, "auth_protocol", "authentication_protocol")
    if auth_proto:
        raw["_authProtocol"] = str(auth_proto)

    ticket_type = _get_additional(row, "ticket_type", "kerberos_ticket_type")
    if ticket_type:
        raw["_ticketType"] = str(ticket_type)

    last_pwd = _get_additional(row, "last_password_change_days", "password_age_days")
    if last_pwd:
        try: raw["_passwordAgeDays"] = int(last_pwd)
        except (ValueError, TypeError): pass

    logon_type = _get_additional(row, "logon_type", "logon_method")
    if logon_type:
        raw["_logonType"] = str(logon_type)

    domain_controller = _get_additional(row, "domain_controller", "dc")
    if domain_controller:
        raw["_domainController"] = str(domain_controller)

    # ── Mine enrichment context from additional/flattened fields ──────
    _enrich_identity_context(raw, row)
    _enrich_bulk_target(raw, row)
    _enrich_app_context(raw, row)
    _enrich_file_context(raw, row)
    _enrich_mailbox_context(raw, row)
    _enrich_actor_context(raw, row)
    _enrich_geo_context(raw, row)
    _enrich_network_context(raw, row)

    # ── Context bucket: preserve unmapped fields for explainability ─────
    context: dict[str, Any] = {}
    _mapped_prefixes = (
        "additional.", "raw_log.",
    )
    for k, v in row.items():
        if v is None or str(v).strip() in ("", "null", "none"):
            continue
        key_lower = k.lower().strip()
        # Stash additional.* and raw_log.* into context sub-dicts
        if key_lower.startswith("additional."):
            context.setdefault("additional", {})[k.split(".", 1)[1]] = v
        elif key_lower.startswith("raw_log."):
            context.setdefault("raw_log", {})[k.split(".", 1)[1]] = v
    if context:
        raw["context"] = context

    raw["_originalRow"] = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v)) for k, v in row.items()}

    # Ensure minimum entity presence for strict validation requirements.
    # Cloud alerts need an app entity; email alerts need a mailbox entity.
    if alert_type.startswith("cloud.") and not raw.get("app"):
        src = raw.get("_sourceSiem") or raw.get("_sourceTool") or "unknown"
        raw["app"] = {"name": src, "appId": f"auto:{alert_type}"}
    if alert_type.startswith("email.") and not raw.get("mailbox"):
        upn = (raw.get("identity") or {}).get("upn") or ""
        raw["mailbox"] = {"primaryAddress": upn or "unknown@upload", "ruleName": "auto-detected"}

    return alert_type, raw


# ── Enrichment context miners ────────────────────────────────────────────
# These extract high-value signals from additional/flattened fields and
# populate the nested structures that enrichment mappers expect.

def _get_additional(row: dict[str, Any], *keys: str) -> Any:
    """Find first non-empty value from additional.* or top-level keys."""
    for k in keys:
        # Try additional.key first, then bare key
        for prefix in ("additional.", ""):
            full = f"{prefix}{k}"
            val = row.get(full)
            if val is not None and str(val).strip() not in ("", "null", "none"):
                return val
    return None


def _to_bool(val: Any) -> bool:
    """Coerce a value to boolean."""
    if isinstance(val, bool):
        return val
    s = str(val).lower().strip()
    return s in ("true", "1", "yes")


def _enrich_identity_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate identity.mfaStatus, riskLevel, privilegeTier from row."""
    identity = raw.get("identity") or {}

    mfa = _get_additional(row, "mfa_status", "mfaStatus", "mfa",
                          "mfa_used", "raw_log.mfa_used")
    if mfa is not None:
        mfa_val = str(mfa).lower().strip()
        _MFA_NORMALIZE = {
            "not_satisfied": "disabled",
            "failed": "disabled",
            "bypassed": "disabled",
            "denied": "disabled",
            "not_configured": "not_registered",
            "not required": "not_applicable",
            "not_required": "not_applicable",
            "none": "not_registered",
            "n/a": "not_applicable",
            "": "not_applicable",
            "satisfied": "enabled",
            "passed": "enabled",
            "success": "enabled",
            "true": "enabled",
            "false": "disabled",
            "service account": "not_applicable",
            "service_account": "not_applicable",
        }
        identity["mfaStatus"] = _MFA_NORMALIZE.get(mfa_val, "not_applicable")

    risk = _get_additional(row, "risk", "risk_level", "riskLevel")
    if risk is not None:
        identity["riskLevel"] = str(risk).lower().strip()

    # Check privilege_level column (from multi-SIEM exports)
    priv_level = _get_additional(row, "privilege_level", "privilegeLevel",
                                  "privilege", "account_type")
    if priv_level is not None:
        _PRIV_NORMALIZE = {
            "admin": "admin",
            "administrator": "admin",
            "root": "admin",
            "privileged": "admin",
            "elevated": "admin",
            "standard": "standard",
            "user": "standard",
            "service account": "service_account",
            "service_account": "service_account",
        }
        priv_str = str(priv_level).lower().strip()
        normalized = _PRIV_NORMALIZE.get(priv_str)
        if normalized:
            identity["privilegeTier"] = normalized
        # If not in map, don't set it — avoids schema validation errors
        # from misaligned CSV columns (e.g. MITRE tactics in privilege column)

    # Check privileged flags
    priv = _get_additional(row, "privileged_target", "admin_identity",
                           "privileged", "is_admin")
    if priv is not None and _to_bool(priv):
        identity["privilegeTier"] = "privileged"

    spn = _get_additional(row, "servicePrincipalId", "service_principal_id")
    if spn is not None:
        identity["servicePrincipalId"] = str(spn)
        if not identity.get("identityType") or identity["identityType"] == "user":
            identity["identityType"] = "service_principal"

    failed = _get_additional(row, "failed_attempts", "failedAttempts",
                             "login_failures")
    if failed is not None:
        try:
            identity["failedAttempts"] = int(failed)
        except (ValueError, TypeError):
            pass

    # Auto-detect privilege tier from username patterns if not already set
    if not identity.get("privilegeTier"):
        from backend.app.services.enrichment.base import infer_privilege_tier
        inferred = infer_privilege_tier(raw)
        if inferred:
            identity["privilegeTier"] = inferred

    raw["identity"] = identity


def _enrich_bulk_target(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate bulkTarget from target_count/success_count."""
    count = _get_additional(row, "target_count", "targetCount", "targets")
    success = _get_additional(row, "success_count", "successCount",
                              "successful_logins")
    if count is not None or success is not None:
        bt: dict[str, Any] = raw.get("bulkTarget") or {}
        if count is not None:
            try:
                bt["count"] = int(count)
            except (ValueError, TypeError):
                pass
        if success is not None:
            try:
                bt["successCount"] = int(success)
            except (ValueError, TypeError):
                pass
        raw["bulkTarget"] = bt


def _enrich_app_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate app context from additional fields."""
    app_name = _get_additional(row, "app_name", "appName", "application")
    app_id = _get_additional(row, "appId", "app_id", "applicationId")
    publisher = _get_additional(row, "publisher")
    scopes = _get_additional(row, "scopes")
    first_seen = _get_additional(row, "first_seen", "firstSeen",
                                 "firstSeenInTenantAt")
    api_call = _get_additional(row, "api", "apiOperation", "api_call",
                               "raw_log.api")

    if any(v is not None for v in (app_name, app_id, publisher, scopes,
                                    first_seen, api_call)):
        app: dict[str, Any] = raw.get("app") or {}
        if app_name is not None:
            app["name"] = str(app_name)
        if app_id is not None:
            app["appId"] = str(app_id)
        if publisher is not None:
            app["publisher"] = str(publisher)
        if scopes is not None:
            if isinstance(scopes, list):
                app["scopes"] = scopes
            elif isinstance(scopes, str):
                app["scopes"] = [s.strip() for s in scopes.split(",") if s.strip()]
        if first_seen is not None:
            if _to_bool(first_seen):
                app["firstSeenInTenantAt"] = None
            else:
                app["firstSeenInTenantAt"] = "known"
        if api_call is not None:
            app["apiOperation"] = str(api_call)
            if not app.get("name"):
                app["name"] = str(api_call)
        raw["app"] = app


def _enrich_file_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate file context from additional/process fields."""
    signer = _get_additional(row, "signer")
    prevalence = _get_additional(row, "prevalence")
    full_path = row.get("target.process.file.full_path") or row.get(
        "principal.process.file.full_path")
    cmd_line = (row.get("target.process.command_line")
                or row.get("principal.process.command_line")
                or _get_additional(row, "command_line", "commandline",
                                   "raw_log.command_line"))
    process_name = _get_additional(row, "process", "process_name",
                                   "raw_log.process")
    lolbin = _get_additional(row, "lolbin")
    beacon = _get_additional(row, "beacon")

    has_data = any(v is not None for v in
                   (signer, prevalence, full_path, cmd_line, process_name))
    if has_data:
        f: dict[str, Any] = raw.get("file") or {}
        if signer is not None:
            f["signer"] = str(signer)
        if prevalence is not None:
            f["prevalence"] = str(prevalence).lower().strip()
        if full_path is not None:
            path_str = str(full_path)
            f["filePath"] = path_str
            for sep in ("\\", "/"):
                if sep in path_str:
                    f["fileName"] = path_str.rsplit(sep, 1)[-1]
                    break
            else:
                f["fileName"] = path_str
        elif process_name is not None:
            f["fileName"] = str(process_name)
            f["filePath"] = str(process_name)
        if cmd_line is not None:
            f["commandLine"] = str(cmd_line)
        raw["file"] = f


def _enrich_mailbox_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate mailbox context from additional/email fields."""
    mailbox = _get_additional(row, "mailbox", "primaryAddress")
    forward_to = _get_additional(row, "forward_to", "forwardTo",
                                 "forwardingAddress")
    rule_name = _get_additional(row, "rule_name", "ruleName")
    hidden = _get_additional(row, "hidden")
    executive = _get_additional(row, "executive")

    # Also check email metadata fields
    if mailbox is None:
        mailbox = row.get("network.email.mailfrom")
    if forward_to is None:
        forward_to = row.get("network.email.to")
        # Handle list values
        if isinstance(forward_to, list) and forward_to:
            forward_to = forward_to[0]

    if any(v is not None for v in (mailbox, forward_to, rule_name)):
        mb: dict[str, Any] = raw.get("mailbox") or {}
        if mailbox is not None:
            mb["primaryAddress"] = str(mailbox)
        if forward_to is not None:
            mb["forwardingAddress"] = str(forward_to)
        if rule_name is not None:
            mb["ruleName"] = str(rule_name)
        raw["mailbox"] = mb

    # Mark identity as privileged if executive flag is set
    if executive is not None and _to_bool(executive):
        identity = raw.get("identity") or {}
        identity["privilegeTier"] = "privileged"
        raw["identity"] = identity


def _enrich_actor_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate actor context from additional fields."""
    actor_type = _get_additional(row, "actor_type", "actorType")
    # UDM target.user as actor for privilege elevation
    target_user = row.get("target.user.userid") or row.get(
        "target.user.email_addresses")

    if actor_type is not None or target_user is not None:
        actor: dict[str, Any] = raw.get("actor") or {}
        if actor_type is not None:
            actor["identityType"] = str(actor_type).lower().strip()
        if target_user is not None:
            actor["upn"] = str(target_user)
        raw["actor"] = actor


def _enrich_geo_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Enrich IP geo data from country fields."""
    country = _find_field(row, _GEO_FIELDS)
    prev_country = _get_additional(row, "prev_country", "previous_country")

    ips = raw.get("ips") or []
    if not ips:
        return

    # Set country on the first (anomalous) IP — validate it's a real country
    from backend.app.services.enrichment.base import _is_real_country
    if country and ips and _is_real_country(str(country)):
        geo = ips[0].get("geo") or {}
        if geo.get("country") == "unknown":
            geo["country"] = str(country)
            ips[0]["geo"] = geo

    # If we have a previous country, add a second IP entry to trigger
    # multi_country_ips detection
    if prev_country and str(prev_country) != str(country or ""):
        already_has = len({
            (ip.get("geo") or {}).get("country")
            for ip in ips if isinstance(ip, dict)
        }) >= 2
        if not already_has:
            ips.append({
                "role": "observed",
                "ipAddress": "previous-geo",
                "geo": {"country": str(prev_country)},
            })

    raw["ips"] = ips


def _enrich_network_context(raw: dict[str, Any], row: dict[str, Any]) -> None:
    """Populate network context (bytes sent, protocol) from row."""
    bytes_sent = _get_additional(row, "bytes_sent", "bytesSent",
                                 "raw_log.bytes_sent", "bytes_out",
                                 "network.sent_bytes")
    protocol = _get_additional(row, "protocol", "app_protocol")

    if bytes_sent is not None or protocol is not None:
        net: dict[str, Any] = raw.get("network") or {}
        if bytes_sent is not None:
            try:
                net["bytesSent"] = int(bytes_sent)
            except (ValueError, TypeError):
                pass
        if protocol is not None:
            net["protocol"] = str(protocol)
        raw["network"] = net


def _looks_like_vigilis_format(row: dict[str, Any]) -> bool:
    """Check if the row already has Vigilis rawAlert structure."""
    return "identity" in row and isinstance(row.get("identity"), dict)


def parse_severity(row: dict[str, Any]) -> str:
    """Extract severity from a row, defaulting to medium."""
    raw = _find_field(row, _SEVERITY_FIELDS)
    if not raw:
        return "medium"
    s = raw.lower().strip()
    if s in ("critical", "crit", "4", "p1"):
        return "critical"
    if s in ("high", "3", "p2"):
        return "high"
    if s in ("low", "info", "informational", "1", "p4"):
        return "low"
    # Handle "sev1", "sev2" etc. patterns
    if s.startswith("sev") and s[3:].isdigit():
        s = s[3:]
    # Handle numeric risk bands (1-10 scale, e.g. risk_band)
    try:
        n = int(s)
        if n >= 8:
            return "critical"
        if n >= 6:
            return "high"
        if n >= 3:
            return "medium"
        return "low"
    except ValueError:
        pass
    return "medium"
