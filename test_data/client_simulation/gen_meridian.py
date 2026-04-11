"""Generate Meridian Capital client simulation dataset."""
import json
import os

alerts = []

def ts(day, hour, minute):
    return f"2026-04-{day:02d}T{hour:02d}:{minute:02d}:00Z"

def add(etype, user, ip, sev, host, day, hour, minute, extra=None):
    alerts.append({
        "metadata": {"event_timestamp": ts(day,hour,minute), "product_name": "Meridian SIEM", "event_type": etype},
        "principal": {"user": {"userid": user}, "ip": ip},
        "security_result": {"severity": sev},
        "additional": extra or {},
        "target": {"hostname": host}
    })

# ====== SCENARIO A: Insider Threat - j.parker (junior trader) ======
# After-hours logins over multiple nights
add("suspicious_signin","j.parker@meridian-capital.com","10.50.12.88","HIGH","TRADER-WS-04",7,23,15,{"geo":"US","action":"success","description":"After-hours VPN login from trading floor"})
add("suspicious_signin","j.parker@meridian-capital.com","10.50.12.88","HIGH","TRADER-WS-04",8,0,30,{"geo":"US","action":"success","description":"Login at 12:30 AM"})
add("suspicious_signin","j.parker@meridian-capital.com","10.50.12.88","MEDIUM","TRADER-WS-04",8,23,45,{"geo":"US","action":"success","description":"After-hours login third night"})
add("suspicious_signin","j.parker@meridian-capital.com","10.50.12.88","HIGH","TRADER-WS-04",9,1,10,{"geo":"US","action":"success","description":"1 AM login"})
add("suspicious_signin","j.parker@meridian-capital.com","10.50.12.88","HIGH","TRADER-WS-04",10,0,5,{"geo":"US","action":"success","description":"5th consecutive after-hours session"})
# Encrypted archives
add("process_execution","j.parker@meridian-capital.com","10.50.12.88","CRITICAL","TRADER-WS-04",8,0,45,{"action":"execute","process_name":"7z.exe","command_line":"7z a -p client_portfolios.7z C:\\ClientData\\","parent_process":"explorer.exe"})
add("process_execution","j.parker@meridian-capital.com","10.50.12.88","CRITICAL","TRADER-WS-04",9,1,30,{"action":"execute","process_name":"7z.exe","command_line":"7z a -p q4_trades.7z C:\\TradingRecords\\"})
add("suspicious_process","j.parker@meridian-capital.com","10.50.12.88","HIGH","TRADER-WS-04",10,0,20,{"action":"process_start","process_name":"rclone.exe","description":"Cloud sync tool - not approved"})
# Exfiltration to personal cloud
add("large_data_transfer","j.parker@meridian-capital.com","10.50.12.88","CRITICAL","PROXY-01",8,1,0,{"action":"upload","bytes":"524288000","dst_ip":"162.125.1.1","description":"500MB to Dropbox"})
add("large_data_transfer","j.parker@meridian-capital.com","10.50.12.88","CRITICAL","PROXY-01",9,1,45,{"action":"upload","bytes":"314572800","dst_ip":"162.125.1.1","description":"300MB to cloud"})
add("large_data_transfer","j.parker@meridian-capital.com","10.50.12.88","CRITICAL","PROXY-01",10,0,35,{"action":"upload","bytes":"209715200","dst_ip":"162.125.1.1","description":"200MB - cumulative 1GB+"})
add("data_exfiltration","j.parker@meridian-capital.com","10.50.12.88","CRITICAL","DLP-01",10,0,40,{"action":"exfil","bytes":"1048576000","description":"DLP: 1GB+ sensitive data to unauthorized dest"})
# API abuse
add("anomalous_api_call","j.parker@meridian-capital.com","10.50.12.88","HIGH","API-GW-01",9,2,0,{"action":"api_abuse","description":"Client Portfolio API at 2 AM"})
add("anomalous_api_call","j.parker@meridian-capital.com","10.50.12.88","HIGH","API-GW-01",10,0,15,{"action":"api_abuse","description":"Bulk download 847 client records"})

# ====== SCENARIO B: Payment Gateway Attack ======
attacker1 = "185.220.101.45"  # 50 OTX pulses, DE, Tor exit
attacker2 = "94.102.49.190"   # 50 OTX pulses, GB, scanner
exfil_ip = "198.235.24.20"    # 50 OTX pulses, CA, C2

for i,svc in enumerate(["svc-payment@meridian-capital.com","svc-settle@meridian-capital.com","svc-clearing@meridian-capital.com","admin-pay@meridian-capital.com","root-pay@meridian-capital.com","dba-pay@meridian-capital.com"]):
    add("suspicious_signin",svc,attacker1,"CRITICAL","PAY-GW-01",10,3,i*2,{"geo":"DE","action":"failed","description":"Brute force from Tor exit"})

add("suspicious_process","svc-payment@meridian-capital.com",attacker1,"CRITICAL","PAY-GW-01",10,3,15,{"action":"exploit","description":"SQL injection: SELECT * FROM card_transactions WHERE 1=1--"})
add("suspicious_process","svc-payment@meridian-capital.com",attacker1,"CRITICAL","PAY-DB-01",10,3,18,{"action":"exploit","description":"xp_cmdshell attempt"})
add("suspicious_process","admin-pay@meridian-capital.com",attacker2,"CRITICAL","PAY-DB-01",10,3,20,{"action":"exploit","description":"DB privilege escalation"})

add("CreateAccessKey","admin-pay@meridian-capital.com",attacker2,"CRITICAL","PAY-API-01",10,3,25,{"action":"create_key","description":"API key from scanner IP"})
add("CreateAccessKey","admin-pay@meridian-capital.com",attacker2,"HIGH","PAY-API-01",10,3,28,{"action":"create_key","description":"Second key - persistence"})

add("data_exfiltration","admin-pay@meridian-capital.com",exfil_ip,"CRITICAL","PAY-GW-01",10,3,35,{"action":"exfil","bytes":"52428800","description":"50MB card data to C2"})
add("data_exfiltration","admin-pay@meridian-capital.com",exfil_ip,"CRITICAL","PAY-GW-01",10,3,38,{"action":"exfil","bytes":"31457280","description":"30MB PII exfil - blocked by DLP"})

# ====== SCENARIO C: Phishing Campaign ======
phish_ip = "185.220.100.252"  # 50 OTX pulses, DE, Tor

add("phishing_detected","m.wong@meridian-capital.com",phish_ip,"HIGH","MAIL-GW-01",10,9,0,{"action":"detected","sender":"ceo-update@merid1an-capital.co","description":"CEO impersonation phishing"})
add("phishing_detected","r.shah@meridian-capital.com",phish_ip,"HIGH","MAIL-GW-01",10,9,1,{"action":"detected","sender":"ceo-update@merid1an-capital.co","description":"Same campaign targeting CFO"})
add("phishing_detected","t.chen@meridian-capital.com",phish_ip,"HIGH","MAIL-GW-01",10,9,2,{"action":"detected","sender":"ceo-update@merid1an-capital.co","description":"Third target - compliance"})
add("phishing_detected","m.wong@meridian-capital.com",phish_ip,"CRITICAL","MAIL-GW-01",10,9,5,{"action":"clicked","sender":"ceo-update@merid1an-capital.co","description":"User clicked phishing link"})

add("suspicious_signin","m.wong@meridian-capital.com",phish_ip,"CRITICAL","AAD-01",10,9,15,{"geo":"DE","action":"success","description":"Login from Germany after phishing click"})
add("login_success","m.wong@meridian-capital.com",phish_ip,"HIGH","AAD-01",10,9,16,{"geo":"DE","action":"success","description":"MFA bypassed via real-time proxy"})

add("email_forwarding_rule","m.wong@meridian-capital.com",phish_ip,"CRITICAL","EXO-01",10,9,20,{"action":"rule_created","forwarding_address":"compliance-audit@protonmail.com","description":"Forwarding compliance emails to external"})

# ====== SCENARIO D: Normal Operations (NOISE) ======
for i,user in enumerate(["k.johnson@meridian-capital.com","l.davis@meridian-capital.com","p.garcia@meridian-capital.com","a.kim@meridian-capital.com","s.patel@meridian-capital.com"]):
    add("login_success",user,f"10.10.1.{50+i}","LOW",f"WS-CORP-{10+i}",10,8+i,30,{"geo":"US","action":"success","description":"Standard morning login"})

add("suspicious_process","it-admin@meridian-capital.com","10.10.0.5","LOW","MGMT-01",10,10,0,{"action":"process_start","process_name":"powershell.exe","command_line":"Get-WindowsUpdate","description":"Patch management"})
add("suspicious_process","it-admin@meridian-capital.com","10.10.0.5","LOW","MGMT-01",10,10,15,{"action":"process_start","process_name":"psexec.exe","description":"GP refresh - maintenance"})
add("suspicious_process","it-admin@meridian-capital.com","10.10.0.5","LOW","MGMT-01",10,10,30,{"action":"process_start","process_name":"nmap.exe","description":"Authorized vuln scan CT-4521"})

add("login_success","svc-nagios@meridian-capital.com","10.10.0.2","LOW","MON-01",10,6,0,{"action":"success","description":"Automated monitoring"})
add("login_success","svc-nagios@meridian-capital.com","10.10.0.2","LOW","MON-01",10,7,0,{"action":"success","description":"Hourly health check"})

# Save
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meridian_capital_alerts.json")
with open(path, "w") as f:
    json.dump(alerts, f, indent=2)

insider = sum(1 for x in alerts if "j.parker" in str(x))
payment = sum(1 for x in alerts if any(s in str(x) for s in ["pay","settle","clearing"]) and "j.parker" not in str(x))
phishing = sum(1 for x in alerts if any(s in str(x) for s in ["m.wong","r.shah","t.chen","phishing"]))
noise = len(alerts) - insider - payment - phishing

print(f"Total: {len(alerts)} alerts")
print(f"  A. Insider (j.parker): {insider}")
print(f"  B. Payment attack: {payment}")
print(f"  C. Phishing campaign: {phishing}")
print(f"  D. Noise: {noise}")
print(f"Saved: {path}")
