"""10-Day Pilot Simulation for Meridian Capital.

Simulates 10 days of SIEM data arriving in daily batches.
Tests multi-day incident correlation, noise suppression, and threat intel.
"""
import json
import os
import time
import httpx
from datetime import datetime, timedelta

BASE_URL = "http://localhost:8000"
AK = "socai-demo-key-do-not-use-in-production"
HEADERS = {"X-API-Key": AK}

# Real known-bad IPs with OTX data
ATTACKER_IPS = {
    "insider_exfil": "162.125.1.1",  # Dropbox (internal -> external)
    "payment_attacker": "185.220.101.45",  # 50 OTX pulses, DE, Tor
    "payment_c2": "94.102.49.190",  # 50 OTX pulses, GB
    "phishing_source": "185.220.100.252",  # 50 OTX pulses, DE, Tor
}

def generate_day(day_num: int) -> list[dict]:
    """Generate alerts for a single day."""
    base_date = datetime(2026, 4, day_num, 0, 0, 0)
    alerts = []

    def ts(hour, minute):
        return (base_date + timedelta(hours=hour, minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def alert(etype, user, ip, sev, host, hour, minute, extra=None):
        alerts.append({
            "metadata": {"event_timestamp": ts(hour, minute), "product_name": "Meridian SIEM", "event_type": etype},
            "principal": {"user": {"userid": user}, "ip": ip},
            "security_result": {"severity": sev},
            "additional": extra or {},
            "target": {"hostname": host}
        })

    # ====== DAILY NOISE (every day) ======
    for i, user in enumerate(["k.johnson@meridian-capital.com", "l.davis@meridian-capital.com", "p.garcia@meridian-capital.com"]):
        alert("login_success", user, f"10.10.1.{50+i}", "LOW", f"WS-CORP-{10+i}", 8+i, 30,
              {"action": "success", "description": "Standard morning login", "geo": "US"})

    alert("login_success", "svc-nagios@meridian-capital.com", "10.10.0.2", "LOW", "MON-01", 6, 0,
          {"action": "success", "description": "Automated monitoring"})

    # IT admin (should score LOW with noise suppression)
    if day_num % 2 == 0:  # Every other day
        alert("suspicious_process", "it-admin@meridian-capital.com", "10.10.0.5", "LOW", "MGMT-01", 10, 0,
              {"action": "process_start", "process_name": "powershell.exe", "description": "Scheduled patch management — change ticket CT-8821"})

    # ====== INSIDER THREAT: j.parker (Days 1-7) ======
    if 1 <= day_num <= 7:
        # After-hours login
        alert("suspicious_signin", "j.parker@meridian-capital.com", "10.50.12.88", "HIGH", "TRADER-WS-04", 23, 15 + day_num,
              {"geo": "US", "action": "success", "description": f"After-hours login night {day_num}"})

        # Process execution (creating archives)
        if day_num >= 2:
            alert("process_execution", "j.parker@meridian-capital.com", "10.50.12.88", "CRITICAL", "TRADER-WS-04", 23, 30 + day_num,
                  {"action": "execute", "process_name": "7z.exe", "command_line": f"7z a -p data_batch_{day_num}.7z C:\\ClientData\\"})

        # Exfiltration (escalates over time)
        if day_num >= 3:
            size = 100 * day_num  # Gets bigger each day
            alert("large_data_transfer", "j.parker@meridian-capital.com", "10.50.12.88", "CRITICAL", "PROXY-01", 23, 45 + day_num,
                  {"action": "upload", "bytes": str(size * 1048576), "dst_ip": ATTACKER_IPS["insider_exfil"],
                   "description": f"Night {day_num}: {size}MB upload to personal cloud"})

        # DLP alert on bigger days
        if day_num in [5, 7]:
            alert("data_exfiltration", "j.parker@meridian-capital.com", "10.50.12.88", "CRITICAL", "DLP-01", 23, 50,
                  {"action": "exfil", "description": f"DLP: cumulative exfiltration threshold exceeded — Day {day_num}"})

    # ====== PAYMENT GATEWAY ATTACK (Days 3-6) ======
    if day_num == 3:
        # Day 3: Reconnaissance / brute force
        for svc in ["svc-payment@meridian-capital.com", "admin-pay@meridian-capital.com", "dba-pay@meridian-capital.com"]:
            alert("suspicious_signin", svc, ATTACKER_IPS["payment_attacker"], "CRITICAL", "PAY-GW-01", 3, 10,
                  {"geo": "DE", "action": "failed", "description": "Brute force from Tor exit"})

    if day_num == 4:
        # Day 4: Compromise + lateral
        alert("suspicious_signin", "admin-pay@meridian-capital.com", ATTACKER_IPS["payment_attacker"], "CRITICAL", "PAY-GW-01", 2, 30,
              {"geo": "DE", "action": "success", "description": "Successful login after brute force"})
        alert("suspicious_process", "admin-pay@meridian-capital.com", ATTACKER_IPS["payment_c2"], "CRITICAL", "PAY-DB-01", 2, 45,
              {"action": "exploit", "description": "SQL injection: SELECT * FROM card_transactions"})

    if day_num == 5:
        # Day 5: Persistence + API key creation
        alert("CreateAccessKey", "admin-pay@meridian-capital.com", ATTACKER_IPS["payment_c2"], "CRITICAL", "PAY-API-01", 1, 15,
              {"action": "create_key", "description": "New API key from scanner IP"})
        alert("privilege_escalation", "admin-pay@meridian-capital.com", ATTACKER_IPS["payment_c2"], "CRITICAL", "PAY-DB-01", 1, 30,
              {"action": "role_change", "description": "Elevated to DBA role on payment database"})

    if day_num == 6:
        # Day 6: Data exfiltration
        alert("data_exfiltration", "admin-pay@meridian-capital.com", ATTACKER_IPS["payment_c2"], "CRITICAL", "PAY-GW-01", 4, 0,
              {"action": "exfil", "bytes": "52428800", "description": "50MB card transaction data to C2 server"})

    # ====== PHISHING CAMPAIGN (Days 5-7) ======
    if day_num == 5:
        # Day 5: Phishing emails sent
        for user in ["m.wong@meridian-capital.com", "r.shah@meridian-capital.com"]:
            alert("phishing_detected", user, ATTACKER_IPS["phishing_source"], "HIGH", "MAIL-GW-01", 9, 0,
                  {"action": "detected", "sender": "ceo-update@merid1an-capital.co", "description": "CEO impersonation phishing"})

    if day_num == 6:
        # Day 6: m.wong clicks link, gets compromised
        alert("suspicious_signin", "m.wong@meridian-capital.com", ATTACKER_IPS["phishing_source"], "CRITICAL", "AAD-01", 9, 15,
              {"geo": "DE", "action": "success", "description": "Login from Germany after phishing click"})

    if day_num == 7:
        # Day 7: Mail forwarding rule set up
        alert("email_forwarding_rule", "m.wong@meridian-capital.com", ATTACKER_IPS["phishing_source"], "CRITICAL", "EXO-01", 10, 0,
              {"action": "rule_created", "forwarding_address": "compliance-audit@protonmail.com", "description": "Forwarding compliance emails"})

    return alerts


def upload_day(day_num: int, alerts: list[dict]) -> dict:
    """Upload one day's alerts and return the result."""
    content = json.dumps(alerts)
    with httpx.Client(timeout=120) as client:
        resp = client.post(
            f"{BASE_URL}/api/v1/demo/upload",
            params={"grouping": "true", "persist": "true"},
            headers=HEADERS,
            files={"file": (f"day_{day_num}.json", content.encode(), "application/json")},
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
    print("MERIDIAN CAPITAL — 10-DAY PILOT SIMULATION")
    print("=" * 60)

    # Reset
    with httpx.Client(timeout=30) as client:
        client.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)
    print("Database reset. Starting pilot...\n")

    total_alerts = 0

    for day in range(1, 11):
        alerts = generate_day(day)
        total_alerts += len(alerts)

        # Save daily file
        _dir = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(_dir, f"pilot_day_{day:02d}.json")
        with open(path, "w") as f:
            json.dump(alerts, f, indent=2)

        # Upload
        result = upload_day(day, alerts)
        cases_today = result.get("caseCount", "?")

        # Wait for auto-correlation
        time.sleep(3)

        # Check incidents
        incidents = get_incidents()
        cases = get_cases()

        # Analyze
        incident_titles = []
        for inc in incidents:
            title = "".join(c if ord(c) < 128 else "?" for c in inc.get("title", "?"))
            incident_titles.append(f"[{inc.get('severity', '?')}] {title} ({inc.get('caseCount', '?')} cases)")

        # j.parker tracking (guard against non-dict entries)
        parker_cases = [c for c in cases if isinstance(c, dict) and "j.parker" in str(c.get("entities", {}))]
        parker_incidents = [inc for inc in incidents if isinstance(inc, dict) and ("parker" in str(inc).lower() or "j.parker" in str(inc).lower())]

        print(f"Day {day:2d}: {len(alerts):3d} alerts -> {cases_today} new cases | Total cases: {len(cases)} | Incidents: {len(incidents)}")
        if day >= 2 and parker_cases:
            print(f"        j.parker: {len(parker_cases)} cases, {len(parker_incidents)} incident(s)")
        for t in incident_titles:
            print(f"        {t}")
        print()

    # Final analysis
    print("=" * 60)
    print("FINAL PILOT REPORT")
    print("=" * 60)

    incidents = get_incidents()
    cases = get_cases()

    print(f"\nTotal alerts ingested: {total_alerts}")
    print(f"Total cases: {len(cases)}")
    print(f"Total incidents: {len(incidents)}")
    print()

    # Grade each attack thread
    parker_incs = [i for i in incidents if isinstance(i, dict) and ("parker" in str(i).lower())]
    payment_incs = [i for i in incidents if isinstance(i, dict) and ("pay" in str(i).lower())]
    phishing_incs = [i for i in incidents if "wong" in str(i).lower() or "phishing" in str(i).lower()]

    print("ATTACK THREAD GRADING:")
    print(f"  j.parker insider: {len(parker_incs)} incident(s) — {'PASS (1 expected)' if len(parker_incs) == 1 else 'FAIL (expected 1, got ' + str(len(parker_incs)) + ')'}")
    print(f"  Payment gateway:  {len(payment_incs)} incident(s) — {'PASS' if len(payment_incs) == 1 else 'NEEDS REVIEW (' + str(len(payment_incs)) + ')'}")
    print(f"  Phishing m.wong:  {len(phishing_incs)} incident(s) — {'PASS' if len(phishing_incs) == 1 else 'NEEDS REVIEW (' + str(len(phishing_incs)) + ')'}")

    # Noise check
    noise_users = ["k.johnson", "l.davis", "p.garcia", "svc-nagios", "it-admin"]
    noise_cases = [c for c in cases if isinstance(c, dict) and any(n in str(c.get("entities", {})).lower() for n in noise_users)]
    noise_scores = [c["confidence"]["score"] for c in noise_cases]
    noise_in_incidents = [i for i in incidents if any(n in str(i).lower() for n in noise_users)]

    print(f"\n  Noise suppression:")
    print(f"    Noise cases: {len(noise_cases)}, avg score: {sum(noise_scores)/max(len(noise_scores),1):.0f}")
    print(f"    Noise in incidents: {len(noise_in_incidents)} — {'PASS (0 expected)' if len(noise_in_incidents) == 0 else 'FAIL'}")

    # Overall
    total_attack_incidents = len(parker_incs) + len(payment_incs) + len(phishing_incs)
    expected = 3
    print(f"\n  OVERALL: {total_attack_incidents} attack incidents (expected {expected})")
    if total_attack_incidents == expected and len(noise_in_incidents) == 0:
        print("  GRADE: A — All attacks detected as single incidents, noise suppressed")
    elif total_attack_incidents <= expected + 2 and len(noise_in_incidents) == 0:
        print("  GRADE: B — Minor incident fragmentation but noise suppressed")
    else:
        print(f"  GRADE: C — {total_attack_incidents} attack incidents, {len(noise_in_incidents)} noise incidents")


if __name__ == "__main__":
    run_pilot()
