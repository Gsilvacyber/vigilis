"""CICIDS 2017 Dataset Test — TechVault Corp Simulation.

Uses the real CICIDS 2017 Kaggle dataset (flow statistics + labels).
The dataset lacks IPs, users, and timestamps — we synthesize realistic
context around the real flow data to test how Vigilis handles:
- Real-world attack label distribution
- Mixed benign/malicious traffic
- Multiple concurrent attack types
- High-volume data (sampling from 2.8M rows)

Company: TechVault Corp (cloud infrastructure provider)
"""
import json
import os
import random
import sys
import time
import zipfile
import httpx
from datetime import datetime, timedelta

BASE_URL = os.getenv("VIGILIS_URL", "http://localhost:8000")
AK = os.getenv("DEMO_API_KEY", "socai-demo-key-do-not-use-in-production")
HEADERS = {"X-API-Key": AK}

# CICIDS 2017 dataset archive path. Override via CICIDS_ARCHIVE env var or
# pass as first CLI arg. Download from:
#   https://www.kaggle.com/datasets/cicdataset/cicids2017
ARCHIVE_PATH = (
    sys.argv[1] if len(sys.argv) > 1
    else os.getenv("CICIDS_ARCHIVE", "cicids2017.zip")
)

# Known-bad IPs for threat intel enrichment
ATTACKER_IPS = {
    "ddos_botnet": "185.220.101.45",      # OTX known Tor
    "brute_force": "94.102.49.190",        # OTX known C2
    "web_attack": "23.129.64.100",         # Tor exit range
    "infiltration": "185.220.100.252",     # OTX known Tor
    "portscan": "209.141.58.100",          # Known scanner range
}

# TechVault legitimate users
USERS = [
    "m.chen@techvault.io",
    "k.williams@techvault.io",
    "r.patel@techvault.io",
    "j.garcia@techvault.io",
    "svc-monitoring@techvault.io",
    "svc-backup@techvault.io",
]

SERVERS = ["WEB-01", "WEB-02", "DB-01", "APP-01", "PROXY-01", "FW-01", "MAIL-01"]


def load_attack_samples() -> dict[str, list[dict]]:
    """Load a sample of attack rows from each CICIDS file."""
    attack_samples: dict[str, list[dict]] = {}

    with zipfile.ZipFile(ARCHIVE_PATH, "r") as z:
        for fname in z.namelist():
            with z.open(fname) as f:
                header_line = f.readline().decode("utf-8", errors="replace").strip()
                cols = [c.strip() for c in header_line.split(",")]

                attacks_this_file = []
                benign_count = 0
                total = 0

                for raw_line in f:
                    total += 1
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    vals = line.split(",")
                    if len(vals) != len(cols):
                        continue

                    label = vals[-1].strip()
                    if label == "BENIGN":
                        benign_count += 1
                        continue

                    # Sample: keep ~50 attack rows per file max
                    if len(attacks_this_file) < 50:
                        row = {}
                        for i, col in enumerate(cols):
                            row[col] = vals[i].strip()
                        attacks_this_file.append(row)
                    elif random.random() < 50.0 / total:
                        # Reservoir sampling for uniform distribution
                        idx = random.randint(0, len(attacks_this_file) - 1)
                        row = {}
                        for i, col in enumerate(cols):
                            row[col] = vals[i].strip()
                        attacks_this_file[idx] = row

                if attacks_this_file:
                    # Group by label
                    for row in attacks_this_file:
                        label = row.get("Label", "unknown")
                        attack_samples.setdefault(label, []).append(row)

                short = fname.split(".pcap")[0].replace("-WorkingHours", "")
                print(f"  Loaded {short[:35]:35s}: {len(attacks_this_file)} attack samples, "
                      f"{benign_count:,} benign skipped")

    return attack_samples


def cicids_to_alert(row: dict, label: str, day: int, hour: int, minute: int) -> dict:
    """Convert a CICIDS flow row into a SIEM-style alert."""
    base_date = datetime(2026, 4, day, 0, 0, 0)
    ts = (base_date + timedelta(hours=hour, minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Map CICIDS label → our alert structure
    label_map = {
        "DDoS": {
            "event_type": "blocked_connection",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["ddos_botnet"],
            "description": "DDoS flood detected — volumetric attack against web infrastructure",
            "hostname": random.choice(["WEB-01", "WEB-02", "PROXY-01"]),
        },
        "PortScan": {
            "event_type": "suspicious_domain",  # network recon
            "severity": "MEDIUM",
            "src_ip": ATTACKER_IPS["portscan"],
            "description": "Port scan detected — reconnaissance against internal network",
            "hostname": random.choice(["FW-01", "PROXY-01"]),
        },
        "Bot": {
            "event_type": "suspicious_process",
            "severity": "CRITICAL",
            "src_ip": ATTACKER_IPS["ddos_botnet"],
            "description": "Bot C2 callback detected — compromised host beaconing",
            "hostname": random.choice(["WEB-01", "APP-01"]),
            "user": random.choice(USERS[:4]),
        },
        "Infiltration": {
            "event_type": "data_exfiltration",
            "severity": "CRITICAL",
            "src_ip": ATTACKER_IPS["infiltration"],
            "description": "Data infiltration/exfiltration detected — lateral movement with data theft",
            "hostname": "DB-01",
            "user": "r.patel@techvault.io",
        },
        "FTP-Patator": {
            "event_type": "suspicious_signin",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["brute_force"],
            "description": "FTP brute force attack — Patator tool signature detected",
            "hostname": "FTP-01",
        },
        "SSH-Patator": {
            "event_type": "suspicious_signin",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["brute_force"],
            "description": "SSH brute force attack — Patator tool detected against server",
            "hostname": random.choice(["WEB-01", "APP-01", "DB-01"]),
        },
        "DoS slowloris": {
            "event_type": "blocked_connection",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["ddos_botnet"],
            "description": "Slowloris DoS attack — connection exhaustion against web server",
            "hostname": "WEB-01",
        },
        "DoS Slowhttptest": {
            "event_type": "blocked_connection",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["ddos_botnet"],
            "description": "SlowHTTPTest DoS — slow HTTP POST body attack",
            "hostname": "WEB-02",
        },
        "DoS Hulk": {
            "event_type": "blocked_connection",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["ddos_botnet"],
            "description": "HULK DoS attack — unique URL generation flood",
            "hostname": random.choice(["WEB-01", "WEB-02"]),
        },
        "DoS GoldenEye": {
            "event_type": "blocked_connection",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["ddos_botnet"],
            "description": "GoldenEye DoS attack — HTTP KeepAlive exploitation",
            "hostname": "WEB-01",
        },
        "Heartbleed": {
            "event_type": "suspicious_process",
            "severity": "CRITICAL",
            "src_ip": ATTACKER_IPS["web_attack"],
            "description": "Heartbleed (CVE-2014-0160) exploit attempt — TLS memory disclosure",
            "hostname": "WEB-01",
            "user": "svc-monitoring@techvault.io",
        },
    }

    # Handle "Web Attack" labels with special chars
    clean_label = label
    for prefix in ["Web Attack", "Web Attack "]:
        if label.startswith(prefix):
            suffix = label.replace(prefix, "").strip().strip("\ufffd").strip("-").strip()
            if "Brute" in label:
                clean_label = "Web-Brute-Force"
            elif "XSS" in label:
                clean_label = "Web-XSS"
            elif "Sql" in label or "SQL" in label:
                clean_label = "Web-SQLi"
            break

    web_attack_map = {
        "Web-Brute-Force": {
            "event_type": "suspicious_signin",
            "severity": "HIGH",
            "src_ip": ATTACKER_IPS["web_attack"],
            "description": "Web application brute force — repeated auth failures on login endpoint",
            "hostname": "WEB-01",
        },
        "Web-XSS": {
            "event_type": "suspicious_process",
            "severity": "CRITICAL",
            "src_ip": ATTACKER_IPS["web_attack"],
            "description": "Cross-site scripting (XSS) attack — malicious script injection detected",
            "hostname": "WEB-01",
        },
        "Web-SQLi": {
            "event_type": "suspicious_process",
            "severity": "CRITICAL",
            "src_ip": ATTACKER_IPS["web_attack"],
            "description": "SQL injection attack — malicious query detected in request parameters",
            "hostname": "DB-01",
            "user": "svc-monitoring@techvault.io",
        },
    }

    config = label_map.get(label) or web_attack_map.get(clean_label)
    if not config:
        config = {
            "event_type": "suspicious_process",
            "severity": "MEDIUM",
            "src_ip": ATTACKER_IPS["web_attack"],
            "description": f"CICIDS attack detected: {label}",
            "hostname": "WEB-01",
        }

    # Build alert with CICIDS flow metrics as additional context
    dst_port = row.get("Destination Port", "0")
    flow_bytes = row.get("Flow Bytes/s", "0")
    fwd_packets = row.get("Total Fwd Packets", "0")
    bwd_packets = row.get("Total Backward Packets", "0")

    alert = {
        "timestamp": ts,
        "event_type": config["event_type"],
        "severity": config["severity"],
        "src_ip": config["src_ip"],
        "hostname": config["hostname"],
        "source": "TechVault-IDS",
        "description": config["description"],
        "action": "detected",
        # Preserve real CICIDS flow data
        "dst_port": dst_port,
        "flow_bytes_per_sec": flow_bytes,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "cicids_label": label,
    }
    if "user" in config:
        alert["user"] = config["user"]

    return alert


def generate_benign_noise(day: int) -> list[dict]:
    """Generate daily benign noise alerts."""
    base_date = datetime(2026, 4, day, 0, 0, 0)
    alerts = []

    # Normal user logins
    for i, user in enumerate(USERS[:4]):
        ts = (base_date + timedelta(hours=8 + i, minutes=10 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        alerts.append({
            "timestamp": ts,
            "event_type": "login_success",
            "severity": "LOW",
            "src_ip": f"10.10.{1 + i}.{100 + day}",
            "hostname": f"WS-{100 + i}",
            "user": user,
            "source": "TechVault-AD",
            "description": "Standard workday login",
            "action": "success",
            "geo": "US",
        })

    # Service account activity
    ts = (base_date + timedelta(hours=0, minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    alerts.append({
        "timestamp": ts,
        "event_type": "login_success",
        "severity": "LOW",
        "src_ip": "10.10.0.5",
        "hostname": "MON-01",
        "user": "svc-monitoring@techvault.io",
        "source": "TechVault-AD",
        "description": "Automated health check cycle",
        "action": "success",
    })

    return alerts


def run_cicids_pilot():
    print("=" * 65)
    print("TECHVAULT CORP - CICIDS 2017 REAL DATASET PILOT")
    print("=" * 65)
    print("Source: CICIDS 2017 Kaggle dataset (2.8M+ flow records)")
    print("Format: Flow statistics + attack labels (no IPs/users in raw data)")
    print("Test: Can Vigilis handle real-world attack data distributions?\n")

    # Load attack samples
    print("Loading attack samples from archive...")
    random.seed(42)  # Reproducible sampling
    attack_samples = load_attack_samples()

    print(f"\nAttack types found: {len(attack_samples)}")
    for label, samples in sorted(attack_samples.items()):
        safe_label = label.encode("ascii", errors="replace").decode("ascii")
        print(f"  {safe_label:35s}: {len(samples)} samples")

    # Reset
    with httpx.Client(timeout=30) as client:
        client.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)
    print("\nDatabase reset. Starting 5-day pilot...\n")

    # Simulate 5 days with different attack mixes
    day_plan = {
        1: ["FTP-Patator", "SSH-Patator"],  # Brute force day
        2: ["DoS slowloris", "DoS Hulk", "DoS GoldenEye"],  # DoS day
        3: ["PortScan", "Infiltration", "Bot"],  # Recon + infiltration
        4: ["DDoS"],  # Major DDoS
        5: ["Heartbleed", "Bot", "Infiltration"],  # Exploit + persistent
    }

    # Add web attacks to days 3 and 5
    for label in attack_samples:
        if "Web Attack" in label or label.startswith("Web-"):
            day_plan.setdefault(3, []).append(label)
            day_plan.setdefault(5, []).append(label)

    total_alerts = 0
    for day in range(1, 6):
        alerts = generate_benign_noise(day)

        # Add attack alerts for this day
        planned_attacks = day_plan.get(day, [])
        hour = 10  # Attacks start at 10am
        for label in planned_attacks:
            samples = attack_samples.get(label, [])
            # Take up to 8 samples per attack type per day
            for i, row in enumerate(samples[:8]):
                minute = (i * 7) % 60
                alert = cicids_to_alert(row, label, day, hour + (i // 8), minute)
                alerts.append(alert)
            hour += 2  # Space attack types 2 hours apart

        total_alerts += len(alerts)

        # Upload
        content = json.dumps(alerts)
        with httpx.Client(timeout=120) as client:
            resp = client.post(
                f"{BASE_URL}/api/v1/demo/upload",
                params={"grouping": "true", "persist": "true"},
                headers=HEADERS,
                files={"file": (f"techvault_day_{day}.json", content.encode(), "application/json")},
            )
            result = resp.json()

        time.sleep(4)

        with httpx.Client(timeout=30) as client:
            cases = client.get(f"{BASE_URL}/api/v1/cases", params={"limit": 100}, headers=HEADERS).json()
            incidents = client.get(f"{BASE_URL}/api/v1/incidents", headers=HEADERS).json()

        at_dist = result.get("alertTypeDistribution", {})
        print(f"Day {day}: {len(alerts):3d} alerts -> {result.get('caseCount', '?')} cases | "
              f"Total: {len(cases)} cases, {len(incidents)} incidents")
        print(f"       Types: {at_dist}")
        safe_attacks = [a.encode("ascii", errors="replace").decode("ascii") for a in planned_attacks]
        print(f"       Attacks: {safe_attacks}")
        for inc in incidents:
            if isinstance(inc, dict):
                title = "".join(c if ord(c) < 128 else "?" for c in inc.get("title", "?"))
                nc = inc.get("caseCount", "?")
                sev = inc.get("severity", "?")
                print(f"       [{sev}] {title} ({nc} cases)")
        print()

    # Final report
    print("=" * 65)
    print("TECHVAULT CICIDS 2017 PILOT REPORT")
    print("=" * 65)

    with httpx.Client(timeout=30) as client:
        cases = client.get(f"{BASE_URL}/api/v1/cases", params={"limit": 100}, headers=HEADERS).json()
        incidents = client.get(f"{BASE_URL}/api/v1/incidents", headers=HEADERS).json()

    print(f"\nTotal alerts ingested: {total_alerts}")
    print(f"Total cases: {len(cases)}")
    print(f"Total incidents: {len(incidents)}")

    # Score analysis
    noise_users = ["m.chen", "k.williams", "r.patel", "j.garcia", "svc-monitoring", "svc-backup"]
    attack_cases = []
    noise_cases = []
    for c in cases:
        if not isinstance(c, dict):
            continue
        ent = c.get("entities", {})
        ident = ent.get("identity", {}) if isinstance(ent, dict) else {}
        upn = ident.get("upn", "") if isinstance(ident, dict) else ""
        score = c.get("confidence", {}).get("score", 0) if isinstance(c.get("confidence"), dict) else 0
        at = c.get("alertType", "")

        if any(n in upn.lower() for n in noise_users) and at == "identity.suspiciousSignIn" and score < 30:
            noise_cases.append(c)
        elif score >= 50 or "unknown" in upn.lower():
            attack_cases.append(c)

    noise_in_incidents = [i for i in incidents if any(n in str(i).lower() for n in noise_users[:4])]

    print(f"\nAttack cases (score >= 50): {len(attack_cases)}")
    print(f"Noise cases (low-score logins): {len(noise_cases)}")
    print(f"Noise in incidents: {len(noise_in_incidents)}")

    print(f"\nAll incidents:")
    for inc in incidents:
        if isinstance(inc, dict):
            title = "".join(c if ord(c) < 128 else "?" for c in inc.get("title", "?"))
            nc = inc.get("caseCount", "?")
            sev = inc.get("severity", "?")
            conf = inc.get("confidenceScore", "?")
            print(f"  [{sev:10s}] {title:55s} ({nc} cases, {conf}% conf)")

    print(f"\nAll attack cases by type:")
    type_summary = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        at = c.get("alertType", "?")
        score = c.get("confidence", {}).get("score", 0) if isinstance(c.get("confidence"), dict) else 0
        if score >= 40:
            type_summary.setdefault(at, []).append(score)
    for at, scores in sorted(type_summary.items()):
        print(f"  {at:40s}: {len(scores)} cases, scores {min(scores)}-{max(scores)}")

    # Grade
    has_incidents = len(incidents) >= 1
    noise_clean = len(noise_in_incidents) == 0
    if has_incidents and noise_clean and len(incidents) >= 2:
        print(f"\n  GRADE: A - {len(incidents)} incidents detected, noise clean")
    elif has_incidents and noise_clean:
        print(f"\n  GRADE: B - {len(incidents)} incident(s) detected, noise clean")
    elif has_incidents:
        print(f"\n  GRADE: C - {len(incidents)} incidents but noise contamination")
    else:
        print(f"\n  GRADE: D - No incidents detected")


if __name__ == "__main__":
    run_cicids_pilot()
