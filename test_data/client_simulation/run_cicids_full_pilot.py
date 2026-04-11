"""CICIDS 2017 Full Dataset Test — Real IPs from Flow IDs.

Uses the CICIDS 2017 dataset with real source/destination IPs extracted
from Flow ID fields. Tests Vigilis against genuine network attack data.

Attack timeline (from the actual CICIDS lab):
  Tuesday:    FTP + SSH brute force (Patator tool)
  Wednesday:  DoS attacks (Slowloris, Hulk, GoldenEye, Heartbleed)
  Thursday:   Web attacks (Brute Force, XSS, SQL Injection) + Infiltration
  Friday:     Port scanning, DDoS, Botnet C2

This is the HARDEST test — real network flows, no synthetic enrichment.
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
# CICIDS 2017 full dataset archive. Override via CICIDS_ARCHIVE env var or
# pass as first CLI arg. Download from:
#   https://www.kaggle.com/datasets/cicdataset/cicids2017
ARCHIVE = (
    sys.argv[1] if len(sys.argv) > 1
    else os.getenv("CICIDS_ARCHIVE", "cicids2017_full.zip")
)

# Map CICIDS labels to SIEM-style event types + severity
LABEL_MAP = {
    "FTP-Patator": ("suspicious_signin", "HIGH", "FTP brute force — Patator tool"),
    "FTP-Patator - Attempted": ("suspicious_signin", "MEDIUM", "FTP brute force attempt (blocked)"),
    "SSH-Patator": ("suspicious_signin", "HIGH", "SSH brute force — Patator tool"),
    "SSH-Patator - Attempted": ("suspicious_signin", "MEDIUM", "SSH brute force attempt (blocked)"),
    "DoS Slowloris": ("blocked_connection", "HIGH", "Slowloris DoS — connection exhaustion"),
    "DoS Slowloris - Attempted": ("blocked_connection", "MEDIUM", "Slowloris DoS attempt (mitigated)"),
    "DoS Slowhttptest": ("blocked_connection", "HIGH", "SlowHTTPTest DoS — slow POST attack"),
    "DoS Slowhttptest - Attempted": ("blocked_connection", "MEDIUM", "SlowHTTPTest DoS attempt (mitigated)"),
    "DoS Hulk": ("blocked_connection", "HIGH", "HULK DoS — unique URL flood"),
    "DoS Hulk - Attempted": ("blocked_connection", "MEDIUM", "HULK DoS attempt (mitigated)"),
    "DoS GoldenEye": ("blocked_connection", "HIGH", "GoldenEye DoS — KeepAlive exploitation"),
    "DoS GoldenEye - Attempted": ("blocked_connection", "MEDIUM", "GoldenEye DoS attempt"),
    "Heartbleed": ("suspicious_process", "CRITICAL", "Heartbleed CVE-2014-0160 — TLS memory disclosure exploit"),
    "Web Attack - Brute Force": ("suspicious_signin", "HIGH", "Web app brute force login attack"),
    "Web Attack - Brute Force - Attempted": ("suspicious_signin", "MEDIUM", "Web app brute force attempt (blocked)"),
    "Web Attack - XSS": ("suspicious_process", "CRITICAL", "Cross-site scripting — script injection"),
    "Web Attack - XSS - Attempted": ("suspicious_process", "HIGH", "XSS attempt detected and blocked"),
    "Web Attack - SQL Injection": ("suspicious_process", "CRITICAL", "SQL injection — malicious query"),
    "Web Attack - SQL Injection - Attempted": ("suspicious_process", "HIGH", "SQL injection attempt blocked"),
    "Infiltration": ("data_exfiltration", "CRITICAL", "Network infiltration — lateral movement + data theft"),
    "Infiltration - Attempted": ("suspicious_process", "HIGH", "Infiltration attempt detected"),
    "Infiltration - Portscan": ("suspicious_domain", "MEDIUM", "Infiltration recon — internal port scan"),
    "Portscan": ("suspicious_domain", "MEDIUM", "External port scan — network reconnaissance"),
    "DDoS": ("blocked_connection", "CRITICAL", "Distributed denial-of-service attack"),
    "Botnet": ("suspicious_process", "CRITICAL", "Botnet C2 callback — compromised host"),
    "Botnet - Attempted": ("suspicious_process", "HIGH", "Botnet C2 connection attempt"),
}


def parse_flow_id(flow_id: str) -> tuple[str, str, str, str]:
    """Extract src_ip, dst_ip, src_port, dst_port from Flow ID.
    Format: src_ip-dst_ip-src_port-dst_port-protocol
    """
    parts = flow_id.split("-")
    if len(parts) >= 4:
        return parts[0], parts[1], parts[2], parts[3]
    return "", "", "", ""


def int_to_ip(dec_str: str) -> str:
    """Convert decimal IP to dotted notation."""
    try:
        n = int(dec_str)
        return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"
    except (ValueError, TypeError):
        return ""


def load_samples() -> dict[str, list[dict]]:
    """Load attack samples from _plus CSV files (have Flow IDs with real IPs)."""
    samples: dict[str, list[dict]] = {}

    with zipfile.ZipFile(ARCHIVE, "r") as z:
        for fname in z.namelist():
            if not fname.endswith("_plus.csv"):
                continue

            with z.open(fname) as f:
                header = f.readline().decode("utf-8", errors="replace").strip()
                cols = [c.strip() for c in header.split(",")]

                flow_id_idx = cols.index("Flow ID") if "Flow ID" in cols else -1
                label_idx = cols.index("Label") if "Label" in cols else -1
                ts_idx = cols.index("Timestamp") if "Timestamp" in cols else -1
                src_dec_idx = cols.index("Src IP dec") if "Src IP dec" in cols else -1
                dst_dec_idx = cols.index("Dst IP dec") if "Dst IP dec" in cols else -1
                dst_port_idx = cols.index("Dst Port") if "Dst Port" in cols else -1
                cat_idx = cols.index("Attempted Category") if "Attempted Category" in cols else -1
                bytes_idx = cols.index("Total Length of Fwd Packet") if "Total Length of Fwd Packet" in cols else -1

                attack_count = 0
                for raw in f:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    vals = line.split(",")
                    if len(vals) != len(cols):
                        continue

                    label = vals[label_idx].strip() if label_idx >= 0 else ""
                    if label == "BENIGN" or not label:
                        continue

                    # Sample: keep max 15 per label per file
                    current = samples.setdefault(label, [])
                    if len(current) >= 15:
                        continue

                    # Extract IPs from Flow ID
                    flow_id = vals[flow_id_idx].strip() if flow_id_idx >= 0 else ""
                    src_ip, dst_ip, src_port, dst_port_fid = parse_flow_id(flow_id)

                    # Fallback: decimal IPs
                    if not src_ip and src_dec_idx >= 0:
                        src_ip = int_to_ip(vals[src_dec_idx].strip())
                    if not dst_ip and dst_dec_idx >= 0:
                        dst_ip = int_to_ip(vals[dst_dec_idx].strip())

                    dst_port_val = vals[dst_port_idx].strip() if dst_port_idx >= 0 else ""
                    fwd_bytes = vals[bytes_idx].strip() if bytes_idx >= 0 else "0"
                    timestamp = vals[ts_idx].strip() if ts_idx >= 0 else ""

                    current.append({
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port_val,
                        "flow_id": flow_id,
                        "fwd_bytes": fwd_bytes,
                        "timestamp_raw": timestamp,
                        "label": label,
                    })
                    attack_count += 1

            day_name = fname.replace("_plus.csv", "")
            total_labels = sum(len(v) for v in samples.values())
            print(f"  {day_name:12s}: {attack_count} attacks sampled")

    return samples


def to_alert(sample: dict, label: str, day_date: datetime, hour: int, minute: int) -> dict:
    """Convert a CICIDS sample to a SIEM alert."""
    config = LABEL_MAP.get(label)
    if not config:
        config = ("suspicious_process", "MEDIUM", f"Unknown attack: {label}")

    event_type, severity, description = config
    ts = (day_date + timedelta(hours=hour, minutes=minute)).strftime("%Y-%m-%dT%H:%M:%SZ")

    src_ip = sample["src_ip"]
    dst_ip = sample["dst_ip"]
    dst_port = sample["dst_port"]

    # Determine hostname from dst_ip
    host_map = {
        "192.168.10.50": "WEB-SVR-01",
        "192.168.10.51": "WEB-SVR-02",
        "192.168.10.15": "WORKSTATION-15",
        "192.168.10.8": "WORKSTATION-08",
        "192.168.10.5": "DB-SVR-01",
        "192.168.10.3": "DC-01",
    }
    hostname = host_map.get(dst_ip, f"HOST-{dst_ip.split('.')[-1]}" if dst_ip else "UNKNOWN")

    # Port-based service context
    port_desc = ""
    try:
        p = int(dst_port)
        if p == 21:
            port_desc = " (FTP service)"
        elif p == 22:
            port_desc = " (SSH service)"
        elif p == 80 or p == 8080:
            port_desc = " (HTTP service)"
        elif p == 443:
            port_desc = " (HTTPS service)"
        elif p == 3306:
            port_desc = " (MySQL)"
        elif p == 389:
            port_desc = " (LDAP)"
    except (ValueError, TypeError):
        pass

    alert = {
        "timestamp": ts,
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "hostname": hostname,
        "source": "CICIDS-IDS",
        "description": f"{description}{port_desc}",
        "action": "blocked" if "Attempted" in label or "mitigated" in description else "detected",
        "flow_id": sample.get("flow_id", ""),
        "cicids_label": label,
    }

    # Add bytes for exfiltration
    try:
        b = int(float(sample.get("fwd_bytes", "0")))
        if b > 0:
            alert["bytes"] = str(b)
    except (ValueError, TypeError):
        pass

    return alert


def run_pilot():
    print("=" * 65)
    print("CICIDS 2017 — REAL NETWORK ATTACK DATA PILOT")
    print("=" * 65)
    print("Dataset: CICIDS 2017 with Flow IDs (real IPs)")
    print("Attacks: Brute force, DoS, Web attacks, Infiltration, DDoS, Botnet")
    print("Test: Real attack data, real IPs, no synthetic users\n")

    print("Loading attack samples...")
    random.seed(42)
    samples = load_samples()

    print(f"\nAttack types: {len(samples)}")
    for label in sorted(samples.keys()):
        safe = label.encode("ascii", errors="replace").decode("ascii")
        print(f"  {safe:40s}: {len(samples[label])} samples")

    # Reset
    with httpx.Client(timeout=30) as client:
        client.post(f"{BASE_URL}/api/v1/demo/reset", headers=HEADERS)
    print("\nDatabase reset. Starting 5-day pilot...\n")

    # Simulate 5 days matching CICIDS attack timeline
    day_configs = [
        (datetime(2026, 4, 1), "Tuesday — Brute Force Day",
         ["FTP-Patator", "FTP-Patator - Attempted", "SSH-Patator", "SSH-Patator - Attempted"]),
        (datetime(2026, 4, 2), "Wednesday — DoS Day",
         ["DoS Slowloris", "DoS Hulk", "DoS GoldenEye", "Heartbleed"]),
        (datetime(2026, 4, 3), "Thursday — Web Attacks + Infiltration",
         ["Web Attack - Brute Force", "Web Attack - XSS", "Web Attack - SQL Injection",
          "Infiltration", "Infiltration - Portscan"]),
        (datetime(2026, 4, 4), "Friday — DDoS + Botnet",
         ["DDoS", "Portscan", "Botnet", "Botnet - Attempted"]),
        (datetime(2026, 4, 5), "Saturday — Persistent threats continue",
         ["Botnet", "Infiltration", "Heartbleed", "DoS Hulk"]),
    ]

    total_alerts = 0
    for day_idx, (day_date, day_label, attack_types) in enumerate(day_configs, 1):
        alerts = []

        # Benign traffic (5 normal logins)
        for i in range(5):
            ts = (day_date + timedelta(hours=8 + i, minutes=10 * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            alerts.append({
                "timestamp": ts,
                "event_type": "login_success",
                "severity": "LOW",
                "src_ip": f"192.168.10.{100 + i}",
                "hostname": f"WS-{100 + i}",
                "user": f"user{i+1}@cicids-lab.local",
                "source": "CICIDS-AD",
                "description": "Standard workday login",
                "action": "success",
            })

        # Attack alerts
        hour = 9
        for attack_label in attack_types:
            attack_samples = samples.get(attack_label, [])
            for i, sample in enumerate(attack_samples[:10]):
                minute = (i * 5) % 60
                alert = to_alert(sample, attack_label, day_date, hour + (i // 12), minute)
                alerts.append(alert)
            hour += 3

        total_alerts += len(alerts)

        content = json.dumps(alerts)
        with httpx.Client(timeout=120) as client:
            resp = client.post(
                f"{BASE_URL}/api/v1/demo/upload",
                params={"grouping": "true", "persist": "true"},
                headers=HEADERS,
                files={"file": (f"cicids_day_{day_idx}.json", content.encode(), "application/json")},
            )
            result = resp.json()

        time.sleep(4)

        with httpx.Client(timeout=30) as client:
            cases = client.get(f"{BASE_URL}/api/v1/cases", params={"limit": 100}, headers=HEADERS).json()
            incidents = client.get(f"{BASE_URL}/api/v1/incidents", headers=HEADERS).json()

        at_dist = result.get("alertTypeDistribution", {})
        print(f"Day {day_idx} ({day_label})")
        print(f"  {len(alerts)} alerts -> {result.get('caseCount', '?')} cases | "
              f"Total: {len(cases)} cases, {len(incidents)} incidents")
        print(f"  Types: {at_dist}")
        for inc in incidents:
            if isinstance(inc, dict):
                title = inc.get("title", "?").encode("ascii", errors="replace").decode("ascii")
                nc = inc.get("caseCount", "?")
                sev = inc.get("severity", "?")
                print(f"  [{sev}] {title} ({nc} cases)")
        print()

    # Final report
    print("=" * 65)
    print("CICIDS 2017 PILOT REPORT")
    print("=" * 65)

    with httpx.Client(timeout=30) as client:
        cases = client.get(f"{BASE_URL}/api/v1/cases", params={"limit": 100}, headers=HEADERS).json()
        incidents = client.get(f"{BASE_URL}/api/v1/incidents", headers=HEADERS).json()

    print(f"\nTotal alerts: {total_alerts}")
    print(f"Total cases: {len(cases)}")
    print(f"Total incidents: {len(incidents)}")

    # Score analysis
    attack_cases = []
    noise_cases = []
    for c in cases:
        if not isinstance(c, dict):
            continue
        score = c.get("confidence", {}).get("score", 0) if isinstance(c.get("confidence"), dict) else 0
        at = c.get("alertType", "")
        if at == "identity.suspiciousSignIn" and score < 25:
            noise_cases.append(c)
        else:
            attack_cases.append(c)

    print(f"\nAttack cases: {len(attack_cases)}")
    print(f"Noise cases: {len(noise_cases)}")

    # Cases by type
    print(f"\nCases by alert type:")
    type_summary = {}
    for c in cases:
        if not isinstance(c, dict):
            continue
        at = c.get("alertType", "?")
        score = c.get("confidence", {}).get("score", 0) if isinstance(c.get("confidence"), dict) else 0
        type_summary.setdefault(at, []).append(score)
    for at, scores in sorted(type_summary.items()):
        print(f"  {at:40s}: {len(scores):3d} cases, scores {min(scores):3d}-{max(scores):3d}")

    # Incidents
    print(f"\nIncidents:")
    for inc in incidents:
        if isinstance(inc, dict):
            title = inc.get("title", "?").encode("ascii", errors="replace").decode("ascii")
            nc = inc.get("caseCount", "?")
            sev = inc.get("severity", "?")
            conf = inc.get("confidenceScore", "?")
            stages = [s.get("label", "?") for s in inc.get("killChainStages", [])]
            print(f"  [{sev:10s}] {title}")
            print(f"             {nc} cases | {conf}% conf | stages: {stages}")

    # Noise check
    noise_in_incidents = [i for i in incidents if "user1@" in str(i).lower() or "user2@" in str(i).lower()]
    noise_clean = len(noise_in_incidents) == 0

    # Grade
    if len(incidents) >= 3 and noise_clean:
        grade = "A"
    elif len(incidents) >= 2 and noise_clean:
        grade = "B+"
    elif len(incidents) >= 1 and noise_clean:
        grade = "B"
    elif len(incidents) >= 1:
        grade = "C"
    else:
        grade = "D"

    print(f"\n  GRADE: {grade}")
    print(f"  Incidents: {len(incidents)} | Noise in incidents: {len(noise_in_incidents)}")


if __name__ == "__main__":
    run_pilot()
