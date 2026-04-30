"""Tiny UDM -> Vigilis-flat-CSV mapper.

The HF SIEM dataset uses Google Chronicle UDM-style nested JSON. Vigilis's
upload auto-mapper expects flat columns (timestamp, user, src_ip, ...).
This is the kind of 30-line adapter a real customer writes once.

Run: python test_data/public_datasets/map_udm_to_csv.py
Out: test_data/public_datasets/hf_siem_mapped.csv
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

SRC = Path(__file__).parent / "hf_siem_200_curated.json"
DST = Path(__file__).parent / "hf_siem_mapped.csv"

EVENT_TYPE_TO_ALERT = {
    "login_success": "identity.suspiciousSignIn",
    "login_failure": "identity.suspiciousSignIn",
    "logout": "identity.suspiciousSignIn",
    "password_change": "identity.privilegeElevation",
    "process_creation": "endpoint.suspiciousProcess",
    "file_create": "endpoint.suspiciousProcess",
    "network_connection": "network.dataExfiltration",
    "dns_query": "network.dnsAnomaly",
}

COLUMNS = [
    "timestamp", "event_type", "user", "src_ip", "hostname",
    "action", "severity", "alert_name", "country", "alertType",
]


def map_record(rec: dict) -> dict:
    md = rec.get("metadata", {}) or {}
    pr = rec.get("principal", {}) or {}
    sr = rec.get("security_result", {}) or {}
    ad = rec.get("additional", {}) or {}
    tg = rec.get("target", {}) or {}

    user_obj = pr.get("user", {}) if isinstance(pr.get("user"), dict) else {}
    event_type = (md.get("event_type") or "").strip()

    return {
        "timestamp": md.get("event_timestamp", ""),
        "event_type": event_type,
        "user": user_obj.get("userid", "") or "",
        "src_ip": pr.get("ip", "") or "",
        "hostname": tg.get("hostname", "") or "",
        "action": ad.get("action", "") or "",
        "severity": (sr.get("severity") or "medium").lower(),
        "alert_name": (ad.get("description") or event_type or "").strip()[:200],
        "country": ad.get("geo", "") or "",
        "alertType": EVENT_TYPE_TO_ALERT.get(event_type, "identity.suspiciousSignIn"),
    }


def main() -> None:
    src_records = json.loads(SRC.read_text(encoding="utf-8"))
    with DST.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for rec in src_records:
            w.writerow(map_record(rec))
    print(f"mapped {len(src_records)} records -> {DST}")


if __name__ == "__main__":
    main()
