"""Comprehensive QA Audit - tests every component systematically."""
import sys
sys.path.insert(0, __import__("os").path.join(__import__("os").path.dirname(__file__), "..", ".."))
import httpx
import json
import subprocess
import time

BASE = "http://localhost:8000"
H = {"X-API-Key": "socai-demo-key-do-not-use-in-production"}
import os
PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".venv", "Scripts", "python.exe")
if not os.path.exists(PY):
    PY = sys.executable  # fallback

results = []


def check(name, passed):
    results.append((name, passed))
    print(f"  {'PASS' if passed else 'FAIL'}  {name}")


def main():
    print("=" * 75)
    print("QA AUDIT - VIGILIS/SOCAI PLATFORM")
    print("=" * 75)

    # TEST 1: Unit tests
    print("\n[1] UNIT TESTS")
    r = subprocess.run([PY, "-m", "pytest", "backend/tests/", "-q", "--tb=no"],
                       capture_output=True, text=True, timeout=300)
    lines = [l for l in r.stdout.strip().split("\n") if l.strip()]
    last = lines[-1] if lines else "ERROR"
    print(f"  {last}")
    check("Unit tests all passing", "passed" in last and "failed" not in last)

    # TEST 2: Health + providers
    print("\n[2] HEALTH ENDPOINT")
    with httpx.Client(timeout=10) as c:
        health = c.get(f"{BASE}/health").json()
    print(f"  Status: {health.get('status')}")
    for name, info in health.get("providers", {}).items():
        print(f"  Provider {name}: {info.get('status')}")
    check("Health endpoint operational", health.get("status") in ("ok", "degraded"))

    # TEST 3: Prometheus
    print("\n[3] PROMETHEUS METRICS")
    with httpx.Client(timeout=10) as c:
        metrics = c.get(f"{BASE}/metrics").text
    vc = len([l for l in metrics.split("\n") if l.startswith("vigilis_")])
    print(f"  Vigilis metric lines: {vc}")
    check("Prometheus metrics serving", vc > 0)

    # TEST 4: 30 alert types
    print("\n[4] ALERT TYPE COVERAGE")
    r2 = subprocess.run([PY, "-c",
        "from backend.app.services.case_service import SUPPORTED_ALERT_TYPES;"
        "from backend.app.services.enrichment import _EXTRACTORS;"
        "from backend.app.services.enrichment.actions import _ACTION_GENERATORS;"
        "from backend.app.services.enrichment.playbooks import _PLAYBOOKS;"
        "from backend.app.services.normalizer import _MANUAL_STEPS, _RISK_DETAILS;"
        "from backend.app.services.correlation.kill_chain import _ALERT_TYPE_TO_STAGE;"
        "g=[t for t in SUPPORTED_ALERT_TYPES if t not in _EXTRACTORS or t not in _ACTION_GENERATORS or t not in _PLAYBOOKS or t not in _MANUAL_STEPS or t not in _RISK_DETAILS or t not in _ALERT_TYPE_TO_STAGE];"
        "print(len(SUPPORTED_ALERT_TYPES), len(_EXTRACTORS), len(g));"
        "print('GAPS:',g if g else 'NONE')"
    ], capture_output=True, text=True, timeout=30)
    for line in r2.stdout.strip().split("\n"):
        print(f"  {line}")
    check("30 alert types fully covered", "NONE" in r2.stdout)

    # TEST 5: Enrichment pipeline
    print("\n[5] ENRICHMENT PIPELINE (3 alerts)")
    httpx.Client(timeout=30).post(f"{BASE}/api/v1/demo/reset", headers=H)

    alerts = [
        {"timestamp": "2026-04-09T03:00:00Z", "event_type": "suspicious_signin",
         "user": "test@qa.com", "src_ip": "185.220.101.35", "hostname": "SRV-01",
         "severity": "HIGH", "source": "QA", "description": "Tor login", "geo": "DE"},
        {"timestamp": "2026-04-09T22:30:00Z", "event_type": "data_exfiltration",
         "user": "insider@qa.com", "src_ip": "10.200.1.5", "dst_ip": "162.125.1.1",
         "hostname": "LAB-01", "severity": "CRITICAL", "source": "QA",
         "description": "200MB upload to personal Dropbox after hours", "bytes": "209715200"},
        {"timestamp": "2026-04-09T08:00:00Z", "event_type": "login_success",
         "user": "normal@qa.com", "src_ip": "10.10.1.1", "hostname": "WS-01",
         "severity": "LOW", "source": "QA", "description": "Morning login"},
    ]
    with httpx.Client(timeout=120) as c:
        c.post(f"{BASE}/api/v1/demo/upload", params={"grouping": "true", "persist": "true"},
               headers=H, files={"file": ("qa.json", json.dumps(alerts).encode(), "application/json")})
    time.sleep(2)
    with httpx.Client(timeout=30) as c:
        cases = c.get(f"{BASE}/api/v1/cases", params={"limit": 10}, headers=H).json()

    tor = [c for c in cases if "test@" in str(c.get("entities", {}))]
    ins = [c for c in cases if "insider@" in str(c.get("entities", {}))]
    noi = [c for c in cases if "normal@" in str(c.get("entities", {}))]

    tor_score = tor[0].get("confidence", {}).get("score", 0) if tor else 0
    ins_score = ins[0].get("confidence", {}).get("score", 0) if ins else 0
    ins_disp = ins[0].get("disposition", {}).get("status", "?") if ins else "?"
    noi_score = noi[0].get("confidence", {}).get("score", 0) if noi else 99

    ins_sigs = [s.get("signal") for s in ins[0].get("confidence", {}).get("explanation", [])
                if s.get("signal") != "_score_breakdown"] if ins else []

    print(f"  Tor case: score={tor_score}")
    print(f"  Insider case: score={ins_score}, disp={ins_disp}, signals={ins_sigs}")
    print(f"  Noise case: score={noi_score}")

    check("External attack scores 50+", tor_score >= 50)
    check("Insider NOT auto-closed", ins_disp != "benign")
    check("Insider has data_exfiltration signal", "data_exfiltration" in ins_sigs)
    check("Insider has after_hours signal", "after_hours" in ins_sigs)
    check("Noise scores < 15", noi_score < 15)

    # TEST 6: Signal tiers
    print("\n[6] SIGNAL TIER SYSTEM")
    all_sigs = []
    for c in cases:
        for s in c.get("confidence", {}).get("explanation", []):
            if s.get("signal") != "_score_breakdown":
                all_sigs.append(s)
    tiered = sum(1 for s in all_sigs if s.get("tier") in ("verified", "inferred", "observed"))
    bd = any(s.get("signal") == "_score_breakdown" for c in cases
             for s in c.get("confidence", {}).get("explanation", []))
    print(f"  Signals with tier: {tiered}/{len(all_sigs)}")
    print(f"  Score breakdown present: {bd}")
    check("Signal tiers on all signals", tiered == len(all_sigs))
    check("Score breakdown in explanation", bd)

    # TEST 7: Investigation steps
    print("\n[7] INVESTIGATION STEPS")
    for c in cases:
        upn = (c.get("entities", {}).get("identity") or {}).get("upn", "?")
        imp = (c.get("enrichment", {}).get("impactSummary") or {})
        steps = [s for s in imp.get("manualStepsReplaced", []) if not str(s).startswith("Estimated")]
        has_q = any("index=" in str(s) for s in steps)
        has_entity = any("@" in str(s) and "qa.com" in str(s) for s in steps)
        print(f"  {upn}: {len(steps)} steps, SIEM_query={has_q}, entity_filled={has_entity}")
    check("All cases have investigation steps", all(
        len([s for s in (c.get("enrichment", {}).get("impactSummary") or {}).get("manualStepsReplaced", [])
             if not str(s).startswith("Estimated")]) >= 2 for c in cases))

    # TEST 8: SIEM query uses correct destination IP
    print("\n[8] SIEM QUERY IP ACCURACY")
    if ins:
        imp = (ins[0].get("enrichment", {}).get("impactSummary") or {})
        steps_text = " ".join(str(s) for s in imp.get("manualStepsReplaced", []))
        has_dst = "162.125" in steps_text
        print(f"  Insider SIEM query has dest IP 162.125.x: {has_dst}")
        check("SIEM query uses destination IP for exfiltration", has_dst)
    else:
        check("SIEM query uses destination IP for exfiltration", False)

    # TEST 9: Meridian pilot
    print("\n[9] MERIDIAN CAPITAL 10-DAY PILOT")
    httpx.Client(timeout=30).post(f"{BASE}/api/v1/demo/reset", headers=H)
    from test_data.client_simulation.run_10day_pilot import generate_day
    for day in range(1, 11):
        a = generate_day(day)
        with httpx.Client(timeout=120) as c:
            c.post(f"{BASE}/api/v1/demo/upload", params={"grouping": "true", "persist": "true"},
                   headers=H, files={"file": (f"d{day}.json", json.dumps(a).encode(), "application/json")})
        time.sleep(3)
    with httpx.Client(timeout=30) as c:
        mc = c.get(f"{BASE}/api/v1/cases", params={"limit": 100}, headers=H).json()
        mi = c.get(f"{BASE}/api/v1/incidents", headers=H).json()
    parker = len([i for i in mi if isinstance(i, dict) and "parker" in str(i).lower()])
    payment = len([i for i in mi if isinstance(i, dict) and "pay" in str(i).lower()])
    phishing = len([i for i in mi if isinstance(i, dict) and ("wong" in str(i).lower() or "phish" in str(i).lower())])
    print(f"  Cases: {len(mc)} | Incidents: {len(mi)} | parker={parker} payment={payment} phishing={phishing}")
    check("Meridian: all 3 attack threads detected", parker >= 1 and payment >= 1 and phishing >= 1)
    nk = ["k.johnson", "l.davis", "p.garcia", "svc-nagios", "it-admin"]
    check("Meridian: zero noise in incidents", not any(any(n in str(i).lower() for n in nk) for i in mi))

    # TEST 10: Security
    print("\n[10] SECURITY HARDENING")
    r3 = subprocess.run([PY, "-c",
        "import os; os.environ['APP_ENV']='prod'\n"
        "try:\n"
        "    from backend.app.core.config import settings\n"
        "    print('FAIL')\n"
        "except RuntimeError:\n"
        "    print('PASS')"
    ], capture_output=True, text=True, timeout=10)
    demo_blocked = "PASS" in r3.stdout
    print(f"  Demo key blocks prod startup: {demo_blocked}")
    check("Demo key fails startup in prod", demo_blocked)

    # SCORECARD
    print(f"\n{'=' * 75}")
    print("QA AUDIT SCORECARD")
    print(f"{'=' * 75}")
    total_pass = sum(1 for _, p in results if p)
    total = len(results)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL':4s}  {name}")
    pct = total_pass / total * 100
    print(f"\n  TOTAL: {total_pass}/{total} ({pct:.0f}%)")
    if pct >= 90: grade = "A"
    elif pct >= 80: grade = "B+"
    elif pct >= 70: grade = "B"
    elif pct >= 60: grade = "C"
    else: grade = "D"
    print(f"  GRADE: {grade}")


if __name__ == "__main__":
    main()
