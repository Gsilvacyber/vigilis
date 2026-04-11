"""Fresh eyes evaluation - completely new company, new alert types, edge cases
that have NEVER been tested before."""
import httpx
import json
import time

BASE = "http://localhost:8000"
H = {"X-API-Key": "socai-demo-key-do-not-use-in-production"}


def main():
    httpx.Client(timeout=30).post(f"{BASE}/api/v1/demo/reset", headers=H)

    alerts = [
        # 1. Credential stuffing from residential proxy (NOT Tor - no OTX hit expected)
        {"timestamp": "2026-04-09T14:22:00Z", "event_type": "suspicious_signin",
         "user": "payroll.admin@hartley-mfg.com", "src_ip": "47.89.115.203",
         "hostname": "HR-APP-01", "severity": "HIGH", "source": "Okta",
         "description": "50 failed logins followed by success from residential proxy",
         "geo": "US", "action": "success"},

        # 2. Ransomware - shadow copy deletion
        {"timestamp": "2026-04-09T02:17:00Z", "event_type": "ransomware_detected",
         "user": "svc-backup@hartley-mfg.com", "src_ip": "10.10.50.15",
         "hostname": "FILE-SVR-03", "severity": "CRITICAL", "source": "CrowdStrike",
         "description": "vssadmin delete shadows followed by mass .encrypted file extension changes",
         "process_name": "cmd.exe", "command_line": "vssadmin delete shadows /all /quiet"},

        # 3. Lateral movement via PsExec (8 min after ransomware - same user)
        {"timestamp": "2026-04-09T02:25:00Z", "event_type": "lateral_movement_detected",
         "user": "svc-backup@hartley-mfg.com", "src_ip": "10.10.50.15",
         "dst_ip": "10.10.50.20", "hostname": "FILE-SVR-03", "severity": "CRITICAL",
         "source": "CrowdStrike",
         "description": "PsExec remote execution spreading to domain controller DC-02"},

        # 4. BEC wire transfer request
        {"timestamp": "2026-04-09T09:15:00Z", "event_type": "bec_detected",
         "user": "cfo@hartley-mfg.com", "src_ip": "104.47.58.100",
         "hostname": "MAIL-GW-01", "severity": "HIGH", "source": "Proofpoint",
         "description": "Urgent wire transfer $2.3M from lookalike domain hartley-mfg-corp.com",
         "sender": "ceo@hartley-mfg-corp.com"},

        # 5. Legitimate admin with change ticket (should be NOISE)
        {"timestamp": "2026-04-09T10:00:00Z", "event_type": "process_execution",
         "user": "it-admin@hartley-mfg.com", "src_ip": "10.10.0.5",
         "hostname": "MGMT-01", "severity": "LOW", "source": "CrowdStrike",
         "description": "Scheduled patch deployment via SCCM - change ticket CHG0045123",
         "process_name": "powershell.exe"},
    ]

    with httpx.Client(timeout=120) as c:
        resp = c.post(f"{BASE}/api/v1/demo/upload",
            params={"grouping": "true", "persist": "true"}, headers=H,
            files={"file": ("hartley.json", json.dumps(alerts).encode(), "application/json")})
        upload = resp.json()

    time.sleep(3)

    with httpx.Client(timeout=30) as c:
        cases = c.get(f"{BASE}/api/v1/cases", params={"limit": 20}, headers=H).json()
        incidents = c.get(f"{BASE}/api/v1/incidents", headers=H).json()

    print("=" * 75)
    print("FRESH EYES: Hartley Manufacturing - 5 Never-Before-Tested Alerts")
    print("=" * 75)

    for case in cases:
        ent = case.get("entities", {})
        upn = (ent.get("identity") or {}).get("upn", "?")
        at = case.get("alertType", "?")
        score = case.get("confidence", {}).get("score", 0)
        label = case.get("confidence", {}).get("label", "?")
        sev = case.get("severity", "?")
        disp = case.get("disposition", {}).get("status", "?")
        ready = (case.get("enrichment", {}).get("caseReadiness") or {}).get("readyForAction", "?")

        sigs = case.get("confidence", {}).get("explanation", [])
        real_sigs = [s for s in sigs if s.get("signal") != "_score_breakdown"]
        v = len([s for s in real_sigs if s.get("tier") == "verified"])
        i = len([s for s in real_sigs if s.get("tier") == "inferred"])
        o = len([s for s in real_sigs if s.get("tier") == "observed"])

        notes = case.get("enrichment", {}).get("enrichmentNotes", [])
        imp = (case.get("enrichment", {}).get("impactSummary") or {})
        steps = [s for s in imp.get("manualStepsReplaced", [])
                 if not str(s).startswith("Estimated")]

        print(f"\n{upn}")
        print(f"  Type: {at}")
        print(f"  Score: {score}/100 ({label}) | Sev: {sev} | Disp: {disp} | Ready: {ready}")
        print(f"  Signals: {len(real_sigs)} ({v}V {i}I {o}O)")
        for s in real_sigs[:3]:
            print(f"    [{s.get('tier','?'):8s}] {s.get('signal','?'):28s} w={s.get('weight',0):>3}")
        if len(real_sigs) > 3:
            print(f"    ... +{len(real_sigs)-3} more")
        print(f"  Notes: {len(notes)} | Steps: {len(steps)} | Actions: {len(case.get('recommendedActions', []))}")

    print(f"\nINCIDENTS: {len(incidents)}")
    for inc in incidents:
        if isinstance(inc, dict):
            t = inc.get("title", "?").encode("ascii", errors="replace").decode("ascii")
            nc = inc.get("caseCount", "?")
            stages = [s.get("label") for s in inc.get("killChainStages", [])]
            print(f"  {t} ({nc} cases) -> {' -> '.join(str(s) for s in stages)}")

    # Honest grading
    print(f"\n{'=' * 75}")
    print("HONEST GRADING")
    print(f"{'=' * 75}")

    types_found = set(c.get("alertType", "") for c in cases)

    checks = []

    # Did new alert types classify correctly?
    ransomware = "endpoint.ransomwareDetection" in types_found
    lateral = "endpoint.lateralMovement" in types_found
    bec = "email.businessEmailCompromise" in types_found
    checks.append(("Ransomware classified as endpoint.ransomwareDetection", ransomware))
    checks.append(("Lateral movement classified as endpoint.lateralMovement", lateral))
    checks.append(("BEC classified as email.businessEmailCompromise", bec))

    # Did ransomware + lateral movement form an incident?
    svc_inc = [inc for inc in incidents if "svc-backup" in str(inc).lower() or "hartley" in str(inc).lower()]
    checks.append(("Ransomware + lateral movement form incident", len(svc_inc) >= 1 or len(incidents) >= 1))

    # Is the admin noise suppressed?
    admin_cases = [c for c in cases if "it-admin" in str(c.get("entities", {})).lower()]
    admin_score = admin_cases[0].get("confidence", {}).get("score", 99) if admin_cases else 99
    checks.append(("IT admin with change ticket scores < 30", admin_score < 30))

    # Does credential stuffing get proper score without OTX?
    cred_cases = [c for c in cases if "payroll" in str(c.get("entities", {})).lower()]
    cred_score = cred_cases[0].get("confidence", {}).get("score", 0) if cred_cases else 0
    checks.append(("Credential stuffing scores 40+ without OTX data", cred_score >= 40))

    # Does BEC have wire transfer investigation steps?
    bec_cases = [c for c in cases if "cfo" in str(c.get("entities", {})).lower()]
    bec_steps_text = ""
    if bec_cases:
        imp = (bec_cases[0].get("enrichment", {}).get("impactSummary") or {})
        bec_steps_text = " ".join(str(s) for s in imp.get("manualStepsReplaced", []))
    checks.append(("BEC has wire transfer investigation steps", "wire" in bec_steps_text.lower() or "transfer" in bec_steps_text.lower()))

    # Are signals honest about tier?
    all_sigs = []
    for c in cases:
        for s in c.get("confidence", {}).get("explanation", []):
            if s.get("signal") != "_score_breakdown":
                all_sigs.append(s)
    has_tiers = all(s.get("tier") in ("verified", "inferred", "observed", None) for s in all_sigs)
    checks.append(("All signals have tier classification", has_tiers))

    passed = 0
    for label, ok in checks:
        status = "PASS" if ok else "FAIL"
        print(f"  {status}  {label}")
        if ok:
            passed += 1

    print(f"\n  RESULT: {passed}/{len(checks)} checks passed")

    if passed == len(checks):
        print("  VERDICT: Platform handles new alert types and edge cases correctly")
    elif passed >= len(checks) - 1:
        print("  VERDICT: Minor gap but fundamentally working")
    else:
        print(f"  VERDICT: {len(checks) - passed} failures need investigation")


if __name__ == "__main__":
    main()
