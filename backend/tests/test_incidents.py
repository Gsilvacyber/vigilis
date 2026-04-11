"""Tests for the incident correlation engine."""
from __future__ import annotations

import pytest


def test_simulate_pilot_creates_incidents(test_client):
    """simulate-pilot should auto-correlate incidents from the demo fixtures."""
    test_client.post("/api/v1/demo/reset")
    resp = test_client.post("/api/v1/demo/simulate-pilot")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incidentsCorrelated"] >= 2, (
        f"Expected at least 2 incidents (alice chain + cfo chain), got {data['incidentsCorrelated']}"
    )


def test_list_incidents_after_pilot(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    resp = test_client.get("/api/v1/incidents")
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) >= 2

    for inc in incidents:
        assert "id" in inc
        assert "title" in inc
        assert "severity" in inc
        assert "confidenceScore" in inc
        assert "confidenceLabel" in inc
        assert "killChainStages" in inc
        assert "killChainGaps" in inc
        assert "linkageReasons" in inc
        assert "entities" in inc
        assert "caseCount" in inc
        assert inc["caseCount"] >= 2


def test_incident_detail_has_timeline(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    assert len(incidents) >= 1

    inc_id = incidents[0]["id"]
    resp = test_client.get(f"/api/v1/incidents/{inc_id}")
    assert resp.status_code == 200

    detail = resp.json()
    assert "timeline" in detail
    assert "narrative" in detail
    assert len(detail["timeline"]) >= 2

    for event in detail["timeline"]:
        assert "caseId" in event
        assert "alertType" in event
        assert "killChainStage" in event
        assert "killChainLabel" in event
        assert "eventTime" in event


def test_incident_detail_not_found(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    resp = test_client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


def test_alice_chain_has_four_stages(test_client):
    """Alice should have: initial_access -> privilege_escalation -> execution -> exfiltration."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    alice_incidents = [
        inc for inc in incidents
        if "alice" in str(inc.get("entities", {}).get("users", []))
    ]
    assert len(alice_incidents) >= 1, "Expected at least one incident involving alice"
    alice = alice_incidents[0]

    stages = [s["stage"] for s in alice["killChainStages"]]
    assert "initial_access" in stages
    assert "privilege_escalation" in stages
    assert "execution" in stages
    assert "exfiltration" in stages
    assert alice["caseCount"] == 4


def test_cfo_chain_has_multi_stages(test_client):
    """CFO incident should have at least 2 kill-chain stages.

    The CFO demo cases (passwordSpray, forwardingRule, impossibleGeo) share
    user + IP, so they should cluster.  The exact stage count depends on
    whether the forwardingRule case passes the correlation threshold — its
    score varies with tier multipliers and enrichment context.
    """
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    cfo_incidents = [
        inc for inc in incidents
        if "cfo" in str(inc.get("entities", {}).get("users", []))
    ]
    assert len(cfo_incidents) >= 1, "Expected at least one incident involving cfo"
    cfo = cfo_incidents[0]

    stages = [s["stage"] for s in cfo["killChainStages"]]
    assert len(stages) >= 2, f"Expected 2+ kill-chain stages, got {stages}"
    assert "credential_access" in stages
    assert "lateral_movement" in stages


def test_correlate_endpoint(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    resp = test_client.post("/api/v1/incidents/correlate")
    assert resp.status_code == 200
    data = resp.json()
    assert "incidentsFound" in data
    assert "incidents" in data


def test_incident_narrative_contains_chain(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    assert len(incidents) >= 1

    detail = test_client.get(f"/api/v1/incidents/{incidents[0]['id']}").json()
    narrative = detail["narrative"]

    assert "Kill chain progression" in narrative
    assert "\u2192" in narrative
    assert "Timeline:" in narrative


def test_incident_severity_boosted_for_multi_stage(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    alice_incidents = [
        inc for inc in incidents
        if "alice" in str(inc.get("entities", {}).get("users", []))
    ]
    assert len(alice_incidents) >= 1
    assert alice_incidents[0]["severity"] in ("high", "critical")


# ── Confidence scoring ───────────────────────────────────────────────────

def test_incident_confidence_score_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    for inc in incidents:
        assert 0 < inc["confidenceScore"] <= 100
        assert inc["confidenceLabel"] in ("low", "medium", "high", "critical")


def test_alice_chain_high_confidence(test_client):
    """4-stage chain with consistent user entity should score high."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1
    assert alice[0]["confidenceScore"] >= 65, (
        f"Alice chain (4 stages, same user) should be high confidence, got {alice[0]['confidenceScore']}"
    )


# ── Linkage reasons ──────────────────────────────────────────────────────

def test_linkage_reasons_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    for inc in incidents:
        reasons = inc["linkageReasons"]
        assert len(reasons) >= 1, f"Incident {inc['title']} should have linkage reasons"
        for r in reasons:
            assert "type" in r
            assert "detail" in r
            assert "weight" in r
            assert r["type"] in ("shared_user", "shared_ip", "time_proximity", "kill_chain_progression")


def test_linkage_reasons_include_user(test_client):
    """Alice chain should have a shared_user linkage reason."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1

    reason_types = [r["type"] for r in alice[0]["linkageReasons"]]
    assert "shared_user" in reason_types
    assert "kill_chain_progression" in reason_types


# ── Kill chain gaps ──────────────────────────────────────────────────────

def test_kill_chain_gaps_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    for inc in incidents:
        gaps = inc["killChainGaps"]
        assert len(gaps) >= 2, f"Should have at least 2 gap entries (present stages)"
        for g in gaps:
            assert "stage" in g
            assert "label" in g
            assert "status" in g
            assert g["status"] in ("present", "missing")


def test_alice_chain_shows_gaps(test_client):
    """Alice: initial_access -> priv_esc -> execution -> exfiltration.
    Should flag credential_access and collection as missing."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1

    gaps = alice[0]["killChainGaps"]
    missing = [g["stage"] for g in gaps if g["status"] == "missing"]
    present = [g["stage"] for g in gaps if g["status"] == "present"]

    assert "initial_access" in present
    assert "exfiltration" in present
    assert len(missing) >= 1, "Alice chain should have at least one missing stage"


# ── Title generation ─────────────────────────────────────────────────────

def test_incident_title_descriptive(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    for inc in incidents:
        title = inc["title"]
        assert len(title) > 10
        assert "Attack chain:" not in title, "Should use descriptive title, not generic"


def test_alice_title_mentions_user(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1
    assert "alice" in alice[0]["title"].lower()


# ── Narrative includes new sections ──────────────────────────────────────

def test_narrative_includes_linkage_evidence(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    detail = test_client.get(f"/api/v1/incidents/{incidents[0]['id']}").json()
    assert "Correlation evidence" in detail["narrative"]


def test_narrative_includes_gaps(test_client):
    """At least one incident should mention open gaps in narrative."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    has_gaps = False
    for inc in incidents:
        detail = test_client.get(f"/api/v1/incidents/{inc['id']}").json()
        if "Open investigation gaps" in detail["narrative"]:
            has_gaps = True
            break
    assert has_gaps, "At least one incident should have open investigation gaps"


# ── Over-correlation guardrails ──────────────────────────────────────────

def test_standalone_cases_not_correlated(test_client):
    """Cases with unique users (dan, erin, frank) should NOT be merged into incidents."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    all_incident_users = set()
    for inc in incidents:
        for u in inc.get("entities", {}).get("users", []):
            all_incident_users.add(u)

    assert "dan@contoso.com" not in all_incident_users, "Dan should remain standalone"
    assert "erin@contoso.com" not in all_incident_users, "Erin should remain standalone"


# ── Confidence breakdown ─────────────────────────────────────────────────

def test_confidence_breakdown_present(test_client):
    """Every incident should have a confidenceBreakdown with all 6 factors."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    expected_factors = {"Base", "Stage count", "Case count",
                        "Entity consistency", "Time proximity",
                        "Chain coherence", "Mean case confidence"}

    for inc in incidents:
        bd = inc["confidenceBreakdown"]
        assert len(bd) == 7, f"Expected 7 factors, got {len(bd)}"
        factors = {f["factor"] for f in bd}
        assert factors == expected_factors, f"Missing factors: {expected_factors - factors}"

        total = sum(f["points"] for f in bd)
        assert total == inc["confidenceScore"], (
            f"Breakdown sum {total} != score {inc['confidenceScore']}"
        )

        for f in bd:
            assert "points" in f
            assert "maxPoints" in f
            assert "detail" in f
            assert f["points"] <= f["maxPoints"]


def test_breakdown_alice_entity_consistency(test_client):
    """Alice chain (all same user) should score +15 on entity consistency."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1

    bd = {f["factor"]: f for f in alice[0]["confidenceBreakdown"]}
    assert bd["Entity consistency"]["points"] == 15
    assert bd["Stage count"]["points"] == 30  # 4 stages × 10, capped at 30


# ── Link strength ────────────────────────────────────────────────────────

def test_link_strength_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()

    for inc in incidents:
        ls = inc["linkStrength"]
        assert "totalScore" in ls
        assert "threshold" in ls
        assert "passed" in ls
        assert "components" in ls
        assert ls["passed"] is True, "All demo incidents should pass the threshold"
        assert ls["totalScore"] >= ls["threshold"]


def test_link_strength_components(test_client):
    """Alice chain should have User match component scoring 3."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1

    ls = alice[0]["linkStrength"]
    user_comps = [c for c in ls["components"] if c["factor"] == "User match"]
    assert len(user_comps) >= 1
    assert user_comps[0]["score"] == 3


# ── Summary line ─────────────────────────────────────────────────────────

def test_summary_line_present(test_client):
    """Every incident should have a summary one-liner."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        assert "summary" in inc
        assert len(inc["summary"]) > 20, "Summary should be a meaningful sentence"
        assert "stage" in inc["summary"].lower()
        assert "confidence" in inc["summary"].lower()


def test_alice_summary_mentions_user(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    alice = [i for i in incidents if "alice" in str(i.get("entities", {}).get("users", []))]
    assert len(alice) >= 1
    assert "alice" in alice[0]["summary"].lower()


# ── Recommended actions ──────────────────────────────────────────────────

def test_recommended_actions_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        actions = inc.get("recommendedActions", [])
        assert len(actions) >= 1, "Every multi-stage incident should have actions"
        for a in actions:
            assert "action" in a
            assert "priority" in a
            assert a["priority"] in ("immediate", "recommended")


def test_exfiltration_chain_has_investigate_action(test_client):
    """Incidents with exfiltration stage should suggest investigation."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    exfil_incs = [
        i for i in incidents
        if any(s["stage"] == "exfiltration" for s in i.get("killChainStages", []))
    ]
    assert len(exfil_incs) >= 1
    actions_text = " ".join(
        a["action"].lower() for a in exfil_incs[0]["recommendedActions"]
    )
    assert "exfiltration" in actions_text


def test_credential_chain_has_reset_action(test_client):
    """Incidents with credential_access should suggest credential reset."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    cred_incs = [
        i for i in incidents
        if any(s["stage"] == "credential_access" for s in i.get("killChainStages", []))
    ]
    assert len(cred_incs) >= 1
    actions_text = " ".join(
        a["action"].lower() for a in cred_incs[0]["recommendedActions"]
    )
    assert "reset" in actions_text or "credential" in actions_text


# ── First/last seen ─────────────────────────────────────────────────────

def test_first_last_seen_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        assert "firstSeen" in inc
        assert "lastSeen" in inc
        assert inc["firstSeen"] is not None
        assert inc["lastSeen"] is not None


def test_first_seen_before_last_seen(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        assert inc["firstSeen"] <= inc["lastSeen"]


# ── Severity override ───────────────────────────────────────────────────

def test_exfiltration_chain_severity_at_least_high(test_client):
    """Any chain with exfiltration should be at least high severity."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    exfil = [
        i for i in incidents
        if any(s["stage"] == "exfiltration" for s in i.get("killChainStages", []))
    ]
    assert len(exfil) >= 1
    for inc in exfil:
        assert inc["severity"] in ("high", "critical")


def test_multi_stage_exfil_is_critical(test_client):
    """4+ stages with exfiltration should be critical."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    multi_exfil = [
        i for i in incidents
        if i["alertTypeCount"] >= 4
        and any(s["stage"] == "exfiltration" for s in i.get("killChainStages", []))
    ]
    assert len(multi_exfil) >= 1
    for inc in multi_exfil:
        assert inc["severity"] == "critical"


# ── Detail endpoint includes new fields ──────────────────────────────────

def test_detail_includes_new_fields(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    inc_id = incidents[0]["id"]
    detail = test_client.get(f"/api/v1/incidents/{inc_id}").json()
    assert "summary" in detail
    assert "recommendedActions" in detail
    assert "firstSeen" in detail
    assert "lastSeen" in detail


# ── Risk assessment ──────────────────────────────────────────────────────

def test_risk_level_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        assert "riskLevel" in inc
        assert inc["riskLevel"] in ("low", "medium", "high", "critical")


def test_risk_factors_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        rf = inc.get("riskFactors", [])
        assert len(rf) >= 1
        for f in rf:
            assert "factor" in f
            assert "impact" in f
            assert f["impact"] in ("low", "medium", "high", "critical")


def test_exfiltration_chain_high_risk(test_client):
    """Chains with exfiltration should be high or critical risk."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    exfil = [
        i for i in incidents
        if any(s["stage"] == "exfiltration" for s in i.get("killChainStages", []))
    ]
    assert len(exfil) >= 1
    for inc in exfil:
        assert inc["riskLevel"] in ("high", "critical")


# ── Workflow prediction ──────────────────────────────────────────────────

def test_workflow_present(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    for inc in incidents:
        wf = inc.get("workflow", {})
        assert "wouldEscalate" in wf
        assert "wouldAutoContain" in wf
        assert "disposition" in wf
        assert "estimatedTriage" in wf
        assert wf["disposition"] in ("auto-escalate", "escalate", "investigate", "monitor")


def test_critical_incident_would_escalate(test_client):
    """Critical-severity incidents should be flagged for escalation."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    critical = [i for i in incidents if i["severity"] == "critical"]
    if critical:
        for inc in critical:
            assert inc["workflow"]["wouldEscalate"] is True


# ── Export endpoint ──────────────────────────────────────────────────────

def test_export_slack(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    inc_id = incidents[0]["id"]
    resp = test_client.get(f"/api/v1/incidents/{inc_id}/export?fmt=slack")
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "slack"
    assert "text" in data
    assert "blocks" in data
    assert "Incident" in data["text"]


def test_export_json(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    inc_id = incidents[0]["id"]
    resp = test_client.get(f"/api/v1/incidents/{inc_id}/export?fmt=json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["format"] == "json"
    assert "incident" in data
    assert "title" in data["incident"]
    assert "recommendedActions" in data["incident"]


def test_export_not_found(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    resp = test_client.get("/api/v1/incidents/00000000-0000-0000-0000-000000000000/export")
    assert resp.status_code == 404


# ── Detail includes new fields ───────────────────────────────────────────

def test_detail_includes_risk_and_workflow(test_client):
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    inc_id = incidents[0]["id"]
    detail = test_client.get(f"/api/v1/incidents/{inc_id}").json()
    assert "riskLevel" in detail
    assert "riskFactors" in detail
    assert "workflow" in detail


# ── UI page ──────────────────────────────────────────────────────────────

def test_incidents_page_returns_html(test_client):
    resp = test_client.get("/demo/ui/incidents")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Vigilis - Incidents" in resp.text
    assert "Confidence vs Risk" in resp.text
    assert "Analyst Workflow" in resp.text


# ── BEC chain correlation (Fix 1) ────────────────────────────────────────

def test_bec_chain_persistence_stage(test_client):
    """email.forwardingRule should map to persistence, enabling BEC incident creation."""
    from backend.app.services.incident_service import get_stage
    assert get_stage("email.forwardingRule") == "persistence"
    assert get_stage("identity.suspiciousSignIn") == "initial_access"


def test_cfo_bec_chain_title_descriptive(test_client):
    """CFO incident title should be descriptive of the attack chain."""
    test_client.post("/api/v1/demo/simulate-pilot")
    incidents = test_client.get("/api/v1/incidents").json()
    cfo = [i for i in incidents if "cfo" in str(i.get("entities", {}).get("users", []))]
    assert len(cfo) >= 1
    title = cfo[0]["title"].lower()
    # Title should mention the attack type — various valid descriptions
    assert any(kw in title for kw in [
        "credential", "lateral", "compromise", "persistence", "mailbox",
        "access", "movement", "abuse",
    ]), f"CFO incident title should be descriptive, got: {cfo[0]['title']}"


# ── Cloud sub-stage refinement (Fix 4) ──────────────────────────────────

def test_cloud_stage_mappings():
    """New cloud alert types should map to distinct stages."""
    from backend.app.services.incident_service import get_stage
    assert get_stage("cloud.iamPrivilegeEscalation") == "privilege_escalation"
    assert get_stage("cloud.suspiciousApiCall") == "execution"
    assert get_stage("cloud.secretStoreAccessAnomaly") == "exfiltration"


def test_refine_cloud_stage_persistence():
    """_refine_cloud_stage should detect persistence from enrichment notes."""
    from unittest.mock import MagicMock
    from backend.app.services.incident_service import _refine_cloud_stage

    case = MagicMock()
    case.alert_type = "cloud.secretStoreAccessAnomaly"
    case.description = "CreateAccessKey detected for service account"
    case.enrichment = {"enrichmentNotes": ["CreateAccessKey operation detected"]}
    assert _refine_cloud_stage(case) == "persistence"


def test_refine_cloud_stage_priv_esc():
    """_refine_cloud_stage should detect privilege escalation signals."""
    from unittest.mock import MagicMock
    from backend.app.services.incident_service import _refine_cloud_stage

    case = MagicMock()
    case.alert_type = "cloud.secretStoreAccessAnomaly"
    case.description = "admin_role_grant detected"
    case.enrichment = {"enrichmentNotes": []}
    assert _refine_cloud_stage(case) == "privilege_escalation"


def test_refine_cloud_stage_default():
    """_refine_cloud_stage should fall back to default mapping."""
    from unittest.mock import MagicMock
    from backend.app.services.incident_service import _refine_cloud_stage

    case = MagicMock()
    case.alert_type = "cloud.secretStoreAccessAnomaly"
    case.description = "Normal access event"
    case.enrichment = {"enrichmentNotes": ["Standard access"]}
    assert _refine_cloud_stage(case) == "exfiltration"
