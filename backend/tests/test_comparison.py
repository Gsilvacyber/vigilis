"""Tests for the Side-by-Side Comparison feature."""
from __future__ import annotations

import json

import pytest

from backend.app.services.comparison import compare_enrichments

pytestmark = pytest.mark.usefixtures("_reset_shared_state")


@pytest.fixture()
def client(fresh_client):
    return fresh_client


ALERT_A = json.dumps({
    "identity": {"upn": "alice@corp.com", "mfaStatus": "disabled"},
    "ips": [{"ipAddress": "198.51.100.7", "role": "anomalous", "geo": {"country": "Romania"}}],
    "device": {"hostname": "ws-alice-01"},
})

ALERT_B = json.dumps({
    "identity": {"upn": "bob@corp.com", "mfaStatus": "enabled"},
    "ips": [{"ipAddress": "10.0.0.42", "role": "observed", "geo": {"country": "US"}}],
    "device": {"hostname": "ws-bob-02"},
})

ALERT_SAME_ENTITY = json.dumps({
    "identity": {"upn": "alice@corp.com"},
    "ips": [{"ipAddress": "198.51.100.7"}],
    "mailbox": {"primaryAddress": "alice@corp.com", "forwardingAddress": "drop@evil.com"},
})

ALERT_KV = "src_ip=198.51.100.7 user=alice@corp.com action=process_creation severity=high"

TENANT_ID = "demo-tenant-id"


# ── Service-level tests ──────────────────────────────────────────────

class TestCompareEnrichments:
    def test_same_type_comparison(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        assert "comparison" in result
        cmp = result["comparison"]
        assert cmp["sameAlertType"] is True
        assert "scoreDelta" in cmp
        assert "signals" in cmp
        assert len(cmp["signals"]) > 0

    def test_different_type_comparison(self):
        result = compare_enrichments(ALERT_A, ALERT_KV, TENANT_ID)
        cmp = result["comparison"]
        assert "sameAlertType" in cmp
        assert "verdict" in cmp
        assert len(cmp["verdict"]) > 0

    def test_entity_overlap_detected(self):
        result = compare_enrichments(ALERT_A, ALERT_SAME_ENTITY, TENANT_ID)
        cmp = result["comparison"]
        overlap = cmp["entityOverlap"]
        assert len(overlap["users"]["shared"]) > 0
        assert "alice@corp.com" in overlap["users"]["shared"]
        assert len(overlap["ips"]["shared"]) > 0

    def test_entity_only_in_one(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        overlap = result["comparison"]["entityOverlap"]
        assert "alice@corp.com" in overlap["users"]["onlyA"]
        assert "bob@corp.com" in overlap["users"]["onlyB"]

    def test_signal_status_categories(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        statuses = {s["status"] for s in result["comparison"]["signals"]}
        assert statuses.issubset({"both", "only_a", "only_b", "neither"})

    def test_playbook_comparison(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        pb = result["comparison"]["playbook"]
        assert "shared" in pb
        assert "onlyA" in pb
        assert "onlyB" in pb

    def test_actions_comparison(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        act = result["comparison"]["actions"]
        assert "shared" in act
        assert "onlyA" in act
        assert "onlyB" in act

    def test_verdict_generated(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        assert len(result["comparison"]["verdict"]) > 5

    def test_both_results_present(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        assert "a" in result and "b" in result
        assert result["a"]["alertType"]
        assert result["b"]["alertType"]
        assert result["a"]["scoreBreakdown"]["finalScore"] >= 0
        assert result["b"]["scoreBreakdown"]["finalScore"] >= 0

    def test_signals_fired_counts(self):
        result = compare_enrichments(ALERT_A, ALERT_B, TENANT_ID)
        cmp = result["comparison"]
        assert "signalsFiredA" in cmp
        assert "signalsFiredB" in cmp
        assert isinstance(cmp["signalsFiredA"], int)


# ── API endpoint tests ──────────────────────────────────────────────

def test_compare_endpoint_returns_200(client):
    resp = client.post("/api/v1/demo/compare", json={"textA": ALERT_A, "textB": ALERT_B})
    assert resp.status_code == 200
    d = resp.json()
    assert "comparison" in d
    assert "a" in d
    assert "b" in d


def test_compare_endpoint_empty_input(client):
    resp = client.post("/api/v1/demo/compare", json={"textA": "", "textB": ALERT_B})
    assert resp.status_code == 422


def test_compare_endpoint_both_empty(client):
    resp = client.post("/api/v1/demo/compare", json={"textA": "  ", "textB": "  "})
    assert resp.status_code == 422


def test_compare_different_formats(client):
    resp = client.post("/api/v1/demo/compare", json={"textA": ALERT_A, "textB": ALERT_KV})
    assert resp.status_code == 200
    d = resp.json()
    assert d["a"]["detection"]["inputFormat"] == "json"
    assert d["b"]["detection"]["inputFormat"] == "key_value"


def test_compare_shared_entities(client):
    resp = client.post("/api/v1/demo/compare", json={"textA": ALERT_A, "textB": ALERT_SAME_ENTITY})
    assert resp.status_code == 200
    overlap = resp.json()["comparison"]["entityOverlap"]
    assert "alice@corp.com" in overlap["users"]["shared"]


def test_compare_score_delta(client):
    resp = client.post("/api/v1/demo/compare", json={"textA": ALERT_A, "textB": ALERT_B})
    d = resp.json()
    cmp = d["comparison"]
    assert cmp["scoreDelta"] == cmp["scoreA"] - cmp["scoreB"]


def test_compare_tab_in_ui(client):
    resp = client.get("/demo/ui/enrich")
    assert resp.status_code == 200
    assert "Compare Alerts" in resp.text
    assert "cmpInputA" in resp.text
    assert "cmpInputB" in resp.text
