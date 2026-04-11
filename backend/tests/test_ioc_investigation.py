"""Tests for the IOC Investigation feature."""
from __future__ import annotations

import pytest

from backend.app.services.ioc_investigator import detect_ioc_type

pytestmark = pytest.mark.usefixtures("_reset_shared_state")


@pytest.fixture()
def client(fresh_client):
    return fresh_client


@pytest.fixture()
def populated_client(populated_fresh_client):
    return populated_fresh_client


# ── IOC type detection ────────────────────────────────────────────────

class TestDetectIOCType:
    def test_ipv4(self):
        assert detect_ioc_type("198.51.100.7") == "ip"

    def test_sha256(self):
        assert detect_ioc_type("a" * 64) == "sha256"

    def test_md5(self):
        assert detect_ioc_type("d" * 32) == "md5"

    def test_email(self):
        assert detect_ioc_type("alice@corp.com") == "email"

    def test_domain(self):
        assert detect_ioc_type("evil.example.com") == "domain"

    def test_keyword(self):
        assert detect_ioc_type("alice") == "keyword"

    def test_keyword_with_spaces(self):
        assert detect_ioc_type("some random text") == "keyword"


# ── API endpoint ─────────────────────────────────────────────────────

def test_investigate_empty_query(client):
    resp = client.get("/api/v1/demo/investigate?q=")
    assert resp.status_code == 422


def test_investigate_no_data(client):
    resp = client.get("/api/v1/demo/investigate?q=198.51.100.7")
    assert resp.status_code == 200
    d = resp.json()
    assert d["found"] is False
    assert d["totalHits"] == 0
    assert d["iocType"] == "ip"


def test_investigate_ip_with_data(populated_client):
    resp = populated_client.get("/api/v1/demo/investigate?q=198.51.100.7")
    assert resp.status_code == 200
    d = resp.json()
    assert d["iocType"] == "ip"
    assert d["ioc"] == "198.51.100.7"
    if d["found"]:
        assert d["totalHits"] > 0
        assert len(d["cases"]) > 0
        assert len(d["timeline"]) > 0
        assert d["firstSeen"] is not None
        assert d["lastSeen"] is not None


def test_investigate_returns_entity_graph(populated_client):
    cases_resp = populated_client.get("/api/v1/cases")
    cases = cases_resp.json()
    if not cases:
        pytest.skip("No cases loaded")

    first_case = cases[0]
    entities = first_case.get("entities", {})
    ips = entities.get("ips", [])
    if not ips:
        pytest.skip("No IPs in first case")

    ip = ips[0].get("ipAddress")
    resp = populated_client.get(f"/api/v1/demo/investigate?q={ip}")
    d = resp.json()
    assert "entityGraph" in d
    eg = d["entityGraph"]
    assert "users" in eg
    assert "ips" in eg
    assert "hostnames" in eg


def test_investigate_email(populated_client):
    cases_resp = populated_client.get("/api/v1/cases")
    cases = cases_resp.json()
    if not cases:
        pytest.skip("No cases loaded")

    for case in cases:
        upn = case.get("entities", {}).get("identity", {}).get("upn")
        if upn and "@" in upn:
            resp = populated_client.get(f"/api/v1/demo/investigate?q={upn}")
            d = resp.json()
            assert d["iocType"] == "email"
            assert d["found"] is True
            assert d["totalHits"] > 0
            return
    pytest.skip("No email found in cases")


def test_investigate_hostname(populated_client):
    cases_resp = populated_client.get("/api/v1/cases")
    cases = cases_resp.json()
    for case in cases:
        hostname = case.get("entities", {}).get("device", {}).get("hostname")
        if hostname:
            resp = populated_client.get(f"/api/v1/demo/investigate?q={hostname}")
            d = resp.json()
            assert d["found"] is True
            assert d["totalHits"] > 0
            return
    pytest.skip("No hostname found in cases")


def test_investigate_returns_related_incidents(populated_client):
    resp = populated_client.get("/api/v1/demo/investigate?q=198.51.100.7")
    d = resp.json()
    if d["found"]:
        assert "relatedIncidents" in d
        for inc in d["relatedIncidents"]:
            assert "incidentId" in inc
            assert "title" in inc
            assert "severity" in inc


def test_investigate_returns_geo_data(populated_client):
    resp = populated_client.get("/api/v1/demo/investigate?q=198.51.100.7")
    d = resp.json()
    if d["found"]:
        assert "geoData" in d
        for geo in d["geoData"]:
            assert "ipAddress" in geo


def test_investigate_returns_severity_distribution(populated_client):
    cases_resp = populated_client.get("/api/v1/cases")
    cases = cases_resp.json()
    if not cases:
        pytest.skip("No cases loaded")

    first_ip = None
    for case in cases:
        ips = case.get("entities", {}).get("ips", [])
        if ips:
            first_ip = ips[0].get("ipAddress")
            break
    if not first_ip:
        pytest.skip("No IPs found")

    resp = populated_client.get(f"/api/v1/demo/investigate?q={first_ip}")
    d = resp.json()
    assert "severityDistribution" in d
    assert "alertTypeDistribution" in d


def test_investigate_cases_have_expected_fields(populated_client):
    cases_resp = populated_client.get("/api/v1/cases")
    cases = cases_resp.json()
    if not cases:
        pytest.skip("No cases loaded")

    first_ip = None
    for case in cases:
        ips = case.get("entities", {}).get("ips", [])
        if ips:
            first_ip = ips[0].get("ipAddress")
            break
    if not first_ip:
        pytest.skip("No IPs found")

    resp = populated_client.get(f"/api/v1/demo/investigate?q={first_ip}")
    d = resp.json()
    if d["found"] and d["cases"]:
        c = d["cases"][0]
        assert "caseId" in c
        assert "alertType" in c
        assert "severity" in c
        assert "confidenceScore" in c
        assert "eventTime" in c


def test_investigate_keyword_search(populated_client):
    resp = populated_client.get("/api/v1/demo/investigate?q=alice")
    d = resp.json()
    assert d["iocType"] == "keyword"


def test_investigate_ui_tab_present(populated_client):
    resp = populated_client.get("/demo/ui/enrich")
    assert resp.status_code == 200
    assert "Investigate IOC" in resp.text
    assert "iocInput" in resp.text
