"""Tests for the 'Paste Anything' feature — smart parser + API endpoint."""
from __future__ import annotations

import json

import pytest

from backend.app.services.paste_parser import parse_any

pytestmark = pytest.mark.usefixtures("_reset_shared_state")


@pytest.fixture()
def test_client(fresh_client):
    return fresh_client


# ── Parser unit tests ────────────────────────────────────────────────────

class TestParseJSON:
    def test_json_object(self):
        r = parse_any('{"identity": {"upn": "alice@corp.com"}, "severity": "high"}')
        assert r.format == "json"
        assert r.confidence == "high"
        assert r.data["identity"]["upn"] == "alice@corp.com"

    def test_json_array(self):
        r = parse_any('[{"user": "alice"}, {"user": "bob"}]')
        assert r.format == "json_array"
        assert r.data["user"] == "alice"

    def test_invalid_json_not_parsed(self):
        r = parse_any('{"broken: json')
        assert r.format != "json"


class TestParseCSV:
    def test_csv_with_header(self):
        text = "user,action,src_ip,severity\nalice,login,1.2.3.4,high"
        r = parse_any(text)
        assert r.format == "csv"
        assert r.data["user"] == "alice"
        assert r.data["src_ip"] == "1.2.3.4"

    def test_tab_separated(self):
        text = "user\taction\tsrc_ip\nalice\tlogin\t1.2.3.4"
        r = parse_any(text)
        assert r.format == "csv"
        assert r.data["user"] == "alice"

    def test_single_line_not_csv(self):
        r = parse_any("just a single line of text")
        assert r.format != "csv"


class TestParseKeyValue:
    def test_key_equals_value(self):
        r = parse_any("src_ip=198.51.100.7 user=alice action=login severity=high")
        assert r.format == "key_value"
        assert r.data["user"] == "alice"
        assert r.data["src_ip"] == "198.51.100.7"

    def test_key_colon_value(self):
        r = parse_any("user:alice src_ip:1.2.3.4 action:login")
        assert r.format == "key_value"
        assert r.data["user"] == "alice"

    def test_quoted_values(self):
        r = parse_any('user="alice smith" action="failed login" ip=1.2.3.4')
        assert r.format == "key_value"
        assert r.data["user"] == "alice smith"


class TestParseSyslog:
    def test_syslog_format(self):
        r = parse_any("<134>Mar 30 14:02:00 fw01 sshd[1234]: Failed password for alice from 198.51.100.7")
        assert r.format == "syslog"
        assert r.data["hostname"] == "fw01"
        assert "198.51.100.7" in r.data.get("detected_ips", [])

    def test_syslog_without_priority(self):
        r = parse_any("Mar 30 14:02:00 server01 nginx: GET /admin 403")
        assert r.format == "syslog"
        assert r.data["hostname"] == "server01"


class TestParseRawText:
    def test_extracts_ips(self):
        r = parse_any("Alice logged in from 198.51.100.7 and then 10.0.0.1")
        assert "198.51.100.7" in r.data.get("detected_ips", [])
        assert "10.0.0.1" in r.data.get("detected_ips", [])

    def test_extracts_emails(self):
        r = parse_any("The user alice@corp.com accessed the system")
        assert "alice@corp.com" in r.data.get("detected_emails", [])

    def test_extracts_timestamps(self):
        r = parse_any("Event at 2024-03-30T14:02:00Z from unknown")
        assert r.data.get("detected_timestamp") == "2024-03-30T14:02:00Z"

    def test_empty_input(self):
        r = parse_any("")
        assert r.format == "empty"
        assert r.confidence == "low"


# ── API endpoint tests ───────────────────────────────────────────────────

def test_paste_json_event(test_client):
    text = json.dumps({
        "identity": {"upn": "alice@corp.com", "userId": "u1"},
        "ips": [{"ipAddress": "198.51.100.7", "role": "anomalous", "geo": {"country": "Romania"}}],
        "device": {"hostname": "ws-01"},
    })
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    assert resp.status_code == 200
    d = resp.json()
    assert "detection" in d
    assert d["detection"]["inputFormat"] == "json"
    assert "finalCase" in d
    assert d["scoreBreakdown"]["finalScore"] > 0


def test_paste_csv_row(test_client):
    text = "user,action,src_ip,severity\nalice@corp.com,login_failure,198.51.100.7,high"
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    assert resp.status_code == 200
    d = resp.json()
    assert d["detection"]["inputFormat"] == "csv"
    assert d["detection"]["fieldsExtracted"] >= 3


def test_paste_key_value(test_client):
    text = "src_ip=198.51.100.7 user=alice@corp.com action=login_failure severity=high"
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    assert resp.status_code == 200
    d = resp.json()
    assert d["detection"]["inputFormat"] == "key_value"


def test_paste_syslog(test_client):
    text = "<134>Mar 30 14:02:00 fw01 sshd[1234]: Failed password for alice from 198.51.100.7"
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    assert resp.status_code == 200
    d = resp.json()
    assert d["detection"]["inputFormat"] == "syslog"


def test_paste_raw_text(test_client):
    text = "Alice attempted login from Romania (198.51.100.7). MFA not used. Sign-in blocked."
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    assert resp.status_code == 200
    d = resp.json()
    assert "finalCase" in d


def test_paste_empty_fails(test_client):
    resp = test_client.post("/api/v1/demo/paste", json={"text": ""})
    assert resp.status_code == 422


def test_paste_persist(test_client):
    text = json.dumps({
        "identity": {"upn": "bob@corp.com"},
        "ips": [{"ipAddress": "1.2.3.4"}],
        "device": {"hostname": "ws-bob-01"},
    })
    resp = test_client.post("/api/v1/demo/paste", json={"text": text, "persist": True})
    assert resp.status_code == 200, resp.json()
    cases = test_client.get("/api/v1/cases").json()
    assert len(cases) >= 1


def test_paste_returns_signals(test_client):
    text = json.dumps({
        "identity": {"upn": "alice@corp.com", "mfaStatus": "disabled"},
        "ips": [{"ipAddress": "198.51.100.7", "role": "anomalous"}],
    })
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    d = resp.json()
    assert "derivedSignals" in d
    assert len(d["derivedSignals"]) > 0
    assert "recommendedPlaybook" in d
    assert "recommendedActions" in d


def test_paste_detection_has_notes(test_client):
    text = "user=alice action=login src_ip=1.2.3.4"
    resp = test_client.post("/api/v1/demo/paste", json={"text": text})
    d = resp.json()
    assert len(d["detection"]["notes"]) >= 1


def test_enrich_page_has_paste_ui(test_client):
    resp = test_client.get("/demo/ui/enrich")
    assert resp.status_code == 200
    assert "Paste" in resp.text
    assert "Investigate" in resp.text
