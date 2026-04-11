"""Tests for batch enrichment, file upload, and alert auto-mapping."""
from __future__ import annotations

import io
import json

import pytest


# ── Alert mapper unit tests ──────────────────────────────────────────────

class TestAlertMapper:
    def test_guess_alert_type_malware(self):
        from backend.app.services.alert_mapper import guess_alert_type
        row = {"alert_name": "Malware detected on endpoint", "user": "alice"}
        assert "malware" in guess_alert_type(row).lower()

    def test_guess_alert_type_signin(self):
        from backend.app.services.alert_mapper import guess_alert_type
        row = {"title": "Suspicious sign-in from new location", "user": "bob@corp.com"}
        assert guess_alert_type(row) == "identity.suspiciousSignIn"

    def test_guess_alert_type_forwarding(self):
        from backend.app.services.alert_mapper import guess_alert_type
        row = {"description": "New inbox forwarding rule created", "email": "cfo@corp.com"}
        assert guess_alert_type(row) == "email.forwardingRule"

    def test_map_row_extracts_identity(self):
        from backend.app.services.alert_mapper import map_row_to_raw_alert
        row = {"UserPrincipalName": "alice@corp.com", "IPAddress": "10.0.0.1", "severity": "high"}
        alert_type, raw = map_row_to_raw_alert(row)
        assert raw["identity"]["upn"] == "alice@corp.com"
        assert raw["ips"][0]["ipAddress"] == "10.0.0.1"

    def test_map_row_with_splunk_fields(self):
        from backend.app.services.alert_mapper import map_row_to_raw_alert
        row = {"src_user": "bob", "src_ip": "192.168.1.1", "dest_ip": "10.0.0.2", "hostname": "WS01"}
        alert_type, raw = map_row_to_raw_alert(row)
        assert raw["identity"]["upn"] == "bob"
        assert len(raw["ips"]) == 2
        assert raw["device"]["hostname"] == "WS01"

    def test_map_row_override_alert_type(self):
        from backend.app.services.alert_mapper import map_row_to_raw_alert
        row = {"user": "test", "action": "something random"}
        alert_type, raw = map_row_to_raw_alert(row, alert_type_override="endpoint.malwareDetection")
        assert alert_type == "endpoint.malwareDetection"

    def test_parse_severity_variants(self):
        from backend.app.services.alert_mapper import parse_severity
        assert parse_severity({"severity": "HIGH"}) == "high"
        assert parse_severity({"priority": "P1"}) == "critical"
        assert parse_severity({"risk_level": "info"}) == "low"
        assert parse_severity({}) == "medium"

    def test_socai_format_passthrough(self):
        from backend.app.services.alert_mapper import map_row_to_raw_alert
        raw = {"identity": {"identityType": "user", "upn": "x@y.com"}, "ips": []}
        alert_type, result = map_row_to_raw_alert(raw)
        assert result is raw

    def test_always_populates_required_entities(self):
        from backend.app.services.alert_mapper import map_row_to_raw_alert
        row = {"severity": "high"}
        alert_type, raw = map_row_to_raw_alert(row)
        assert "identity" in raw
        assert "ips" in raw and len(raw["ips"]) >= 1
        assert "device" in raw


# ── Batch enrichment endpoint ────────────────────────────────────────────

class TestBatchEnrich:
    def test_batch_basic(self, test_client):
        alerts = [
            {"user": "alice@corp.com", "src_ip": "10.0.0.1", "severity": "high",
             "alert_name": "Suspicious sign-in"},
            {"user": "bob@corp.com", "src_ip": "10.0.0.2", "severity": "medium",
             "alert_name": "Malware detected"},
            {"UserPrincipalName": "cfo@corp.com", "severity": "critical",
             "title": "New forwarding rule"},
        ]
        resp = test_client.post("/api/v1/demo/enrich-batch", json={"alerts": alerts})
        assert resp.status_code == 200
        data = resp.json()
        assert data["processed"] == 3
        assert data["errors"] == 0
        assert data["avgScore"] > 0
        assert len(data["results"]) == 3
        for r in data["results"]:
            assert "alertType" in r
            assert "score" in r
            assert "label" in r

    def test_batch_with_alert_type_override(self, test_client):
        alerts = [{"user": "x", "ip": "1.2.3.4"}]
        resp = test_client.post("/api/v1/demo/enrich-batch", json={
            "alerts": alerts,
            "alertType": "identity.mfaFatigue",
        })
        data = resp.json()
        assert data["results"][0]["alertType"] == "identity.mfaFatigue"

    def test_batch_with_persist(self, test_client):
        test_client.post("/api/v1/demo/reset")
        alerts = [
            {"user": "persist@corp.com", "severity": "high", "title": "suspicious login"},
        ]
        resp = test_client.post("/api/v1/demo/enrich-batch", json={
            "alerts": alerts,
            "persist": True,
        })
        data = resp.json()
        assert data["errorDetails"] == [], f"Errors: {data['errorDetails']}"
        assert data["processed"] == 1
        assert data["results"][0]["caseId"] is not None

        cases = test_client.get("/api/v1/cases").json()
        assert len(cases) >= 1

    def test_batch_empty_returns_zero(self, test_client):
        resp = test_client.post("/api/v1/demo/enrich-batch", json={"alerts": []})
        data = resp.json()
        assert data["processed"] == 0

    def test_batch_label_distribution(self, test_client):
        alerts = [{"user": f"u{i}@corp.com", "severity": s, "title": "suspicious login"}
                  for i, s in enumerate(["low", "medium", "high", "critical"])]
        resp = test_client.post("/api/v1/demo/enrich-batch", json={"alerts": alerts})
        data = resp.json()
        labels = data["labelDistribution"]
        assert sum(labels.values()) == 4


# ── File upload endpoint ─────────────────────────────────────────────────

class TestFileUpload:
    def _upload(self, test_client, content: str, filename: str, **params):
        files = {"file": (filename, io.BytesIO(content.encode("utf-8")), "application/octet-stream")}
        return test_client.post("/api/v1/demo/upload", files=files, params=params)

    def test_upload_csv(self, test_client):
        csv_data = "user,src_ip,severity,alert_name\nalice@corp.com,10.0.0.1,high,Suspicious Login\nbob@corp.com,10.0.0.2,medium,Malware Found"
        resp = self._upload(test_client, csv_data, "alerts.csv")
        assert resp.status_code == 200
        data = resp.json()
        assert data["processed"] == 2
        assert data["errors"] == 0

    def test_upload_json_array(self, test_client):
        rows = [
            {"UserPrincipalName": "alice@corp.com", "IPAddress": "10.0.0.1", "severity": "high"},
            {"UserPrincipalName": "bob@corp.com", "IPAddress": "10.0.0.2", "severity": "low"},
        ]
        resp = self._upload(test_client, json.dumps(rows), "alerts.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["processed"] == 2

    def test_upload_jsonl(self, test_client):
        lines = '{"user":"a@b.com","severity":"high"}\n{"user":"c@d.com","severity":"low"}'
        resp = self._upload(test_client, lines, "alerts.jsonl")
        assert resp.status_code == 200
        assert resp.json()["processed"] == 2

    def test_upload_with_alert_type(self, test_client):
        csv_data = "user,severity\nalice@corp.com,high"
        resp = self._upload(test_client, csv_data, "a.csv", alertType="endpoint.malwareDetection")
        data = resp.json()
        assert data["results"][0]["alertType"] == "endpoint.malwareDetection"

    def test_upload_with_persist(self, test_client):
        test_client.post("/api/v1/demo/reset")
        csv_data = "user,severity\nalice@corp.com,high"
        resp = self._upload(test_client, csv_data, "a.csv", persist="true")
        data = resp.json()
        assert data["processed"] == 1
        cases = test_client.get("/api/v1/cases").json()
        assert len(cases) >= 1

    def test_upload_empty_file_returns_422(self, test_client):
        resp = self._upload(test_client, "", "empty.csv")
        assert resp.status_code == 422


# ── Upload UI page ───────────────────────────────────────────────────────

def test_upload_page_returns_html(test_client):
    resp = test_client.get("/demo/ui/upload")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Upload" in resp.text
    assert "drag" in resp.text.lower()
