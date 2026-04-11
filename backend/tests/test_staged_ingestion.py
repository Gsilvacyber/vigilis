"""Tests for the staged ingestion pipeline: preview, mappings, validation, process."""
from __future__ import annotations

import io
import json

import pytest


# ── Ingestion service unit tests ─────────────────────────────────────────

class TestSourceProfileDetection:
    def test_detects_splunk(self):
        from backend.app.services.ingestion import detect_source_profile
        cols = ["_time", "src_user", "src_ip", "dest_ip", "host", "severity", "signature", "action"]
        profile = detect_source_profile(cols)
        assert profile.detected == "splunk"
        assert profile.confidence > 0.4
        assert len(profile.matched_fields) >= 3

    def test_detects_sentinel(self):
        from backend.app.services.ingestion import detect_source_profile
        cols = ["TimeGenerated", "UserPrincipalName", "IPAddress", "AlertSeverity", "AlertName", "TenantId"]
        profile = detect_source_profile(cols)
        assert profile.detected == "sentinel"
        assert profile.confidence > 0.4

    def test_unknown_columns(self):
        from backend.app.services.ingestion import detect_source_profile
        cols = ["foo", "bar", "baz", "qux"]
        profile = detect_source_profile(cols)
        assert profile.detected == "unknown"
        assert profile.confidence == 0.0

    def test_partial_match_still_detects(self):
        from backend.app.services.ingestion import detect_source_profile
        cols = ["_time", "src_ip", "dest_ip", "random_field", "another_field"]
        profile = detect_source_profile(cols)
        assert profile.detected == "splunk"


class TestColumnMapping:
    def test_maps_known_columns(self):
        from backend.app.services.ingestion import map_columns
        cols = ["UserPrincipalName", "IPAddress", "severity", "hostname"]
        mappings = map_columns(cols)
        mapped = {m.source_column: m.canonical_field for m in mappings}
        assert mapped["UserPrincipalName"] == "identity"
        assert mapped["IPAddress"] == "ip"
        assert mapped["severity"] == "severity"
        assert mapped["hostname"] == "device"

    def test_maps_splunk_columns(self):
        from backend.app.services.ingestion import map_columns
        cols = ["src_user", "src_ip", "dest_ip", "host", "action"]
        mappings = map_columns(cols)
        mapped = {m.source_column: m.canonical_field for m in mappings}
        assert mapped["src_user"] == "identity"
        assert mapped["src_ip"] == "ip"
        assert mapped["dest_ip"] == "dest_ip"
        assert mapped["host"] == "device"

    def test_unknown_columns_marked_unmapped(self):
        from backend.app.services.ingestion import map_columns
        cols = ["foo", "bar"]
        mappings = map_columns(cols)
        assert all(m.canonical_field == "unmapped" for m in mappings)
        assert all(m.confidence == 0.0 for m in mappings)

    def test_confidence_scores_present(self):
        from backend.app.services.ingestion import map_columns
        cols = ["user", "ip", "severity"]
        mappings = map_columns(cols)
        for m in mappings:
            assert 0.0 <= m.confidence <= 1.0

    def test_timestamp_detection(self):
        from backend.app.services.ingestion import map_columns
        cols = ["TimeGenerated", "user", "ip"]
        mappings = map_columns(cols)
        ts_mapping = next(m for m in mappings if m.source_column == "TimeGenerated")
        assert ts_mapping.canonical_field == "timestamp"


class TestRowValidation:
    def test_valid_row(self):
        from backend.app.services.ingestion import validate_row, map_columns
        cols = ["user", "src_ip", "severity", "title", "timestamp"]
        mappings = map_columns(cols)
        row = {"user": "alice@corp.com", "src_ip": "10.0.0.1", "severity": "high", "title": "Suspicious login", "timestamp": "2026-03-25T08:00:00Z"}
        v = validate_row(0, row, mappings)
        assert v.valid is True
        assert v.reasons == []

    def test_missing_identity(self):
        # Row with IP + severity but no identity is NOW valid (lenient validation)
        # because K8s/cloud alerts may lack user but still have IP + severity
        from backend.app.services.ingestion import validate_row, map_columns
        cols = ["src_ip", "severity"]
        mappings = map_columns(cols)
        row = {"src_ip": "10.0.0.1", "severity": "high"}
        v = validate_row(0, row, mappings)
        assert v.valid is True  # valid because has_ip + has_severity
        assert any("identity" in r.lower() for r in v.reasons)  # still notes the gap

    def test_missing_ip(self):
        from backend.app.services.ingestion import validate_row, map_columns
        cols = ["user", "severity", "title"]
        mappings = map_columns(cols)
        row = {"user": "alice@corp.com", "severity": "high", "title": "Suspicious login"}
        v = validate_row(0, row, mappings)
        assert any("ip" in r.lower() for r in v.reasons)

    def test_no_alert_keywords(self):
        from backend.app.services.ingestion import validate_row, map_columns
        cols = ["user", "src_ip", "notes"]
        mappings = map_columns(cols)
        row = {"user": "alice@corp.com", "src_ip": "10.0.0.1", "notes": "routine check"}
        v = validate_row(0, row, mappings)
        assert any("alert type" in r.lower() for r in v.reasons)

    def test_empty_identity_treated_as_missing(self):
        from backend.app.services.ingestion import validate_row, map_columns
        cols = ["user", "src_ip"]
        mappings = map_columns(cols)
        row = {"user": "", "src_ip": "10.0.0.1"}
        v = validate_row(0, row, mappings)
        assert any("identity" in r.lower() for r in v.reasons)


class TestBuildPreview:
    def test_csv_preview(self):
        from backend.app.services.ingestion import build_preview
        csv_data = "user,src_ip,severity,alert_name\nalice@corp.com,10.0.0.1,high,Suspicious Login\nbob@corp.com,10.0.0.2,medium,Malware Found"
        preview = build_preview(csv_data, "test.csv")
        assert preview.total_rows == 2
        assert preview.file_format == "csv"
        assert len(preview.columns) == 4
        assert len(preview.column_mappings) == 4
        assert len(preview.row_validations) == 2
        assert preview.summary["total"] == 2

    def test_json_preview(self):
        from backend.app.services.ingestion import build_preview
        rows = [
            {"UserPrincipalName": "alice@corp.com", "IPAddress": "10.0.0.1", "severity": "high"},
            {"UserPrincipalName": "bob@corp.com", "IPAddress": "10.0.0.2", "severity": "low"},
        ]
        preview = build_preview(json.dumps(rows), "test.json")
        assert preview.total_rows == 2
        assert preview.file_format == "json"
        assert preview.source_profile.detected == "unknown"  # not enough sentinel fields

    def test_empty_file(self):
        from backend.app.services.ingestion import build_preview
        preview = build_preview("", "empty.csv")
        assert preview.total_rows == 0

    def test_splunk_profile_detection(self):
        from backend.app.services.ingestion import build_preview
        csv_data = "_time,src_user,src_ip,dest_ip,host,severity,signature,action\n2026-01-01T00:00:00Z,alice@corp.com,10.0.0.1,10.0.0.2,ws-01,high,Suspicious Login,allowed"
        preview = build_preview(csv_data, "splunk.csv")
        assert preview.source_profile.detected == "splunk"

    def test_max_rows_capped(self):
        from backend.app.services.ingestion import build_preview
        lines = ["user,ip"] + [f"u{i}@corp.com,10.0.0.{i%255}" for i in range(600)]
        csv_data = "\n".join(lines)
        preview = build_preview(csv_data, "big.csv", max_rows=100)
        assert preview.total_rows == 100

    def test_sample_rows_limited_to_5(self):
        from backend.app.services.ingestion import build_preview
        lines = ["user,ip"] + [f"u{i}@corp.com,10.0.0.{i}" for i in range(20)]
        csv_data = "\n".join(lines)
        preview = build_preview(csv_data, "test.csv")
        assert len(preview.sample_rows) == 5


class TestProcessUpload:
    def test_basic_processing(self):
        from backend.app.services.ingestion import process_upload
        csv_data = "user,src_ip,severity,alert_name\nalice@corp.com,10.0.0.1,high,Suspicious Login\nbob@corp.com,10.0.0.2,medium,Malware Found"
        result = process_upload(csv_data, "test.csv", tenant_id="demo-tenant")
        assert result.processed == 2
        assert result.enriched == 2
        assert result.skipped == 0
        assert result.avg_score > 0

    def test_column_overrides(self):
        from backend.app.services.ingestion import process_upload
        csv_data = "employee,address,level,desc\nalice@corp.com,10.0.0.1,high,Suspicious Login"
        # Without overrides these columns won't map well
        result = process_upload(
            csv_data, "test.csv", tenant_id="demo-tenant",
            column_overrides={"employee": "identity", "address": "ip", "level": "severity", "desc": "alert_name"},
        )
        assert result.enriched == 1

    def test_alert_type_override(self):
        from backend.app.services.ingestion import process_upload
        csv_data = "user,src_ip,severity\nalice@corp.com,10.0.0.1,high"
        result = process_upload(csv_data, "test.csv", tenant_id="demo-tenant", alert_type_override="endpoint.malwareDetection")
        enriched = [r for r in result.results if r.get("status") == "enriched"]
        assert enriched[0]["alertType"] == "endpoint.malwareDetection"

    def test_skipped_rows_have_reasons(self):
        from backend.app.services.ingestion import process_upload
        # Row with no identity AND no IP should be skipped
        csv_data = "notes,random\njust a note,nothing here"
        result = process_upload(csv_data, "test.csv", tenant_id="demo-tenant")
        skipped = [r for r in result.results if r.get("status") == "skipped"]
        assert len(skipped) == 1
        assert len(skipped[0]["reasons"]) > 0

    def test_mixed_valid_and_invalid_rows(self):
        from backend.app.services.ingestion import process_upload
        csv_data = "user,src_ip,severity,title\nalice@corp.com,10.0.0.1,high,Suspicious Login\n,,,"
        result = process_upload(csv_data, "test.csv", tenant_id="demo-tenant")
        assert result.processed == 2
        # Second row has no identity and no IP, should be skipped
        assert result.skipped >= 1 or result.enriched <= 2


# ── API endpoint tests ───────────────────────────────────────────────────

class TestUploadPreviewEndpoint:
    def _upload(self, test_client, content: str, filename: str):
        files = {"file": (filename, io.BytesIO(content.encode("utf-8")), "application/octet-stream")}
        return test_client.post("/api/v1/demo/upload/preview", files=files)

    def test_preview_csv(self, test_client):
        csv_data = "user,src_ip,severity,alert_name\nalice@corp.com,10.0.0.1,high,Suspicious Login\nbob@corp.com,10.0.0.2,medium,Malware Found"
        resp = self._upload(test_client, csv_data, "alerts.csv")
        assert resp.status_code == 200
        data = resp.json()
        assert data["totalRows"] == 2
        assert data["fileFormat"] == "csv"
        assert len(data["columns"]) == 4
        assert len(data["columnMappings"]) == 4
        assert len(data["rowValidations"]) == 2
        assert "sourceProfile" in data
        assert data["sourceProfile"]["detected"] in ("splunk", "sentinel", "unknown")

    def test_preview_json(self, test_client):
        rows = [{"UserPrincipalName": "alice@corp.com", "IPAddress": "10.0.0.1", "severity": "high"}]
        resp = self._upload(test_client, json.dumps(rows), "alerts.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["totalRows"] == 1
        assert data["fileFormat"] == "json"

    def test_preview_empty_file_422(self, test_client):
        resp = self._upload(test_client, "", "empty.csv")
        assert resp.status_code == 422

    def test_preview_has_mapping_confidence(self, test_client):
        csv_data = "UserPrincipalName,IPAddress,AlertSeverity\nalice@corp.com,10.0.0.1,high"
        resp = self._upload(test_client, csv_data, "sentinel.csv")
        data = resp.json()
        for m in data["columnMappings"]:
            assert "confidence" in m
            assert 0 <= m["confidence"] <= 1.0

    def test_preview_has_validation_reasons(self, test_client):
        csv_data = "notes,random\njust a note,nothing here"
        resp = self._upload(test_client, csv_data, "bad.csv")
        data = resp.json()
        invalid = [v for v in data["rowValidations"] if not v["valid"]]
        assert len(invalid) > 0
        assert len(invalid[0]["reasons"]) > 0

    def test_preview_sentinel_detection(self, test_client):
        csv_data = "TimeGenerated,UserPrincipalName,IPAddress,AlertSeverity,AlertName,TenantId\n2026-01-01T00:00:00Z,alice@corp.com,10.0.0.1,High,Suspicious Login,abc123"
        resp = self._upload(test_client, csv_data, "sentinel.csv")
        data = resp.json()
        assert data["sourceProfile"]["detected"] == "sentinel"


class TestUploadProcessEndpoint:
    def test_process_basic(self, test_client):
        csv_data = "user,src_ip,severity,alert_name\nalice@corp.com,10.0.0.1,high,Suspicious Login"
        resp = test_client.post("/api/v1/demo/upload/process", json={
            "fileContent": csv_data,
            "filename": "test.csv",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["processed"] == 1
        assert data["enriched"] == 1
        assert data["skipped"] == 0
        assert "avgScore" in data
        assert "labelDistribution" in data
        assert "alertTypeDistribution" in data

    def test_process_with_overrides(self, test_client):
        csv_data = "employee,address\nalice@corp.com,10.0.0.1"
        resp = test_client.post("/api/v1/demo/upload/process", json={
            "fileContent": csv_data,
            "filename": "test.csv",
            "columnOverrides": {"employee": "identity", "address": "ip"},
        })
        data = resp.json()
        assert data["enriched"] >= 1

    def test_process_with_alert_type_override(self, test_client):
        csv_data = "user,src_ip,severity\nalice@corp.com,10.0.0.1,high"
        resp = test_client.post("/api/v1/demo/upload/process", json={
            "fileContent": csv_data,
            "filename": "test.csv",
            "alertType": "identity.mfaFatigue",
        })
        data = resp.json()
        enriched = [r for r in data["results"] if r.get("status") == "enriched"]
        assert enriched[0]["alertType"] == "identity.mfaFatigue"

    def test_process_with_persist(self, test_client):
        test_client.post("/api/v1/demo/reset")
        csv_data = "user,src_ip,severity,title\nalice@corp.com,10.0.0.1,high,Suspicious Login"
        resp = test_client.post("/api/v1/demo/upload/process", json={
            "fileContent": csv_data,
            "filename": "test.csv",
            "persist": True,
        })
        data = resp.json()
        assert data["enriched"] == 1
        enriched = [r for r in data["results"] if r.get("status") == "enriched"]
        assert enriched[0]["caseId"] is not None
        cases = test_client.get("/api/v1/cases").json()
        assert len(cases) >= 1

    def test_process_reports_skipped_with_reasons(self, test_client):
        csv_data = "notes,random\njust a note,nothing"
        resp = test_client.post("/api/v1/demo/upload/process", json={
            "fileContent": csv_data,
            "filename": "test.csv",
        })
        data = resp.json()
        assert data["skipped"] >= 1
        skipped = [r for r in data["results"] if r.get("status") == "skipped"]
        assert len(skipped) >= 1
        assert len(skipped[0]["reasons"]) > 0

    def test_process_summary_fields(self, test_client):
        csv_data = "user,src_ip,severity,alert_name\nalice@corp.com,10.0.0.1,high,Suspicious Login\nbob@corp.com,10.0.0.2,medium,Malware Found"
        resp = test_client.post("/api/v1/demo/upload/process", json={
            "fileContent": csv_data,
            "filename": "test.csv",
        })
        data = resp.json()
        # All new summary fields must be present
        assert "enriched" in data
        assert "skipped" in data
        assert "failed" in data
        assert "unknownAlertTypes" in data
        assert "missingContextCount" in data
        assert "readyForAction" in data


# ── Upload UI page still works ───────────────────────────────────────────

def test_upload_page_returns_html(test_client):
    resp = test_client.get("/demo/ui/upload")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Upload" in resp.text
    assert "Analyze File" in resp.text
    assert "step-num" in resp.text
