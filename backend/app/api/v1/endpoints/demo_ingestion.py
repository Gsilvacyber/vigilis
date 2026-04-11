"""Demo API — Ingestion and file upload routes.

Handles batch enrichment via JSON body, CSV/JSON file upload,
staged upload preview, and confirmed upload processing.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.app.core.auth import optional_tenant
from backend.app.core.db import get_session
from backend.app.schemas.case_v0_2 import Customer, Source
from backend.app.schemas.requests import CreateCaseRequest, ProcessUploadRequest
from backend.app.services.alert_mapper import extract_event_time, map_row_to_raw_alert, parse_severity
from backend.app.services.case_service import create_case
from backend.app.services.incident_service import auto_correlate_background
from backend.app.services.ingestion import build_preview, process_upload
from backend.app.services.normalizer import normalize_case_from_request

router = APIRouter()


# ---------------------------------------------------------------------------
# Batch enrichment (JSON body)
# ---------------------------------------------------------------------------

class BatchEnrichRequest(BaseModel):
    alerts: list[dict[str, Any]]
    alertType: str | None = None
    persist: bool = False
    grouping: bool = False


@router.post("/enrich-batch")
def api_enrich_batch(
    req: BatchEnrichRequest,
    auth_tenant: str = Depends(optional_tenant),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> dict[str, Any]:
    """Process multiple alerts through the enrichment engine at once."""
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    score_sum = 0
    label_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}

    for i, row in enumerate(req.alerts[:2000]):
        try:
            alert_type, raw_alert = map_row_to_raw_alert(row, req.alertType)
            severity = parse_severity(row)
            event_time = extract_event_time(row) or datetime.now(timezone.utc)

            case = normalize_case_from_request(
                tenant={"tenantId": auth_tenant, "name": "Upload Customer"},
                source={"sourceSystem": "custom", "sourceName": "batch_upload",
                         "sourceAlertId": f"batch:{i}", "sourceSeverity": severity},
                alert_type=alert_type, title=None, description=None,
                severity=severity, event_time=event_time, raw_alert=raw_alert,
            )

            if req.persist:
                with get_session() as session:
                    create_req = CreateCaseRequest(
                        tenantId=auth_tenant,
                        customer=Customer(name="Upload Customer"),
                        alertType=alert_type,
                        source=Source(sourceSystem="custom", sourceName="batch_upload",
                                      sourceAlertId=f"batch:{i}", sourceSeverity=severity),
                        rawAlert=raw_alert, severity=severity, eventTime=event_time,
                    )
                    case = create_case(session, create_req)

            case_json = case.model_dump(mode="json")
            score = case_json.get("confidence", {}).get("score", 0)
            label = case_json.get("confidence", {}).get("label", "low")
            score_sum += score
            label_counts[label] = label_counts.get(label, 0) + 1
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1

            results.append({
                "index": i,
                "alertType": alert_type,
                "severity": severity,
                "score": score,
                "label": label,
                "signalsFired": len(case_json.get("confidence", {}).get("explanation", [])),
                "readyForAction": (case_json.get("enrichment", {}).get("caseReadiness", {}) or {}).get("readyForAction", False),
                "caseId": case_json.get("caseId"),
            })
        except Exception as e:
            errors.append({"index": i, "error": str(e)})

    total = len(results)

    if req.persist:
        background_tasks.add_task(auto_correlate_background, auth_tenant)

    return {
        "processed": total,
        "errors": len(errors),
        "errorDetails": errors[:10],
        "avgScore": round(score_sum / total, 1) if total else 0,
        "labelDistribution": label_counts,
        "alertTypeDistribution": type_counts,
        "readyForAction": sum(1 for r in results if r["readyForAction"]),
        "results": results,
    }


# ---------------------------------------------------------------------------
# File upload (CSV / JSON)
# ---------------------------------------------------------------------------

@router.post("/upload")
async def api_upload_file(
    file: UploadFile = File(...),
    alertType: str | None = Query(None),
    persist: bool = Query(False),
    grouping: bool = Query(False),
    auth_tenant: str = Depends(optional_tenant),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> dict[str, Any]:
    """Accept a CSV or JSON file, auto-map fields, and enrich all rows.

    When grouping=True, related alerts are merged into incident cases
    using category-aware composite keys (SOC mode).
    """
    content = (await file.read()).decode("utf-8", errors="replace")
    filename = (file.filename or "").lower()

    # If grouping is enabled, use the full ingestion pipeline
    if grouping:
        result = process_upload(
            content=content,
            filename=file.filename or filename,
            tenant_id=auth_tenant,
            alert_type_override=alertType,
            persist=persist,
            grouping=True,
        )
        if persist:
            background_tasks.add_task(auto_correlate_background, auth_tenant)
        return {
            "processed": result.processed,
            "enriched": result.enriched,
            "skipped": result.skipped,
            "failed": result.failed,
            "errors": result.errors,
            "avgScore": result.avg_score,
            "labelDistribution": result.label_distribution,
            "alertTypeDistribution": result.alert_type_distribution,
            "readyForAction": result.ready_for_action,
            "groupingEnabled": True,
            "caseCount": result.case_count,
            "groups": result.groups,
            "results": sorted(result.results, key=lambda r: r["index"]),
        }

    rows: list[dict[str, Any]] = []
    if filename.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(content))
        rows = [dict(r) for r in reader]
    elif filename.endswith(".json") or filename.endswith(".jsonl"):
        stripped = content.strip()
        if stripped.startswith("["):
            rows = json.loads(stripped)
        else:
            for line in stripped.splitlines():
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    else:
        try:
            parsed = json.loads(content)
            rows = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            reader = csv.DictReader(io.StringIO(content))
            rows = [dict(r) for r in reader]

    if not rows:
        raise HTTPException(status_code=422, detail="No rows found in uploaded file")
    if len(rows) > 2000:
        rows = rows[:2000]

    # Large persisted uploads run in a background job
    if persist and len(rows) > 50:
        from backend.app.services.job_manager import get_job_manager

        _content = content
        _filename = file.filename or filename
        _tenant = auth_tenant
        _alert_type = alertType

        def _background_upload(job_record=None):  # type: ignore[no-untyped-def]
            result = process_upload(
                content=_content,
                filename=_filename,
                tenant_id=_tenant,
                alert_type_override=_alert_type,
                persist=True,
                grouping=False,
            )
            if job_record:
                job_record.progress = 100
                job_record.message = f"Processed {result.processed} alerts"
            return {
                "processed": result.processed,
                "enriched": result.enriched,
                "caseCount": result.case_count,
            }

        job_id = get_job_manager().submit(auth_tenant, _background_upload)
        return JSONResponse(
            status_code=202,
            content={
                "status": "accepted",
                "jobId": job_id,
                "message": f"Processing {len(rows)} alerts in background",
            },
        )

    batch_req = BatchEnrichRequest(alerts=rows, alertType=alertType, persist=persist)
    if persist:
        background_tasks.add_task(auto_correlate_background, auth_tenant)
    return api_enrich_batch(batch_req, auth_tenant=auth_tenant)


# ---------------------------------------------------------------------------
# Staged upload: dry-run preview
# ---------------------------------------------------------------------------

@router.post("/upload/preview")
async def api_upload_preview(
    file: UploadFile = File(...),
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Parse and analyze a file without creating any cases.

    Returns column mappings, source profile detection, per-row validation,
    and a summary so the UI can show a confirmation step.
    """
    content = (await file.read()).decode("utf-8", errors="replace")
    filename = file.filename or "unknown"

    preview = build_preview(content, filename)

    if preview.total_rows == 0:
        raise HTTPException(status_code=422, detail="No rows found in uploaded file")

    return {
        "filename": preview.filename,
        "fileFormat": preview.file_format,
        "totalRows": preview.total_rows,
        "columns": preview.columns,
        "sourceProfile": {
            "detected": preview.source_profile.detected,
            "label": preview.source_profile.label,
            "confidence": preview.source_profile.confidence,
            "matchedFields": preview.source_profile.matched_fields,
        },
        "columnMappings": [
            {
                "sourceColumn": m.source_column,
                "canonicalField": m.canonical_field,
                "confidence": m.confidence,
                "reason": m.reason,
            }
            for m in preview.column_mappings
        ],
        "sampleRows": preview.sample_rows,
        "rowValidations": [
            {
                "index": v.index,
                "valid": v.valid,
                "reasons": v.reasons,
                "detectedAlertType": v.detected_alert_type,
                "detectedSeverity": v.detected_severity,
            }
            for v in preview.row_validations
        ],
        "summary": preview.summary,
    }


# ---------------------------------------------------------------------------
# Staged upload: process with confirmed / overridden mappings
# ---------------------------------------------------------------------------

@router.post("/upload/process")
def api_upload_process(
    req: ProcessUploadRequest,
    auth_tenant: str = Depends(optional_tenant),
    background_tasks: BackgroundTasks = BackgroundTasks(),
) -> dict[str, Any]:
    """Process a previously previewed file with optional mapping overrides."""
    try:
        result = process_upload(
        content=req.fileContent,
        filename=req.filename,
        tenant_id=auth_tenant,
        alert_type_override=req.alertType,
        column_overrides=req.columnOverrides,
        persist=req.persist,
        grouping=req.grouping,
    )
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to process file: {str(e)[:200]}")

    if req.persist:
        background_tasks.add_task(auto_correlate_background, auth_tenant)

    resp: dict[str, Any] = {
        "processed": result.processed,
        "enriched": result.enriched,
        "skipped": result.skipped,
        "failed": result.failed,
        "errors": result.errors,
        "avgScore": result.avg_score,
        "labelDistribution": result.label_distribution,
        "alertTypeDistribution": result.alert_type_distribution,
        "readyForAction": result.ready_for_action,
        "unknownAlertTypes": result.unknown_alert_types,
        "missingContextCount": result.missing_context_count,
        "groupingEnabled": result.grouping_enabled,
        "caseCount": result.case_count,
        "originalRowCount": result.original_row_count,
        "truncated": result.truncated,
        "results": sorted(result.results, key=lambda r: r["index"]),
    }
    if result.groups is not None:
        resp["groups"] = result.groups
    return resp
