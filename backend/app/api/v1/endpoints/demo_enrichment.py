"""Demo API — Enrichment, investigation, and calibration routes.

Handles single-alert enrichment, paste-anything parsing, live feed,
side-by-side comparison, IOC investigation, and calibration feedback.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from backend.app.core.auth import optional_tenant
from backend.app.core.db import get_session
from backend.app.db.models import CalibrationFeedback
from backend.app.schemas.case_v0_2 import Customer, Source
from backend.app.schemas.requests import CreateCaseRequest, EnrichRawRequest
from backend.app.services.alert_mapper import map_row_to_raw_alert, parse_severity
from backend.app.services.case_service import create_case
from backend.app.services.comparison import compare_enrichments
from backend.app.services.enrichment import enrich_debug
from backend.app.services.ioc_investigator import investigate_ioc
from backend.app.services.live_feed import generate_feed
from backend.app.services.normalizer import normalize_case_from_request
from backend.app.services.paste_parser import parse_any

router = APIRouter()


@router.post("/enrich-raw")
def api_enrich_raw(
    req: EnrichRawRequest,
    includeDebug: bool = Query(False),
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Accept a raw alert, run enrichment, return the case.v0.2 payload."""
    severity = req.severity or "medium"
    event_time = req.eventTime or datetime.now(timezone.utc)
    tenant_id = auth_tenant
    source = req.source or Source(
        sourceSystem="custom",
        sourceName="demo_enrich_raw",
        sourceAlertId=f"{req.alertType}:enrich-raw",
        sourceSeverity=severity,
    )

    try:
        case = normalize_case_from_request(
            tenant={"tenantId": tenant_id, **req.customer.model_dump()},
            source=source.model_dump(),
            alert_type=req.alertType,
            title=req.title,
            description=req.description,
            severity=severity,
            event_time=event_time,
            raw_alert=req.rawAlert,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    if req.persist:
        with get_session() as session:
            try:
                create_req = CreateCaseRequest(
                    tenantId=tenant_id,
                    customer=req.customer,
                    alertType=req.alertType,
                    source=source,
                    rawAlert=req.rawAlert,
                    severity=severity,
                    eventTime=event_time,
                    title=req.title,
                    description=req.description,
                )
                case = create_case(session, create_req)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=str(e)) from e

    case_json = case.model_dump(mode="json")

    if not includeDebug:
        return case_json

    debug = enrich_debug(req.alertType, severity, req.rawAlert, event_time)
    return {
        "rawInput": req.rawAlert,
        "alertType": req.alertType,
        "severity": severity,
        "derivedSignals": [
            {
                "signal": s.name,
                "weight": s.weight,
                "fired": s.fired,
                "label": s.label,
            }
            for s in debug.all_signals
        ],
        "scoreBreakdown": {
            "severityBase": debug.severity_base,
            "signalBoost": debug.signal_boost,
            "finalScore": debug.result.confidence_score,
            "label": debug.result.confidence_label,
        },
        "confidence": {
            "score": debug.result.confidence_score,
            "label": debug.result.confidence_label,
            "explanation": debug.result.confidence_explanation,
        },
        "recommendedPlaybook": debug.result.recommended_playbook,
        "recommendedActions": debug.result.recommended_actions,
        "enrichmentNotes": debug.result.enrichment_notes,
        "finalCase": case_json,
    }


class PasteRequest(BaseModel):
    text: str
    persist: bool = False


@router.post("/paste")
def api_paste_anything(
    req: PasteRequest,
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Accept any text — JSON, CSV, key=value, syslog, raw text — and
    auto-detect format, alert type, then enrich into a full case."""
    parsed = parse_any(req.text)

    if parsed.format == "empty":
        raise HTTPException(status_code=422, detail="Empty input")

    alert_type, raw_alert = map_row_to_raw_alert(parsed.data)
    severity = parse_severity(parsed.data)
    event_time = datetime.now(timezone.utc)

    paste_id = f"paste:{hash(req.text) % 100000}"
    try:
        case = normalize_case_from_request(
            tenant={"tenantId": auth_tenant, "name": "Paste Customer"},
            source={
                "sourceSystem": "custom",
                "sourceName": "paste_anything",
                "sourceAlertId": paste_id,
                "sourceSeverity": severity,
            },
            alert_type=alert_type,
            title=None,
            description=None,
            severity=severity,
            event_time=event_time,
            raw_alert=raw_alert,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e

    if req.persist:
        with get_session() as session:
            try:
                create_req = CreateCaseRequest(
                    tenantId=auth_tenant,
                    customer=Customer(name="Paste Customer"),
                    alertType=alert_type,
                    source=Source(
                        sourceSystem="custom",
                        sourceName="paste_anything",
                        sourceAlertId=paste_id,
                        sourceSeverity=severity,
                    ),
                    rawAlert=raw_alert,
                    severity=severity,
                    eventTime=event_time,
                )
                case = create_case(session, create_req)
            except ValueError as e:
                raise HTTPException(status_code=422, detail=str(e)) from e

    debug = enrich_debug(alert_type, severity, raw_alert, event_time)
    case_json = case.model_dump(mode="json")

    return {
        "detection": {
            "inputFormat": parsed.format,
            "inputConfidence": parsed.confidence,
            "detectedAlertType": alert_type,
            "detectedSeverity": severity,
            "fieldsExtracted": len(parsed.data),
            "notes": parsed.notes,
            "extractedFields": {
                k: v for k, v in list(parsed.data.items())[:20]
                if not isinstance(v, (dict, list))
            },
        },
        "rawInput": req.text[:2000],
        "alertType": alert_type,
        "severity": severity,
        "derivedSignals": [
            {
                "signal": s.name,
                "weight": s.weight,
                "fired": s.fired,
                "label": s.label,
            }
            for s in debug.all_signals
        ],
        "scoreBreakdown": {
            "severityBase": debug.severity_base,
            "signalBoost": debug.signal_boost,
            "finalScore": debug.result.confidence_score,
            "label": debug.result.confidence_label,
        },
        "confidence": {
            "score": debug.result.confidence_score,
            "label": debug.result.confidence_label,
            "explanation": debug.result.confidence_explanation,
        },
        "recommendedPlaybook": debug.result.recommended_playbook,
        "recommendedActions": debug.result.recommended_actions,
        "enrichmentNotes": debug.result.enrichment_notes,
        "finalCase": case_json,
    }


@router.get("/live-feed")
def api_live_feed() -> list[dict[str, Any]]:
    """Return enrichment results for all sample alerts, ready for animated feed."""
    return generate_feed()


class CompareRequest(BaseModel):
    textA: str
    textB: str


@router.post("/compare")
def api_compare(
    req: CompareRequest,
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Enrich two alerts side by side and return a structured comparison."""
    if not req.textA.strip() or not req.textB.strip():
        raise HTTPException(status_code=422, detail="Both inputs must be non-empty")
    return compare_enrichments(req.textA, req.textB, tenant_id=auth_tenant)


@router.get("/investigate")
def api_investigate_ioc(
    q: str = Query(..., min_length=1, description="IOC to search for"),
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Search all ingested cases for an IOC and return an investigation dossier."""
    with get_session() as session:
        return investigate_ioc(session, q.strip(), tenant_id=auth_tenant)


# ---------------------------------------------------------------------------
# Confidence calibration (Phase 4)
# ---------------------------------------------------------------------------

class CalibrationFeedbackRequest(BaseModel):
    case_id: str
    analyst_verdict: str
    confidence_score: int = 0
    signals_fired: list[str] = []
    alert_type: str = "unknown"
    notes: str | None = None
    submitted_by: str | None = None


@router.post("/calibration/feedback")
def api_calibration_feedback(
    req: CalibrationFeedbackRequest,
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Record analyst feedback on enrichment accuracy for calibration."""
    if req.analyst_verdict not in ("true_positive", "false_positive", "benign_true_positive"):
        raise HTTPException(status_code=422, detail="analyst_verdict must be: true_positive, false_positive, or benign_true_positive")

    with get_session() as session:
        fb = CalibrationFeedback(
            case_id=req.case_id,
            alert_type=req.alert_type,
            analyst_verdict=req.analyst_verdict,
            confidence_score=req.confidence_score,
            signals_fired=req.signals_fired,
            notes=req.notes,
            submitted_by=req.submitted_by,
        )
        session.add(fb)
        session.commit()
        session.refresh(fb)

    return {
        "id": fb.id,
        "case_id": fb.case_id,
        "verdict": fb.analyst_verdict,
        "recorded": True,
    }


@router.get("/calibration/stats")
def api_calibration_stats(
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Return precision, recall, FP rate from analyst calibration feedback."""
    from sqlmodel import select
    with get_session() as session:
        feedbacks = session.exec(select(CalibrationFeedback)).all()

    if not feedbacks:
        return {
            "totalFeedback": 0,
            "precision": None,
            "falsePositiveRate": None,
            "byAlertType": {},
            "bySignal": {},
        }

    total = len(feedbacks)
    tp = sum(1 for f in feedbacks if f.analyst_verdict == "true_positive")
    fp = sum(1 for f in feedbacks if f.analyst_verdict == "false_positive")
    btp = sum(1 for f in feedbacks if f.analyst_verdict == "benign_true_positive")

    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    fp_rate = fp / total if total > 0 else None

    by_type: dict[str, dict[str, Any]] = {}
    for f in feedbacks:
        at = f.alert_type
        if at not in by_type:
            by_type[at] = {"total": 0, "tp": 0, "fp": 0, "btp": 0}
        by_type[at]["total"] += 1
        if f.analyst_verdict == "true_positive":
            by_type[at]["tp"] += 1
        elif f.analyst_verdict == "false_positive":
            by_type[at]["fp"] += 1
        else:
            by_type[at]["btp"] += 1

    for at, stats in by_type.items():
        t, f_ = stats["tp"], stats["fp"]
        stats["precision"] = t / (t + f_) if (t + f_) > 0 else None
        stats["fpRate"] = f_ / stats["total"] if stats["total"] > 0 else None

    by_signal: dict[str, dict[str, int]] = {}
    for f in feedbacks:
        for sig in (f.signals_fired or []):
            if sig not in by_signal:
                by_signal[sig] = {"tp": 0, "fp": 0, "btp": 0, "total": 0}
            by_signal[sig]["total"] += 1
            if f.analyst_verdict == "true_positive":
                by_signal[sig]["tp"] += 1
            elif f.analyst_verdict == "false_positive":
                by_signal[sig]["fp"] += 1
            else:
                by_signal[sig]["btp"] += 1

    return {
        "totalFeedback": total,
        "truePositives": tp,
        "falsePositives": fp,
        "benignTruePositives": btp,
        "precision": round(precision, 4) if precision is not None else None,
        "falsePositiveRate": round(fp_rate, 4) if fp_rate is not None else None,
        "byAlertType": by_type,
        "bySignal": by_signal,
    }
