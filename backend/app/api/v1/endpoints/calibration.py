"""Calibration feedback + signal telemetry dashboard endpoints (Phases 4-5).

Calibration feedback: POST/GET at /api/v1/calibration/
Telemetry dashboard: GET at /api/v1/telemetry/
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import select

from backend.app.core.auth import optional_tenant
from backend.app.core.db import get_session
from backend.app.db.models import (
    CalibrationFeedback,
    Case,
    CaseConfidenceSignal,
    SignalTelemetry,
)

router = APIRouter()


# ── Calibration Feedback ─────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    case_id: str
    analyst_verdict: str
    analyst: str | None = None
    notes: str | None = None


_VALID_VERDICTS = {"true_positive", "false_positive", "benign_true_positive"}


@router.post("/calibration/feedback")
def api_submit_feedback(
    req: FeedbackRequest,
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Submit analyst TP/FP verdict for a case to calibrate scoring accuracy."""
    if req.analyst_verdict not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=422,
            detail=f"analyst_verdict must be one of: {', '.join(sorted(_VALID_VERDICTS))}",
        )

    with get_session() as session:
        # Look up the case to pull alert_type and confidence
        try:
            case_uuid = UUID(req.case_id)
            case = session.get(Case, case_uuid)
        except (ValueError, TypeError):
            case = None

        alert_type = case.alert_type if case else "unknown"
        confidence_score = case.confidence_score if case else 0

        signals_fired = []
        if case:
            stmt = select(CaseConfidenceSignal).where(
                CaseConfidenceSignal.case_id == case_uuid)
            for sig in session.exec(stmt).all():
                signals_fired.append(sig.signal)

        fb = CalibrationFeedback(
            case_id=req.case_id,
            analyst_verdict=req.analyst_verdict,
            analyst=req.analyst,
            notes=req.notes,
            alert_type=alert_type,
            confidence_score=confidence_score,
            signals_fired=signals_fired,
        )
        session.add(fb)
        session.commit()
        session.refresh(fb)

    return {
        "id": fb.id,
        "case_id": fb.case_id,
        "analyst_verdict": fb.analyst_verdict,
        "alert_type": fb.alert_type,
        "confidence_score": fb.confidence_score,
        "created_at": fb.created_at.isoformat() if fb.created_at else None,
    }


@router.get("/calibration/stats")
def api_calibration_stats(
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Return precision, recall, FP rate, per alert type and per signal."""
    with get_session() as session:
        stmt = select(CalibrationFeedback)
        feedbacks = session.exec(stmt).all()

    if not feedbacks:
        return {
            "total_feedback": 0,
            "precision": None,
            "false_positive_rate": None,
            "by_alert_type": {},
            "by_signal": {},
        }

    total = len(feedbacks)
    tp_count = sum(1 for f in feedbacks if f.analyst_verdict == "true_positive")
    fp_count = sum(1 for f in feedbacks if f.analyst_verdict == "false_positive")
    btp_count = sum(1 for f in feedbacks if f.analyst_verdict == "benign_true_positive")

    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else None
    fp_rate = fp_count / total if total > 0 else None

    by_type: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "btp": 0, "total": 0})
    for f in feedbacks:
        bucket = by_type[f.alert_type]
        bucket["total"] += 1
        if f.analyst_verdict == "true_positive":
            bucket["tp"] += 1
        elif f.analyst_verdict == "false_positive":
            bucket["fp"] += 1
        else:
            bucket["btp"] += 1

    by_type_stats: dict[str, Any] = {}
    for atype, counts in by_type.items():
        tp_fp = counts["tp"] + counts["fp"]
        by_type_stats[atype] = {
            **counts,
            "precision": counts["tp"] / tp_fp if tp_fp > 0 else None,
            "fp_rate": counts["fp"] / counts["total"] if counts["total"] > 0 else None,
        }

    signal_tp: dict[str, int] = defaultdict(int)
    signal_fp: dict[str, int] = defaultdict(int)
    for f in feedbacks:
        for sig_name in f.signals_fired or []:
            if f.analyst_verdict == "true_positive":
                signal_tp[sig_name] += 1
            elif f.analyst_verdict == "false_positive":
                signal_fp[sig_name] += 1

    all_signals = set(signal_tp.keys()) | set(signal_fp.keys())
    by_signal: dict[str, Any] = {}
    for sig in sorted(all_signals):
        tp_s = signal_tp.get(sig, 0)
        fp_s = signal_fp.get(sig, 0)
        total_s = tp_s + fp_s
        by_signal[sig] = {
            "tp_count": tp_s,
            "fp_count": fp_s,
            "precision": tp_s / total_s if total_s > 0 else None,
        }

    return {
        "total_feedback": total,
        "true_positives": tp_count,
        "false_positives": fp_count,
        "benign_true_positives": btp_count,
        "precision": round(precision, 4) if precision is not None else None,
        "false_positive_rate": round(fp_rate, 4) if fp_rate is not None else None,
        "by_alert_type": by_type_stats,
        "by_signal": by_signal,
    }


# ── Telemetry Dashboard ──────────────────────────────────────────────

@router.get("/telemetry/dashboard")
def api_telemetry_dashboard(
    window_hours: int = Query(24, ge=1, le=720),
    auth_tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Return signal telemetry analytics: frequency, effectiveness, weight impact."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    with get_session() as session:
        stmt = select(SignalTelemetry).where(SignalTelemetry.created_at >= cutoff)
        records = session.exec(stmt).all()

    if not records:
        return {
            "window_hours": window_hours,
            "total_enrichments": 0,
            "signal_frequency": {},
            "avg_confidence": None,
            "score_distribution": {},
            "alert_type_distribution": {},
            "asset_tier_distribution": {},
            "user_risk_distribution": {},
            "top_signals_by_impact": [],
        }

    total = len(records)

    signal_freq: dict[str, int] = defaultdict(int)
    for r in records:
        for sig in r.signals_fired or []:
            signal_freq[sig] += 1

    avg_conf = sum(r.confidence_score for r in records) / total

    score_dist: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in records:
        if r.confidence_score >= 85:
            score_dist["critical"] += 1
        elif r.confidence_score >= 60:
            score_dist["high"] += 1
        elif r.confidence_score >= 35:
            score_dist["medium"] += 1
        else:
            score_dist["low"] += 1

    type_dist: dict[str, int] = defaultdict(int)
    for r in records:
        type_dist[r.alert_type] += 1

    asset_dist: dict[str, int] = defaultdict(int)
    for r in records:
        asset_dist[r.asset_tier] += 1

    user_dist: dict[str, int] = defaultdict(int)
    for r in records:
        user_dist[r.user_risk_tier] += 1

    from backend.app.services.enrichment.weights import get_weight
    signal_impact: dict[str, int] = defaultdict(int)
    for sig_name, freq in signal_freq.items():
        w = get_weight(sig_name)
        signal_impact[sig_name] = w * freq
    top_by_impact = sorted(
        [{"signal": k, "weight": get_weight(k), "fire_count": signal_freq[k],
          "total_impact": v}
         for k, v in signal_impact.items()],
        key=lambda x: abs(x["total_impact"]), reverse=True,
    )[:20]

    cross_alerts_total = sum(1 for r in records if r.cross_alert_flags)

    return {
        "window_hours": window_hours,
        "total_enrichments": total,
        "avg_confidence": round(avg_conf, 1),
        "score_distribution": score_dist,
        "alert_type_distribution": dict(type_dist),
        "asset_tier_distribution": dict(asset_dist),
        "user_risk_distribution": dict(user_dist),
        "signal_frequency": dict(sorted(signal_freq.items(), key=lambda x: -x[1])),
        "top_signals_by_impact": top_by_impact,
        "cross_alert_enrichments": cross_alerts_total,
        "cross_alert_rate": round(cross_alerts_total / total, 4) if total > 0 else 0,
    }
