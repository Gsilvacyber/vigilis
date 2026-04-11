"""Calibration API — signal effectiveness reports from analyst feedback."""
from fastapi import APIRouter, Depends, Query

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.services.calibration import (
    get_calibration_report,
    get_weight_adjustments,
)

router = APIRouter(prefix="/calibration", tags=["calibration"])


@router.get("/report")
def api_calibration_report(
    window_days: int = Query(30, ge=7, le=365),
    auth_tenant: str = Depends(require_tenant),
):
    """Show signal effectiveness based on analyst feedback.

    Returns each signal's true/false positive rate, current weight,
    adjusted weight (from learning loop), and status (reduce/boost/stable).
    """
    with get_session() as session:
        report = get_calibration_report(session, auth_tenant, window_days)
    return {
        "windowDays": window_days,
        "signalCount": len(report),
        "signals": report,
    }


@router.get("/adjustments")
def api_weight_adjustments(
    window_days: int = Query(30, ge=7, le=365),
    auth_tenant: str = Depends(require_tenant),
):
    """Get active weight adjustments from the learning loop.

    Returns only signals whose weights have been adjusted (multiplier != 1.0).
    These adjustments are automatically applied during enrichment scoring.
    """
    with get_session() as session:
        adjustments = get_weight_adjustments(session, auth_tenant, window_days)
    return {
        "windowDays": window_days,
        "adjustedSignals": len(adjustments),
        "adjustments": {
            name: {"multiplier": round(mult, 2), "effect": "reduce" if mult < 1 else "boost"}
            for name, mult in adjustments.items()
        },
    }
