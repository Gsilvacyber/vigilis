"""Dev-only helper to seed random dispositions on open cases.

The calibration learning loop (backend/app/services/calibration.py) needs
dispositioned cases to compute FP/TP rates. In demo/dev environments there
are no analyst dispositions, so the calibration UI would render empty.

This endpoint picks N random open cases and assigns dispositions using a
realistic mix of {true_positive, benign, escalated}, then invokes the normal
update_disposition service path so all side effects fire (disposition events,
audit log, WebSocket broadcast, time-to-first-decision computation).

GUARDED by APP_ENV != "prod" — never runs in production regardless of tenant.
"""
from __future__ import annotations

import logging
import random
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import select

from backend.app.core.auth import optional_tenant
from backend.app.core.config import settings
from backend.app.core.db import get_session
from backend.app.db.models import Case as CaseRow, Tenant as TenantRow
from backend.app.services.case_service import update_disposition

_log = logging.getLogger(__name__)

router = APIRouter()

# Statuses from schemas/case_v0_2.py::DispositionStatus Literal.
# true_positive + escalated count as POSITIVE in calibration.py (_POSITIVE set).
# benign counts as NEGATIVE in calibration.py (_NEGATIVE set).
# The mix below produces ~60% positive / 40% negative so the learning loop
# has a realistic spread of signals to reduce and boost.
_TP = "true_positive"
_BENIGN = "benign"
_ESCALATED = "escalated"


@router.post("/seed-dispositions")
def seed_dispositions(
    count: int = Query(100, ge=1, le=500,
                       description="Number of cases to disposition"),
    tp_ratio: float = Query(0.40, ge=0.0, le=1.0,
                            description="Fraction assigned true_positive"),
    benign_ratio: float = Query(0.40, ge=0.0, le=1.0,
                                description="Fraction assigned benign"),
    escalated_ratio: float = Query(0.20, ge=0.0, le=1.0,
                                   description="Fraction assigned escalated"),
    tenant: str = Depends(optional_tenant),
) -> dict[str, Any]:
    """Seed N random open cases with dispositions for calibration testing.

    Returns counts of each disposition applied and any errors encountered.
    Ratios are normalized to sum to 1.0.
    """
    if settings.app_env == "prod":
        raise HTTPException(
            status_code=403,
            detail="seed-dispositions is disabled in production",
        )

    total = tp_ratio + benign_ratio + escalated_ratio
    if total <= 0:
        raise HTTPException(
            status_code=422,
            detail="at least one ratio must be > 0",
        )
    # Normalize so the 3 weights sum to 1.0
    weights = [tp_ratio / total, benign_ratio / total, escalated_ratio / total]
    statuses = [_TP, _BENIGN, _ESCALATED]

    counts = {
        "true_positive": 0,
        "benign": 0,
        "escalated": 0,
        "errors": 0,
    }

    with get_session() as session:
        # Resolve tenant UUID from tenant_id string (the cases table uses UUID FK).
        # If the tenant doesn't exist, treat it like an empty pool — no cases
        # to disposition is a success, not an error.
        t = session.exec(
            select(TenantRow).where(TenantRow.tenant_id == tenant)
        ).first()
        if not t:
            return {
                **counts,
                "total_processed": 0,
                "message": f"tenant {tenant!r} has no cases — seed pool is empty",
            }

        # Over-fetch so random.sample can pick a diverse subset
        candidates = session.exec(
            select(CaseRow)
            .where(CaseRow.tenant_id == t.id)
            .where(CaseRow.disposition_status == "open")
            .limit(count * 3)
        ).all()

        if not candidates:
            return {
                **counts,
                "total_processed": 0,
                "message": "no open cases to seed — disposition pool is empty",
            }

        picked = random.sample(candidates, min(count, len(candidates)))

        for case in picked:
            status = random.choices(statuses, weights=weights, k=1)[0]
            try:
                update_disposition(
                    session,
                    case.id,  # UUID, not str
                    {
                        "status": status,
                        "setBy": "seed-helper",
                        "notes": "Seeded by /demo/seed-dispositions for calibration testing",
                    },
                    set_by="seed-helper",
                )
                counts[status] += 1
            except Exception as e:  # noqa: BLE001
                _log.warning(
                    "seed-dispositions failed for case %s: %s",
                    case.id, e,
                )
                counts["errors"] += 1

    return {
        **counts,
        "total_processed": counts[_TP] + counts[_BENIGN] + counts[_ESCALATED],
    }
