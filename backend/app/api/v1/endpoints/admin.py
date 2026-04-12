"""Admin endpoints for API key management.

Requires admin role for all operations.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import select

from backend.app.core.auth import require_admin, _hash_key, _resolve_key_prefix
from backend.app.core.audit import log_audit
from backend.app.core.db import get_session
from backend.app.db.models import (
    ApiKey,
    AuditEvent,
    Case as CaseRow,
    Tenant as TenantRow,
)
from backend.app.services.case_service import reenrich_case

router = APIRouter(prefix="/admin")


class CreateApiKeyRequest(BaseModel):
    tenantId: str
    name: str = ""
    role: str = "analyst"


@router.post("/api-keys")
def api_create_key(
    req: CreateApiKeyRequest,
    auth_tenant: str = Depends(require_admin),
    x_api_key: str | None = Header(None),
) -> dict[str, Any]:
    """Generate a new API key for a tenant."""
    raw_key = f"sk-{secrets.token_urlsafe(32)}"
    hashed = _hash_key(raw_key)
    prefix = raw_key[:8]
    with get_session() as session:
        row = ApiKey(
            key_hash=hashed,
            key_prefix=prefix,
            tenant_id=req.tenantId,
            name=req.name,
            role=req.role,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        # Capture values before audit commit detaches the row
        result = {
            "key": raw_key,
            "tenantId": row.tenant_id,
            "name": row.name,
            "createdAt": row.created_at.isoformat(),
            "isActive": row.is_active,
        }
        row_id = str(row.id)
        log_audit(
            session,
            tenant_id=auth_tenant,
            actor=_resolve_key_prefix(x_api_key),
            action="key.created",
            resource_type="api_key",
            resource_id=row_id,
            details={"target_tenant": req.tenantId, "name": req.name, "role": req.role},
        )
    return result


@router.get("/api-keys")
def api_list_keys(
    auth_tenant: str = Depends(require_admin),
    x_api_key: str | None = Header(None),
) -> list[dict[str, Any]]:
    """List all API keys (key values are masked)."""
    with get_session() as session:
        rows = session.exec(select(ApiKey).order_by(ApiKey.created_at.desc())).all()
        # Capture values before audit commit detaches the rows
        result = [
            {
                "key": row.key_prefix + "...",
                "tenantId": row.tenant_id,
                "name": row.name,
                "createdAt": row.created_at.isoformat(),
                "isActive": row.is_active,
            }
            for row in rows
        ]
        log_audit(
            session,
            tenant_id=auth_tenant,
            actor=_resolve_key_prefix(x_api_key),
            action="key.listed",
            resource_type="api_key",
        )
    return result


@router.get("/admin/audit-log")
def api_audit_log(
    limit: int = Query(50, ge=1, le=500),
    action: str | None = Query(None),
    auth_tenant: str = Depends(require_admin),
) -> list[dict[str, Any]]:
    """Return recent audit events for the tenant."""
    with get_session() as session:
        stmt = (
            select(AuditEvent)
            .where(AuditEvent.tenant_id == auth_tenant)
            .order_by(AuditEvent.timestamp.desc())
            .limit(limit)
        )
        if action:
            stmt = stmt.where(AuditEvent.action == action)
        events = session.exec(stmt).all()
        return [
            {
                "timestamp": e.timestamp.isoformat(),
                "actor": e.actor,
                "action": e.action,
                "resourceType": e.resource_type,
                "resourceId": e.resource_id,
                "details": e.details,
            }
            for e in events
        ]


@router.post("/re-enrich")
def api_reenrich_cases(
    window_days: int = Query(14, ge=1, le=90,
                             description="Re-enrich cases created within the last N days"),
    alert_type: str | None = Query(None,
                                   description="Optional: filter to a single alertType"),
    max_count: int = Query(500, ge=1, le=5000,
                           description="Maximum number of cases to re-enrich in one call"),
    auth_tenant: str = Depends(require_admin),
) -> dict[str, Any]:
    """Re-run enrichment on existing cases in-place.

    Applies current signal logic to historical cases so that recent fixes
    (e.g. the Day 6 repeat_offender noise-floor removal) take effect
    immediately instead of waiting for natural case turnover.

    PRESERVES: disposition_status, disposition_set_by, disposition_set_at,
    time_to_first_decision_ms, created_at, event_time, ingested_time.
    Also skips entity-graph relationship storage to avoid double-counting.

    Returns aggregate stats including the average score before/after and
    the delta, so you can see at a glance whether the signal changes moved
    the needle in the expected direction.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    # First pass: collect case IDs scoped to the admin's tenant
    with get_session() as session:
        tenant = session.exec(
            select(TenantRow).where(TenantRow.tenant_id == auth_tenant)
        ).first()
        if tenant is None:
            raise HTTPException(404, f"tenant {auth_tenant!r} not found")

        stmt = (
            select(CaseRow)
            .where(CaseRow.tenant_id == tenant.id)
            .where(CaseRow.created_at >= cutoff)
        )
        if alert_type:
            stmt = stmt.where(CaseRow.alert_type == alert_type)
        stmt = stmt.limit(max_count)

        cases = session.exec(stmt).all()
        case_ids = [c.id for c in cases]

    # Second pass: re-enrich each case in its own transaction so a single
    # failure doesn't abort the whole batch
    processed = 0
    updated = 0
    errors = 0
    total_old = 0
    total_new = 0
    score_increases = 0
    score_decreases = 0
    for cid in case_ids:
        processed += 1
        with get_session() as sub_session:
            result = reenrich_case(
                sub_session, cid, set_by=f"admin:{auth_tenant}",
            )
        if result.get("success"):
            updated += 1
            old = int(result.get("oldScore", 0) or 0)
            new = int(result.get("newScore", 0) or 0)
            total_old += old
            total_new += new
            if new > old:
                score_increases += 1
            elif new < old:
                score_decreases += 1
        else:
            errors += 1

    avg_old = round(total_old / updated, 1) if updated else 0.0
    avg_new = round(total_new / updated, 1) if updated else 0.0
    return {
        "processed": processed,
        "updated": updated,
        "errors": errors,
        "window_days": window_days,
        "alert_type": alert_type,
        "max_count": max_count,
        "avg_score_before": avg_old,
        "avg_score_after": avg_new,
        "avg_delta": round(avg_new - avg_old, 1),
        "score_increases": score_increases,
        "score_decreases": score_decreases,
    }
