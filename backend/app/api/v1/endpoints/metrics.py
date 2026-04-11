from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.services.metrics_service import (
    compute_by_alert_type,
    compute_summary,
    compute_ttfd,
)

router = APIRouter(prefix="/metrics")


@router.get("/summary")
def api_metrics_summary(
    auth_tenant: str = Depends(require_tenant),
    tenantId: Optional[str] = Query(None, description="Ignored when API key present"),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
) -> dict[str, Any]:
    """Overall pilot metrics scoped to the authenticated tenant."""
    with get_session() as session:
        return compute_summary(session, tenant_id=auth_tenant, start=start, end=end)


@router.get("/ttfd")
def api_metrics_ttfd(
    auth_tenant: str = Depends(require_tenant),
    tenantId: Optional[str] = Query(None, description="Ignored when API key present"),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
) -> dict[str, Any]:
    """Time-to-first-decision metrics scoped to the authenticated tenant."""
    with get_session() as session:
        return compute_ttfd(session, tenant_id=auth_tenant, start=start, end=end)


@router.get("/by-alert-type")
def api_metrics_by_alert_type(
    auth_tenant: str = Depends(require_tenant),
    tenantId: Optional[str] = Query(None, description="Ignored when API key present"),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
) -> dict[str, Any]:
    """Per-alert-type breakdown scoped to the authenticated tenant."""
    with get_session() as session:
        return compute_by_alert_type(session, tenant_id=auth_tenant, start=start, end=end)


@router.get("/by-tenant/{tenant_id}")
def api_metrics_by_tenant(
    tenant_id: str,
    auth_tenant: str = Depends(require_tenant),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
) -> dict[str, Any]:
    """Summary metrics for a tenant.  Must match authenticated tenant."""
    if tenant_id != auth_tenant:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Access denied: tenant mismatch")
    with get_session() as session:
        return compute_summary(session, tenant_id=auth_tenant, start=start, end=end)
