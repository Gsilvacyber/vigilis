from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.services.incident_service import (
    correlate_incidents,
    generate_export_payload,
    get_incident_detail,
    list_incidents,
)

router = APIRouter(prefix="/incidents")


@router.get("")
def api_list_incidents(
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """List all correlated incidents for the authenticated tenant."""
    with get_session() as session:
        return list_incidents(session, tenant_id=auth_tenant)


@router.get("/{incident_id}")
def api_get_incident(
    incident_id: UUID,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Get full incident detail with attack timeline."""
    with get_session() as session:
        result = get_incident_detail(session, incident_id, tenant_id=auth_tenant)
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return result


@router.get("/{incident_id}/export")
def api_export_incident(
    incident_id: UUID,
    fmt: str = Query("slack", pattern="^(slack|json)$"),
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Export incident as a shareable Slack or JSON payload."""
    with get_session() as session:
        result = get_incident_detail(session, incident_id, tenant_id=auth_tenant)
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return generate_export_payload(result, fmt=fmt)


@router.post("/correlate")
def api_correlate_incidents(
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Trigger incident correlation analysis for the authenticated tenant."""
    with get_session() as session:
        incidents = correlate_incidents(session, tenant_id=auth_tenant)
        return {
            "incidentsFound": len(incidents),
            "incidents": incidents,
        }
