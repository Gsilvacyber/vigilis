"""Admin endpoints for API key management.

Requires admin role for all operations.
"""
from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel
from sqlmodel import select

from backend.app.core.auth import require_admin, _hash_key, _resolve_key_prefix
from backend.app.core.audit import log_audit
from backend.app.core.db import get_session
from backend.app.db.models import ApiKey, AuditEvent

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
