from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlmodel import select

from backend.app.core.auth import require_tenant
from backend.app.core.db import get_session
from backend.app.db.models import Case as CaseRow, Tenant as TenantRow, WebhookDelivery

router = APIRouter(prefix="/webhooks")


@router.get("/logs")
def api_webhook_logs(
    auth_tenant: str = Depends(require_tenant),
    limit: int = Query(50, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Return recent webhook delivery log entries for the authenticated tenant."""
    with get_session() as session:
        tenant_row = session.exec(
            select(TenantRow).where(TenantRow.tenant_id == auth_tenant)
        ).first()
        if tenant_row is None:
            return []

        case_ids_q = select(CaseRow.id).where(CaseRow.tenant_id == tenant_row.id)
        deliveries = session.exec(
            select(WebhookDelivery)
            .where(WebhookDelivery.case_id.in_(case_ids_q))  # type: ignore[arg-type]
            .order_by(WebhookDelivery.id.desc())
            .limit(limit)
        ).all()
        return [
            {
                "caseId": str(d.case_id),
                "target": d.webhook_url,
                "status": "delivered" if d.delivered else "failed",
                "statusCode": d.status_code,
                "deliveredAt": (
                    d.delivered_at.isoformat() if d.delivered_at else None
                ),
                "attemptNo": d.attempt_no,
                "error": d.error,
            }
            for d in deliveries
        ]
