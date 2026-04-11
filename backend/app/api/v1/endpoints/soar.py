"""SOAR Action API — execute response actions from case context."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.app.core.auth import require_tenant, require_admin
from backend.app.services.integrations.soar import (
    execute_action,
    list_integrations,
    ActionResult,
)

router = APIRouter(prefix="/soar", tags=["soar"])


class ActionRequest(BaseModel):
    integration: str           # "crowdstrike", "okta", "servicenow"
    action: str                # "isolate_host", "suspend_user", "create_incident"
    target: str                # hostname, email, or ticket description
    reason: str = ""           # audit trail
    caseId: str | None = None  # link action to a case


@router.get("/integrations")
def api_list_integrations(
    auth_tenant: str = Depends(require_tenant),
):
    """List configured SOAR integrations."""
    return {"integrations": list_integrations()}


@router.post("/execute")
def api_execute_action(
    req: ActionRequest,
    auth_tenant: str = Depends(require_tenant),
):
    """Execute a SOAR response action.

    Examples:
      - Isolate endpoint: {"integration": "crowdstrike", "action": "isolate_host", "target": "FILE-SVR-03"}
      - Suspend user: {"integration": "okta", "action": "suspend_user", "target": "admin@acme.com"}
      - Create ticket: {"integration": "servicenow", "action": "create_incident", "target": "Ransomware detected on FILE-SVR-03"}
    """
    result = execute_action(req.integration, req.action, req.target, reason=req.reason)

    # Log to case audit trail if caseId provided
    if req.caseId and result.result == ActionResult.SUCCESS:
        try:
            from backend.app.core.db import get_session
            from backend.app.core.audit import log_audit
            with get_session() as session:
                log_audit(
                    session,
                    tenant_id=auth_tenant,
                    actor=f"soar:{req.integration}",
                    action=f"soar.{req.action}",
                    resource_type="case",
                    resource_id=req.caseId,
                    details={
                        "integration": req.integration,
                        "action": req.action,
                        "target": req.target,
                        "result": result.result.value,
                        "details": result.details,
                    },
                )
        except Exception:
            pass  # Audit logging is best-effort

    return {
        "action": result.action,
        "target": result.target,
        "result": result.result.value,
        "details": result.details,
        "vendor": result.vendor,
        "timestamp": result.timestamp.isoformat(),
    }
