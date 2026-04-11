"""Audit event logging for security-relevant operations."""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import Session

from backend.app.db.models import AuditEvent

_log = logging.getLogger(__name__)


def log_audit(
    session: Session,
    tenant_id: str,
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str = "",
    details: dict[str, Any] | None = None,
) -> None:
    """Persist an audit event. Failures are logged but never propagated."""
    try:
        event = AuditEvent(
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id),
            details=details or {},
        )
        session.add(event)
        session.commit()
    except Exception:
        _log.exception("Failed to log audit event: %s %s", action, resource_id)
