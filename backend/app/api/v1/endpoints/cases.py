from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlmodel import Session, select

from backend.app.core.auth import require_tenant
from backend.app.core.config import settings
from backend.app.core.db import engine, get_session
from backend.app.db.models import (
    Case,
    CaseConfidenceSignal,
    CaseDispositionEvent,
    CaseNote,
    CaseSource,
    IncidentCaseLink,
    WebhookDelivery,
)
from backend.app.schemas.case_v0_2 import CaseV0_2
from backend.app.schemas.requests import (
    BulkDispositionRequest,
    CreateCaseRequest,
    CreateNoteRequest,
    DeliverWebhookRequest,
    PatchDispositionRequest,
)
from backend.app.services.case_service import (
    create_case,
    get_case,
    list_cases,
    update_disposition,
)
from backend.app.services.webhook_service import deliver_case_payload

router = APIRouter()


def db_session_dep() -> Session:
    return get_session()


def _check_tenant(case: CaseV0_2, auth_tenant: str) -> None:
    if case.tenantId != auth_tenant:
        raise HTTPException(status_code=403, detail="Access denied: case belongs to another tenant")


@router.post("/cases", response_model=CaseV0_2)
def api_create_case(
    req: CreateCaseRequest,
    auth_tenant: str = Depends(require_tenant),
) -> CaseV0_2:
    req.tenantId = auth_tenant
    with db_session_dep() as session:
        try:
            return create_case(session, req)
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e)) from e


@router.get("/cases", response_model=list[CaseV0_2])
def api_list_cases(
    auth_tenant: str = Depends(require_tenant),
    tenantId: str | None = Query(None, description="Ignored when API key present"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> list[CaseV0_2]:
    with db_session_dep() as session:
        return list_cases(session, tenant_id=auth_tenant, limit=limit, offset=offset)


@router.get("/cases/{case_id}", response_model=CaseV0_2)
def api_get_case(
    case_id: UUID,
    auth_tenant: str = Depends(require_tenant),
) -> CaseV0_2:
    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(case, auth_tenant)
        return case


@router.patch("/cases/{case_id}/disposition", response_model=CaseV0_2)
def api_patch_disposition(
    case_id: UUID,
    req: PatchDispositionRequest,
    auth_tenant: str = Depends(require_tenant),
) -> CaseV0_2:
    with db_session_dep() as session:
        existing = get_case(session, case_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(existing, auth_tenant)
        try:
            return update_disposition(session, case_id, req.model_dump(), set_by=None)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e


@router.post("/cases/bulk-disposition")
def api_bulk_disposition(
    req: BulkDispositionRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Update disposition for multiple cases at once."""
    updated = []
    errors = []
    with db_session_dep() as session:
        for case_id in req.caseIds:
            case = get_case(session, case_id)
            if case is None:
                errors.append({"caseId": str(case_id), "error": "not found"})
                continue
            if case.tenantId != auth_tenant:
                errors.append({"caseId": str(case_id), "error": "access denied"})
                continue
            try:
                update_disposition(
                    session,
                    case_id,
                    {"status": req.status, "setBy": req.setBy},
                    set_by=None,
                )
                updated.append(str(case_id))
            except ValueError as e:
                errors.append({"caseId": str(case_id), "error": str(e)})
    return {"updated": updated, "errors": errors, "count": len(updated)}


def _cascade_delete_cases(session: Session, case_ids: list[UUID]) -> dict[str, int]:
    """Cascade-delete rows for the given case IDs. Shared by single + bulk delete."""
    from sqlmodel import delete as _delete

    counts: dict[str, int] = {}
    for model, label in [
        (CaseSource, "sources"),
        (CaseConfidenceSignal, "signals"),
        (CaseDispositionEvent, "dispositionEvents"),
        (CaseNote, "notes"),
        (WebhookDelivery, "webhookDeliveries"),
        (IncidentCaseLink, "incidentLinks"),
    ]:
        stmt = _delete(model).where(model.case_id.in_(case_ids))
        result = session.exec(stmt)
        counts[label] = getattr(result, "rowcount", 0) or 0
    case_result = session.exec(_delete(Case).where(Case.id.in_(case_ids)))
    counts["cases"] = getattr(case_result, "rowcount", 0) or 0
    return counts


@router.delete("/cases/{case_id}")
def api_delete_case(
    case_id: UUID,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Delete a single case and all its child rows (sources, signals, notes, etc.)."""
    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        if case.tenantId != auth_tenant:
            raise HTTPException(status_code=403, detail="Access denied: case belongs to another tenant")
        counts = _cascade_delete_cases(session, [case_id])
        session.commit()
    return {"status": "deleted", "caseId": str(case_id), "cascade": counts}


class BulkDeleteRequest(BaseModel):
    caseIds: list[UUID]


@router.post("/cases/bulk-delete")
def api_bulk_delete(
    req: BulkDeleteRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Delete multiple cases at once, scoped to the authenticated tenant."""
    if not req.caseIds:
        return {"status": "ok", "deleted": 0, "cascade": {}, "skipped": 0}
    with db_session_dep() as session:
        # Tenant scoping: only delete cases owned by this tenant
        allowed_ids: list[UUID] = []
        skipped = 0
        for cid in req.caseIds:
            case = get_case(session, cid)
            if case is None or case.tenantId != auth_tenant:
                skipped += 1
                continue
            allowed_ids.append(cid)
        if not allowed_ids:
            return {"status": "ok", "deleted": 0, "cascade": {}, "skipped": skipped}
        counts = _cascade_delete_cases(session, allowed_ids)
        session.commit()
    return {
        "status": "ok",
        "deleted": len(allowed_ids),
        "cascade": counts,
        "skipped": skipped,
    }


@router.get("/cases/{case_id}/export")
def api_export_case(
    case_id: UUID,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    """Export a case in a clean, integration-friendly JSON format."""
    from datetime import datetime, timezone

    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(case, auth_tenant)

    return {
        "exportVersion": "1.0",
        "exportedAt": datetime.now(timezone.utc).isoformat(),
        "format": "case.v0.2",
        "case": case.model_dump(mode="json"),
    }


@router.post("/cases/{case_id}/deliver-webhook")
def api_deliver_webhook(
    case_id: UUID,
    req: DeliverWebhookRequest,
    background_tasks: BackgroundTasks,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(case, auth_tenant)

    resolved_url = req.webhookUrl or settings.webhook_default_url

    def _bg_deliver() -> None:
        with Session(engine) as bg_session:
            deliver_case_payload(
                session=bg_session,
                case_id=case_id,
                webhook_url=resolved_url,
                attempt_no=req.attemptNo,
            )

    background_tasks.add_task(_bg_deliver)
    return {"status": "scheduled"}


# ── Notes ────────────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/notes")
def api_list_notes(
    case_id: UUID,
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(case, auth_tenant)
        notes = session.exec(
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at.desc())
        ).all()
        return [
            {
                "id": n.id,
                "author": n.author,
                "content": n.content,
                "createdAt": n.created_at.isoformat() if n.created_at else None,
            }
            for n in notes
        ]


@router.post("/cases/{case_id}/notes")
def api_create_note(
    case_id: UUID,
    req: CreateNoteRequest,
    auth_tenant: str = Depends(require_tenant),
) -> dict[str, Any]:
    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(case, auth_tenant)
        note = CaseNote(case_id=case_id, author=req.author, content=req.content)
        session.add(note)
        session.commit()
        session.refresh(note)
        return {
            "id": note.id,
            "author": note.author,
            "content": note.content,
            "createdAt": note.created_at.isoformat() if note.created_at else None,
        }


# ── Timeline ─────────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/timeline")
def api_case_timeline(
    case_id: UUID,
    auth_tenant: str = Depends(require_tenant),
) -> list[dict[str, Any]]:
    """Aggregate all events for a case into a chronological timeline."""
    with db_session_dep() as session:
        case = get_case(session, case_id)
        if case is None:
            raise HTTPException(status_code=404, detail="Case not found")
        _check_tenant(case, auth_tenant)

        events: list[dict[str, Any]] = []

        # Case creation
        events.append({
            "type": "created",
            "icon": "plus",
            "title": f"Case created: {case.alertType}",
            "detail": case.title,
            "time": case.timestamps.ingestedTime.isoformat() if case.timestamps.ingestedTime else None,
        })

        # Enrichment
        if case.timestamps.enrichedTime:
            events.append({
                "type": "enriched",
                "icon": "zap",
                "title": f"Enriched — confidence {case.confidence.score}/100 ({case.confidence.label})",
                "detail": f"{len(case.confidence.explanation)} signals fired",
                "time": case.timestamps.enrichedTime.isoformat(),
            })

        # Disposition events
        disps = session.exec(
            select(CaseDispositionEvent)
            .where(CaseDispositionEvent.case_id == case_id)
            .order_by(CaseDispositionEvent.set_at)
        ).all()
        for d in disps:
            events.append({
                "type": "disposition",
                "icon": "gavel",
                "title": f"Disposition: {d.status}",
                "detail": f"by {d.set_by or 'system'}" + (f" — {d.notes}" if d.notes else ""),
                "time": d.set_at.isoformat() if d.set_at else None,
            })

        # Webhook deliveries
        whs = session.exec(
            select(WebhookDelivery)
            .where(WebhookDelivery.case_id == case_id)
            .order_by(WebhookDelivery.delivered_at)
        ).all()
        for w in whs:
            status = "delivered" if w.delivered else "failed"
            events.append({
                "type": "webhook",
                "icon": "send",
                "title": f"Webhook {status}",
                "detail": w.webhook_url,
                "time": w.delivered_at.isoformat() if w.delivered_at else None,
            })

        # Incident links
        links = session.exec(
            select(IncidentCaseLink)
            .where(IncidentCaseLink.case_id == case_id)
            .order_by(IncidentCaseLink.added_at)
        ).all()
        for lnk in links:
            events.append({
                "type": "incident",
                "icon": "chain",
                "title": f"Linked to incident ({lnk.kill_chain_stage})",
                "detail": str(lnk.incident_id),
                "time": lnk.added_at.isoformat() if lnk.added_at else None,
            })

        # Notes
        notes = session.exec(
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at)
        ).all()
        for n in notes:
            events.append({
                "type": "note",
                "icon": "pencil",
                "title": f"Note by {n.author}",
                "detail": n.content,
                "time": n.created_at.isoformat() if n.created_at else None,
            })

        # Sort chronologically
        events.sort(key=lambda e: e.get("time") or "")
        return events
