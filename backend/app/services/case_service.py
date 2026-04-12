from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from sqlmodel import Session, select

from backend.app.db.models import (
    Case as CaseRow,
    CaseConfidenceSignal,
    CaseDispositionEvent,
    CaseSource,
    Tenant as TenantRow,
)
from backend.app.schemas.case_v0_2 import (
    Audit,
    BulkTarget,
    CaseV0_2,
    Confidence,
    ConfidenceSignal,
    Customer,
    Disposition,
    Enrichment,
    Entities,
    Outputs,
    Retention,
    Source,
    Timestamps,
)
from backend.app.schemas.requests import CreateCaseRequest, PatchDispositionRequest
from backend.app.services.normalizer import normalize_case_from_request
from backend.app.services.validation import validate_required_entities
from backend.app.services.ws_manager import ws_manager

_log = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_tz_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


SUPPORTED_ALERT_TYPES = {
    "identity.suspiciousSignIn",
    "identity.passwordSpray",
    "identity.mfaFatigue",
    "identity.oauthConsentRisk",
    "identity.privilegeElevation",
    "endpoint.malwareDetection",
    "endpoint.suspiciousProcess",
    "email.forwardingRule",
    "email.phishingDetected",
    "cloud.secretStoreAccessAnomaly",
    "cloud.iamPrivilegeEscalation",
    "cloud.suspiciousApiCall",
    "network.impossibleGeoAccess",
    "network.dataExfiltration",
    "identity.impossibleTravel",
    "identity.dormantAccountLogin",
    "identity.serviceAccountAbuse",
    "endpoint.ransomwareDetection",
    "endpoint.lateralMovement",
    "endpoint.credentialDumping",
    "endpoint.persistenceMechanism",
    "endpoint.defenseEvasion",
    "email.businessEmailCompromise",
    "email.maliciousAttachment",
    "network.commandAndControl",
    "network.portScan",
    "network.dnsAnomaly",
    "cloud.resourceHijacking",
    "cloud.dataExposure",
    "dlp.sensitiveDataExposure",
    # Phase 2 new alert types (Sysmon EIDs 10/17/18/19/20/21 + Security Log + PSBL)
    "identity.logonSuccess",
    "identity.accountCreation",
    "endpoint.powershellExecution",
    "endpoint.lsassAccess",
    "endpoint.pipeActivity",
    "endpoint.wmiPersistence",
    "endpoint.massFileCreate",
    # Phase 3 state drift
    "endpoint.stateDrift",
}


def create_case(session: Session, req: CreateCaseRequest) -> CaseV0_2:
    if req.alertType not in SUPPORTED_ALERT_TYPES:
        raise ValueError(f"Unsupported alertType: {req.alertType}")

    event_time = req.eventTime or _utc_now()
    severity = req.severity or req.source.sourceSeverity

    case = normalize_case_from_request(
        tenant={"tenantId": req.tenantId, **req.customer.model_dump()},
        source=req.source.model_dump(),
        alert_type=req.alertType,
        title=req.title,
        description=req.description,
        severity=severity,
        event_time=event_time,
        raw_alert=req.rawAlert,
    )

    # Graceful entity validation: if enrichment accepted it, we save it.
    # Missing entities get flagged but don't block persistence.
    try:
        validate_required_entities(case)
    except (ValueError, Exception):
        flags = case.enrichment.get("qualityFlags") if isinstance(case.enrichment, dict) else getattr(case.enrichment, "qualityFlags", None)
        if flags is None:
            flags = []
        if isinstance(case.enrichment, dict):
            case.enrichment.setdefault("qualityFlags", []).append("MISSING_ENTITIES")
        elif hasattr(case.enrichment, "qualityFlags"):
            if case.enrichment.qualityFlags is None:
                case.enrichment.qualityFlags = []
            case.enrichment.qualityFlags.append("MISSING_ENTITIES")

    tenant_row = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == req.tenantId)
    ).first()
    if tenant_row is None:
        tenant_row = TenantRow(
            tenant_id=req.tenantId,
            customer_name=req.customer.name,
            customer_environment=req.customer.environment,
            customer_industry=req.customer.industry,
        )
        session.add(tenant_row)
        session.commit()
        session.refresh(tenant_row)

    # Cross-upload dedup: if this exact source already exists, return the existing case
    if req.source:
        existing = _find_existing_case_by_source(
            session, req.tenantId,
            req.source.sourceSystem, req.source.sourceAlertId,
        )
        if existing is not None:
            _log.info("Case deduplicated: existing %s matches source %s", existing.caseId, req.source.sourceAlertId)
            return existing

    # Preserve the raw alert + original alert_type + severity in the audit
    # JSON so the re-enrichment endpoint can re-run enrichment cleanly.
    # Zero-migration approach: audit is already a JSON column.
    _audit_dict = case.audit.model_dump()
    if req.rawAlert:
        try:
            _audit_dict["_rawAlertPreserved"] = dict(req.rawAlert)
        except (TypeError, ValueError):
            # Best effort — if the raw alert can't be coerced to a dict,
            # fall back to model_dump on pydantic shapes
            _audit_dict["_rawAlertPreserved"] = (
                req.rawAlert.model_dump()
                if hasattr(req.rawAlert, "model_dump")
                else {}
            )
    _audit_dict["_originalAlertType"] = req.alertType
    _audit_dict["_originalSeverity"] = severity

    case_row = CaseRow(
        tenant_id=tenant_row.id,
        schema_version=case.schemaVersion,
        alert_type=case.alertType,
        title=case.title,
        description=case.description,
        severity=case.severity,
        event_time=case.timestamps.eventTime,
        ingested_time=case.timestamps.ingestedTime,
        enriched_time=case.timestamps.enrichedTime,
        confidence_score=case.confidence.score,
        confidence_label=case.confidence.label,
        entities=case.entities.model_dump(),
        enrichment=case.enrichment.model_dump(),
        recommended_playbook=case.recommendedPlaybook,
        recommended_actions=case.recommendedActions,
        outputs=case.outputs.model_dump(),
        audit=_audit_dict,
        bulk_target=case.bulkTarget.model_dump(),
        disposition_status=case.disposition.status,
        disposition_set_by=case.disposition.setBy,
        disposition_set_at=case.disposition.setAt,
        disposition_notes=case.disposition.notes,
        retention_store_mode=case.retention.storeMode,
        retention_ttl_days=case.retention.ttlDays,
        retention_redacted=case.retention.redacted,
        time_to_first_decision_ms=None,
    )

    session.add(case_row)
    session.commit()
    session.refresh(case_row)

    for s in case.sources:
        session.add(
            CaseSource(
                case_id=case_row.id,
                source_system=s.sourceSystem,
                source_name=s.sourceName,
                source_alert_id=s.sourceAlertId,
                source_severity=s.sourceSeverity,
                source_url=s.sourceUrl,
            )
        )

    for expl in case.confidence.explanation:
        session.add(
            CaseConfidenceSignal(
                case_id=case_row.id,
                signal=expl.signal,
                weight=expl.weight,
                label=getattr(expl, 'label', None),
                tier=getattr(expl, 'tier', None),
            )
        )

    session.commit()
    session.refresh(case_row)

    # Reconstruct from DB so returned caseId matches the persisted row
    result = get_case(session, case_row.id)
    assert result is not None

    # Broadcast new case event via WebSocket
    ws_manager.broadcast_sync({
        "type": "new_case",
        "caseId": str(result.caseId),
        "alertType": result.alertType,
        "severity": result.severity,
        "confidence": result.confidence.score,
    })

    _log.info("Case created: %s (type=%s)", result.caseId, result.alertType)

    # Audit log
    from backend.app.core.audit import log_audit
    try:
        log_audit(
            session,
            tenant_id=req.tenantId,
            actor="system",
            action="case.created",
            resource_type="case",
            resource_id=str(result.caseId),
            details={"alert_type": result.alertType, "severity": result.severity},
        )
    except Exception:
        _log.debug("Audit log for case.created failed (non-fatal)")

    # Entity graph: store relationships for this case (builds the detection brain)
    try:
        from backend.app.services.enrichment.entity_graph import extract_and_store_relationships
        raw_for_graph = dict(req.rawAlert) if req.rawAlert else {}
        # Merge in structured entities so the graph has identity/device/ips
        if result.entities:
            entity_dict = result.entities.model_dump() if hasattr(result.entities, 'model_dump') else result.entities
            raw_for_graph = {**raw_for_graph, **entity_dict}
        extract_and_store_relationships(
            raw_alert=raw_for_graph,
            case_id=case_row.id,
            tenant_id=req.tenantId,
        )
    except Exception:
        _log.debug("Entity graph storage failed (non-fatal)", exc_info=True)

    return result


def _find_existing_case(
    session: Session,
    tenant_db_id: UUID,
    alert_type: str,
    upn: str,
    event_time: datetime,
    window_minutes: int = 30,
) -> CaseRow | None:
    """Check for an existing case with same user + alert_type within a time window."""
    if not upn or upn in ("unknown@upload", "unknown"):
        return None
    window = timedelta(minutes=window_minutes)
    rows = session.exec(
        select(CaseRow).where(
            CaseRow.tenant_id == tenant_db_id,
            CaseRow.alert_type == alert_type,
            CaseRow.event_time >= event_time - window,
            CaseRow.event_time <= event_time + window,
        )
    ).all()
    for row in rows:
        ent = row.entities or {}
        identity = ent.get("identity") or {}
        row_upn = (identity.get("upn") or "").lower()
        if row_upn == upn.lower():
            return row
    return None


def _find_existing_case_by_source(
    session: Session,
    tenant_id: str,
    source_system: str,
    source_alert_id: str,
) -> CaseV0_2 | None:
    """Check for an existing case with this exact source alert (cross-upload dedup)."""
    if not source_alert_id or not source_system:
        return None
    row = session.exec(
        select(CaseSource)
        .join(CaseRow, CaseSource.case_id == CaseRow.id)
        .join(TenantRow, CaseRow.tenant_id == TenantRow.id)
        .where(
            TenantRow.tenant_id == tenant_id,
            CaseSource.source_system == source_system,
            CaseSource.source_alert_id == source_alert_id,
        )
    ).first()
    if row is None:
        return None
    return get_case(session, row.case_id)


def create_grouped_case(
    session: Session,
    case: CaseV0_2,
    tenant_id: str,
    alert_count: int,
    grouping_key: str,
    member_alert_indices: list[int],
) -> CaseV0_2:
    """Persist a pre-built grouped case (already enriched and assembled).

    Includes DB-level dedup: if a case with the same user + alert_type already
    exists within 30 minutes, returns the existing case instead of creating a
    duplicate.
    """
    if case.alertType not in SUPPORTED_ALERT_TYPES:
        raise ValueError(f"Unsupported alertType: {case.alertType}")

    tenant_row = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()
    if tenant_row is None:
        tenant_row = TenantRow(
            tenant_id=tenant_id,
            customer_name=case.customer.name,
            customer_environment=case.customer.environment,
            customer_industry=case.customer.industry,
        )
        session.add(tenant_row)
        session.commit()
        session.refresh(tenant_row)

    # Cross-upload dedup: if this exact source already exists, return the existing case
    if case.sources:
        src = case.sources[0]
        existing = _find_existing_case_by_source(
            session, tenant_id,
            src.sourceSystem, src.sourceAlertId,
        )
        if existing is not None:
            return existing

    # DB-level dedup check
    upn = ""
    if hasattr(case.entities, "identity") and case.entities.identity:
        ident = case.entities.identity
        upn = (ident.upn if hasattr(ident, "upn") else "") or ""
    existing = _find_existing_case(
        session, tenant_row.id, case.alertType, upn,
        case.timestamps.eventTime,
    )
    if existing:
        result = get_case(session, existing.id)
        if result is not None:
            return result

    case_row = CaseRow(
        tenant_id=tenant_row.id,
        schema_version=case.schemaVersion,
        alert_type=case.alertType,
        title=case.title,
        description=case.description,
        severity=case.severity,
        event_time=case.timestamps.eventTime,
        ingested_time=case.timestamps.ingestedTime,
        enriched_time=case.timestamps.enrichedTime,
        confidence_score=case.confidence.score,
        confidence_label=case.confidence.label,
        entities=case.entities.model_dump(),
        enrichment=case.enrichment.model_dump(),
        recommended_playbook=case.recommendedPlaybook,
        recommended_actions=case.recommendedActions,
        outputs=case.outputs.model_dump(),
        audit=case.audit.model_dump(),
        bulk_target=case.bulkTarget.model_dump(),
        disposition_status=case.disposition.status,
        alert_count=alert_count,
        grouping_key=grouping_key,
        member_alert_ids=member_alert_indices,
    )

    session.add(case_row)
    session.commit()
    session.refresh(case_row)

    for s in case.sources:
        session.add(
            CaseSource(
                case_id=case_row.id,
                source_system=s.sourceSystem,
                source_name=s.sourceName,
                source_alert_id=s.sourceAlertId,
                source_severity=s.sourceSeverity,
                source_url=s.sourceUrl,
            )
        )

    for expl in case.confidence.explanation:
        session.add(
            CaseConfidenceSignal(
                case_id=case_row.id,
                signal=expl.signal,
                weight=expl.weight,
                label=getattr(expl, 'label', None),
                tier=getattr(expl, 'tier', None),
            )
        )

    session.commit()
    session.refresh(case_row)

    result = get_case(session, case_row.id)
    assert result is not None
    _log.info("Grouped case created: %s (%d alerts)", result.caseId, alert_count)

    # Entity graph: store relationships for grouped case
    try:
        from backend.app.services.enrichment.entity_graph import extract_and_store_relationships
        raw_for_graph = case.enrichment if isinstance(case.enrichment, dict) else {}
        if result.entities:
            raw_for_graph = {**raw_for_graph, **result.entities}
        extract_and_store_relationships(
            raw_alert=raw_for_graph,
            case_id=case_row.id,
            tenant_id=case.tenantId if hasattr(case, 'tenantId') else None,
        )
    except Exception:
        _log.debug("Entity graph storage for grouped case failed (non-fatal)")

    return result


def get_case(session: Session, case_id: UUID) -> Optional[CaseV0_2]:
    row = session.exec(select(CaseRow).where(CaseRow.id == case_id)).first()
    if row is None:
        return None

    sources = session.exec(
        select(CaseSource).where(CaseSource.case_id == row.id)
    ).all()
    signals = session.exec(
        select(CaseConfidenceSignal).where(CaseConfidenceSignal.case_id == row.id)
    ).all()

    tenant = session.exec(
        select(TenantRow).where(TenantRow.id == row.tenant_id)
    ).first()

    tenant_customer = Customer(
        name=tenant.customer_name,
        environment=tenant.customer_environment,
        industry=tenant.customer_industry,
    )

    sources_models = [
        Source(
            sourceSystem=s.source_system,
            sourceName=s.source_name,
            sourceAlertId=s.source_alert_id,
            sourceSeverity=s.source_severity,
            sourceUrl=s.source_url,
        )
        for s in sources
    ]

    signals_models = [
        ConfidenceSignal(signal=s.signal, weight=s.weight, label=s.label, tier=s.tier)
        for s in signals
    ]
    confidence = Confidence(
        score=row.confidence_score,
        label=row.confidence_label,
        explanation=signals_models,
    )

    timestamps = Timestamps(
        eventTime=row.event_time,
        ingestedTime=row.ingested_time,
        enrichedTime=row.enriched_time,
    )

    disposition = Disposition(
        status=row.disposition_status,
        setBy=row.disposition_set_by,
        setAt=row.disposition_set_at,
        notes=row.disposition_notes,
    )

    entities = Entities(**row.entities)
    enrichment = Enrichment(**row.enrichment)
    bulk_target = BulkTarget(**row.bulk_target)
    audit_model = Audit(**row.audit)
    outputs_model = Outputs(**row.outputs)
    retention_model = Retention(
        storeMode=row.retention_store_mode,
        ttlDays=row.retention_ttl_days,
        redacted=row.retention_redacted,
    )

    return CaseV0_2(
        schemaVersion=row.schema_version,
        caseId=row.id,
        tenantId=tenant.tenant_id,
        customer=tenant_customer,
        sources=sources_models,
        alertType=row.alert_type,
        title=row.title,
        description=row.description,
        timestamps=timestamps,
        severity=row.severity,
        confidence=confidence,
        disposition=disposition,
        bulkTarget=bulk_target,
        entities=entities,
        enrichment=enrichment,
        recommendedPlaybook=row.recommended_playbook,
        recommendedActions=row.recommended_actions,
        outputs=outputs_model,
        audit=audit_model,
        retention=retention_model,
        alertCount=row.alert_count,
        groupingKey=row.grouping_key,
        memberAlertIndices=row.member_alert_ids or [],
    )


def list_cases(
    session: Session, tenant_id: str, limit: int, offset: int
) -> list[CaseV0_2]:
    tenant_row = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()
    if tenant_row is None:
        return []

    rows = session.exec(
        select(CaseRow)
        .where(CaseRow.tenant_id == tenant_row.id)
        .offset(offset)
        .limit(limit)
        .order_by(CaseRow.created_at.desc())
    ).all()
    return [c for r in rows if (c := get_case(session, r.id)) is not None]


def update_disposition(
    session: Session,
    case_id: UUID,
    req: dict[str, Any],
    set_by: Optional[str] = None,
) -> CaseV0_2:
    patch = PatchDispositionRequest(**req)
    case_row = session.exec(
        select(CaseRow).where(CaseRow.id == case_id)
    ).first()
    if case_row is None:
        raise ValueError("Case not found")

    now = _utc_now()

    prior_events = session.exec(
        select(CaseDispositionEvent).where(
            CaseDispositionEvent.case_id == case_row.id
        )
    ).all()
    is_first_event = len(prior_events) == 0

    set_at = patch.setAt or now
    case_row.disposition_status = patch.status
    case_row.disposition_set_by = patch.setBy or set_by
    case_row.disposition_set_at = set_at
    case_row.disposition_notes = patch.notes
    case_row.updated_at = now

    ttfd_ms = None
    if is_first_event:
        ingested = _ensure_tz_aware(case_row.ingested_time)
        decision = _ensure_tz_aware(set_at)
        delta = decision - ingested
        ttfd_ms = max(0, int(delta.total_seconds() * 1000))
        case_row.time_to_first_decision_ms = ttfd_ms

        ttfd_sec = ttfd_ms / 1000
        manual_est = 900
        factor = round(manual_est / ttfd_sec) if ttfd_sec > 0 else 0
        updated_outputs = dict(case_row.outputs or {})
        updated_outputs["ttfdComparison"] = {
            "automatedSeconds": round(ttfd_sec, 1),
            "estimatedManualSeconds": manual_est,
            "improvement": f"{factor}x faster",
        }
        case_row.outputs = updated_outputs

    session.add(
        CaseDispositionEvent(
            case_id=case_row.id,
            status=patch.status,
            set_by=patch.setBy or set_by,
            set_at=set_at,
            notes=patch.notes,
            ttfd_ms=ttfd_ms,
        )
    )
    session.commit()

    result = get_case(session, case_id)
    assert result is not None

    # Broadcast disposition change via WebSocket
    ws_manager.broadcast_sync({
        "type": "disposition_change",
        "caseId": str(result.caseId),
        "status": patch.status,
        "setBy": patch.setBy or set_by,
    })

    # Audit log
    from backend.app.core.audit import log_audit
    try:
        tenant_row = session.exec(
            select(TenantRow).where(TenantRow.id == case_row.tenant_id)
        ).first()
        log_audit(
            session,
            tenant_id=tenant_row.tenant_id if tenant_row else "unknown",
            actor=patch.setBy or set_by or "system",
            action="case.disposition_updated",
            resource_type="case",
            resource_id=str(case_id),
            details={"status": patch.status, "notes": patch.notes},
        )
    except Exception:
        _log.debug("Audit log for disposition update failed (non-fatal)")

    return result


def reenrich_case(
    session: Session,
    case_id: UUID,
    set_by: str | None = None,
) -> dict[str, Any]:
    """Re-run enrichment on an existing case, updating score/signals in place.

    Used to apply signal logic changes (e.g. the Day 6 repeat_offender fix)
    to the historical case backlog without waiting for natural turnover.

    Preserves (never modifies):
      - disposition_status, disposition_set_by, disposition_set_at, disposition_notes
      - time_to_first_decision_ms, created_at, event_time, ingested_time
      - The entity graph (skips `extract_and_store_relationships` to avoid
        double-counting existing relationships)

    Updates:
      - confidence_score, confidence_label
      - enrichment dict (rewrites the `confidence` sub-dict)
      - recommended_playbook, recommended_actions
      - enriched_time, updated_at
      - CaseConfidenceSignal rows (DELETE + INSERT)

    Returns a dict with success flag + old/new score + delta.
    """
    case_row = session.exec(
        select(CaseRow).where(CaseRow.id == case_id)
    ).first()
    if case_row is None:
        return {"success": False, "error": "not_found"}

    old_score = case_row.confidence_score
    audit = dict(case_row.audit or {})

    # Reconstruct the raw_alert. Prefer the preserved copy (new cases via
    # the audit[_rawAlertPreserved] stash). Fall back to a best-effort merge
    # of entities + enrichment dicts for historical cases that predate the
    # preservation.
    raw_alert: dict[str, Any]
    if "_rawAlertPreserved" in audit and isinstance(audit["_rawAlertPreserved"], dict):
        raw_alert = dict(audit["_rawAlertPreserved"])
    else:
        raw_alert = {}
        if isinstance(case_row.entities, dict):
            raw_alert.update(case_row.entities)
        if isinstance(case_row.enrichment, dict):
            for k, v in case_row.enrichment.items():
                raw_alert.setdefault(k, v)

    alert_type = audit.get("_originalAlertType") or case_row.alert_type
    severity = audit.get("_originalSeverity") or case_row.severity

    # Look up the tenant_id string (the enrichment pipeline takes the string
    # form, not the UUID)
    tenant = session.exec(
        select(TenantRow).where(TenantRow.id == case_row.tenant_id)
    ).first()
    tenant_id_str = tenant.tenant_id if tenant else None

    try:
        from backend.app.services.enrichment import _run_enrichment
        enrich_result, _signals = _run_enrichment(
            alert_type=alert_type,
            severity=severity,
            raw_alert=raw_alert,
            event_time=case_row.event_time,
            tenant_id=tenant_id_str,
        )
    except Exception as e:  # noqa: BLE001
        _log.warning("Re-enrichment failed for case %s: %s", case_id, e)
        return {
            "success": False,
            "error": str(e),
            "caseId": str(case_id),
            "oldScore": old_score,
        }

    new_score = enrich_result.confidence_score
    new_label = enrich_result.confidence_label

    # Update mutable case fields — PRESERVE disposition state
    now = _utc_now()
    case_row.confidence_score = new_score
    case_row.confidence_label = new_label
    case_row.recommended_playbook = enrich_result.recommended_playbook
    case_row.recommended_actions = enrich_result.recommended_actions
    case_row.enriched_time = now
    case_row.updated_at = now

    # Rebuild the enrichment dict's confidence sub-field so the new
    # explanation is visible via GET /api/v1/cases/{id}
    if isinstance(case_row.enrichment, dict):
        _new_enrichment = dict(case_row.enrichment)
        _new_enrichment["confidence"] = {
            "score": new_score,
            "label": new_label,
            "explanation": enrich_result.confidence_explanation,
        }
        _new_enrichment["reenrichedAt"] = now.isoformat()
        case_row.enrichment = _new_enrichment

    # Delete old signal rows and insert new ones
    old_sigs = session.exec(
        select(CaseConfidenceSignal).where(
            CaseConfidenceSignal.case_id == case_row.id
        )
    ).all()
    for s in old_sigs:
        session.delete(s)
    # Flush the deletes before inserting to avoid primary-key conflicts
    session.flush()
    for expl in enrich_result.confidence_explanation:
        sig_name = expl.get("signal", "") if isinstance(expl, dict) else ""
        if not sig_name or sig_name.startswith("_"):
            continue  # skip internal markers like _score_breakdown
        session.add(CaseConfidenceSignal(
            case_id=case_row.id,
            signal=sig_name,
            weight=int(expl.get("weight", 0)) if isinstance(expl, dict) else 0,
            label=expl.get("label") if isinstance(expl, dict) else None,
            tier=expl.get("tier") if isinstance(expl, dict) else None,
        ))

    session.commit()

    # Audit log — captures old/new score for recovery + accountability
    try:
        from backend.app.core.audit import log_audit
        log_audit(
            session,
            tenant_id=tenant_id_str or "unknown",
            actor=set_by or "admin:re-enrich",
            action="case.re_enriched",
            resource_type="case",
            resource_id=str(case_row.id),
            details={
                "oldScore": old_score,
                "newScore": new_score,
                "delta": new_score - old_score,
            },
        )
    except Exception:
        _log.debug("Audit log for re-enrich failed (non-fatal)")

    return {
        "success": True,
        "caseId": str(case_row.id),
        "oldScore": old_score,
        "newScore": new_score,
        "delta": new_score - old_score,
    }
