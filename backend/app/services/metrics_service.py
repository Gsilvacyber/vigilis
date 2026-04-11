from __future__ import annotations

from datetime import datetime
from statistics import median
from typing import Any, Optional
from uuid import UUID

from sqlmodel import Session, func, select

from backend.app.db.models import (
    Case as CaseRow,
    Tenant as TenantRow,
    WebhookDelivery,
)


def _get_filtered_cases(
    session: Session,
    *,
    tenant_id: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> list[CaseRow]:
    stmt = select(CaseRow)
    if tenant_id is not None:
        tenant = session.exec(
            select(TenantRow).where(TenantRow.tenant_id == tenant_id)
        ).first()
        if tenant is None:
            return []
        stmt = stmt.where(CaseRow.tenant_id == tenant.id)
    if start is not None:
        stmt = stmt.where(CaseRow.created_at >= start)
    if end is not None:
        stmt = stmt.where(CaseRow.created_at <= end)
    return list(session.exec(stmt).all())


def _webhook_count_for(session: Session, case_ids: list[UUID]) -> int:
    if not case_ids:
        return 0
    return session.exec(
        select(func.count())
        .select_from(WebhookDelivery)
        .where(WebhookDelivery.case_id.in_(case_ids))
    ).one()


def _webhook_counts_by_case(
    session: Session, case_ids: list[UUID]
) -> dict[UUID, int]:
    if not case_ids:
        return {}
    deliveries = session.exec(
        select(WebhookDelivery).where(WebhookDelivery.case_id.in_(case_ids))
    ).all()
    counts: dict[UUID, int] = {}
    for d in deliveries:
        counts[d.case_id] = counts.get(d.case_id, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Public computation functions
# ---------------------------------------------------------------------------

_EMPTY_SUMMARY: dict[str, Any] = {
    "totalCases": 0,
    "casesByAlertType": {},
    "casesBySeverity": {},
    "casesByConfidenceLabel": {},
    "avgConfidenceScore": 0,
    "avgConfidenceScoreByAlertType": {},
    "dispositionCounts": {},
    "webhookDeliveryCount": 0,
    "casesWithFirstDecision": 0,
    "casesOpenNoDecision": 0,
    "totalTimeSavedMinutes": 0,
    "avgTimeSavedMinutes": 0,
    "totalManualStepsReplaced": 0,
    "casesReadyForAction": 0,
    "casesNeedingReview": 0,
}


def compute_summary(
    session: Session,
    *,
    tenant_id: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict[str, Any]:
    cases = _get_filtered_cases(session, tenant_id=tenant_id, start=start, end=end)
    total = len(cases)
    if total == 0:
        return dict(_EMPTY_SUMMARY)

    by_alert_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_confidence_label: dict[str, int] = {}
    confidence_scores: list[int] = []
    confidence_by_type: dict[str, list[int]] = {}
    disposition_counts: dict[str, int] = {}
    with_decision = 0
    without_decision = 0

    total_time_saved = 0
    total_manual_steps = 0
    cases_ready = 0
    cases_needs_review = 0
    suppressed_count = 0

    for c in cases:
        by_alert_type[c.alert_type] = by_alert_type.get(c.alert_type, 0) + 1
        by_severity[c.severity] = by_severity.get(c.severity, 0) + 1
        by_confidence_label[c.confidence_label] = (
            by_confidence_label.get(c.confidence_label, 0) + 1
        )
        confidence_scores.append(c.confidence_score)
        confidence_by_type.setdefault(c.alert_type, []).append(c.confidence_score)
        disposition_counts[c.disposition_status] = (
            disposition_counts.get(c.disposition_status, 0) + 1
        )
        if c.time_to_first_decision_ms is not None:
            with_decision += 1
        else:
            without_decision += 1

        enr = c.enrichment or {}
        impact = enr.get("impactSummary") or {}
        total_time_saved += impact.get("timeSavedMinutes", 0)
        total_manual_steps += len(impact.get("manualStepsReplaced", []))

        readiness = enr.get("caseReadiness") or {}
        if readiness.get("readyForAction", True):
            cases_ready += 1
        else:
            cases_needs_review += 1

        # Count auto-suppressed
        if c.disposition_set_by and "auto:" in (c.disposition_set_by or ""):
            suppressed_count += 1

    wh_count = _webhook_count_for(session, [c.id for c in cases])
    avg_conf = round(sum(confidence_scores) / total, 1)
    avg_by_type = {
        k: round(sum(v) / len(v), 1) for k, v in confidence_by_type.items()
    }

    return {
        "totalCases": total,
        "casesByAlertType": by_alert_type,
        "casesBySeverity": by_severity,
        "casesByConfidenceLabel": by_confidence_label,
        "avgConfidenceScore": avg_conf,
        "avgConfidenceScoreByAlertType": avg_by_type,
        "dispositionCounts": disposition_counts,
        "webhookDeliveryCount": wh_count,
        "casesWithFirstDecision": with_decision,
        "casesOpenNoDecision": without_decision,
        "totalTimeSavedMinutes": total_time_saved,
        "avgTimeSavedMinutes": round(total_time_saved / total, 1),
        "totalManualStepsReplaced": total_manual_steps,
        "casesReadyForAction": cases_ready,
        "casesNeedingReview": cases_needs_review,
        "suppressedCount": suppressed_count,
    }


def compute_ttfd(
    session: Session,
    *,
    tenant_id: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict[str, Any]:
    cases = _get_filtered_cases(session, tenant_id=tenant_id, start=start, end=end)

    ttfd_values: list[int] = []
    ttfd_by_type: dict[str, list[int]] = {}

    for c in cases:
        if c.time_to_first_decision_ms is not None:
            ms = c.time_to_first_decision_ms
            ttfd_values.append(ms)
            ttfd_by_type.setdefault(c.alert_type, []).append(ms)

    total_with = len(ttfd_values)
    total_without = len(cases) - total_with

    if total_with == 0:
        return {
            "averageTtfdSeconds": None,
            "medianTtfdSeconds": None,
            "minTtfdSeconds": None,
            "maxTtfdSeconds": None,
            "ttfdByAlertType": {},
            "casesWithTtfd": 0,
            "casesWithoutTtfd": total_without,
        }

    avg_s = round(sum(ttfd_values) / total_with / 1000, 1)
    med_s = round(median(ttfd_values) / 1000, 1)
    min_s = round(min(ttfd_values) / 1000, 1)
    max_s = round(max(ttfd_values) / 1000, 1)

    by_type: dict[str, Any] = {}
    for alert_type, vals in sorted(ttfd_by_type.items()):
        by_type[alert_type] = {
            "count": len(vals),
            "avgSeconds": round(sum(vals) / len(vals) / 1000, 1),
            "medianSeconds": round(median(vals) / 1000, 1),
        }

    return {
        "averageTtfdSeconds": avg_s,
        "medianTtfdSeconds": med_s,
        "minTtfdSeconds": min_s,
        "maxTtfdSeconds": max_s,
        "ttfdByAlertType": by_type,
        "casesWithTtfd": total_with,
        "casesWithoutTtfd": total_without,
    }


def compute_by_alert_type(
    session: Session,
    *,
    tenant_id: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict[str, Any]:
    cases = _get_filtered_cases(session, tenant_id=tenant_id, start=start, end=end)

    groups: dict[str, list[CaseRow]] = {}
    for c in cases:
        groups.setdefault(c.alert_type, []).append(c)

    wh_counts = _webhook_counts_by_case(session, [c.id for c in cases])

    result: dict[str, Any] = {}
    for alert_type, type_cases in sorted(groups.items()):
        scores = [c.confidence_score for c in type_cases]
        dispositions: dict[str, int] = {}
        ttfd_vals: list[int] = []
        wh_total = 0

        for c in type_cases:
            dispositions[c.disposition_status] = (
                dispositions.get(c.disposition_status, 0) + 1
            )
            if c.time_to_first_decision_ms is not None:
                ttfd_vals.append(c.time_to_first_decision_ms)
            wh_total += wh_counts.get(c.id, 0)

        result[alert_type] = {
            "count": len(type_cases),
            "avgConfidenceScore": round(sum(scores) / len(scores), 1),
            "dispositions": dispositions,
            "casesWithFirstDecision": len(ttfd_vals),
            "avgTtfdSeconds": (
                round(sum(ttfd_vals) / len(ttfd_vals) / 1000, 1)
                if ttfd_vals
                else None
            ),
            "webhookDeliveries": wh_total,
        }

    return {"alertTypes": result}
