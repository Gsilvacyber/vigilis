from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from statistics import median
from typing import Any, Optional
from uuid import UUID

from sqlmodel import Session, func, select

from backend.app.db.models import (
    Case as CaseRow,
    CaseConfidenceSignal,
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


def compute_enrichment_quality(
    session: Session,
    *,
    tenant_id: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
) -> dict[str, Any]:
    """Diagnostic metrics for enrichment quality assessment.

    Returns a structured dict answering the question: "Is our enrichment
    pipeline actually discriminating between benign and malicious cases,
    or is it just bunching everything into a middle range?"

    Captures:
      - scoreHistogram: 9-bucket distribution of confidence scores
      - signalsPerCase: histogram of how many positive signals fire per case
      - perAlertType: per-alert-type count/avg/stddev, flagged when stddev<7
        across 100+ cases (compressed variance = bad)
      - noisySignals: signals firing on >50% of cases (not discriminating)
      - autoCloseRate: % of cases auto-closed (higher = better tuning)
      - qualityScore: composite 0-100 headline metric
      - scoreStddev: overall standard deviation of all case scores
    """
    cases = _get_filtered_cases(session, tenant_id=tenant_id, start=start, end=end)
    total = len(cases)
    if total == 0:
        return {"totalCases": 0, "qualityScore": None}

    # 1. Score histogram (9 buckets from 90-100 down to 0-19)
    score_buckets: dict[str, int] = {
        "90-100": 0, "80-89": 0, "70-79": 0, "60-69": 0, "50-59": 0,
        "40-49": 0, "30-39": 0, "20-29": 0, "0-19": 0,
    }
    for c in cases:
        s = c.confidence_score
        if s >= 90:
            score_buckets["90-100"] += 1
        elif s >= 80:
            score_buckets["80-89"] += 1
        elif s >= 70:
            score_buckets["70-79"] += 1
        elif s >= 60:
            score_buckets["60-69"] += 1
        elif s >= 50:
            score_buckets["50-59"] += 1
        elif s >= 40:
            score_buckets["40-49"] += 1
        elif s >= 30:
            score_buckets["30-39"] += 1
        elif s >= 20:
            score_buckets["20-29"] += 1
        else:
            score_buckets["0-19"] += 1

    # 2. Signals-per-case distribution + per-signal fire counts (one DB pass)
    case_ids = [c.id for c in cases]
    sig_rows = session.exec(
        select(CaseConfidenceSignal).where(
            CaseConfidenceSignal.case_id.in_(case_ids)
        )
    ).all()
    sig_count_per_case: dict[UUID, int] = defaultdict(int)
    sig_fire_count: dict[str, int] = defaultdict(int)
    for r in sig_rows:
        if r.signal.startswith("_"):
            continue  # skip internal markers like _score_breakdown
        if r.signal in ("noise_flag", "ir_response", "action_status"):
            continue  # skip meta-signals
        sig_count_per_case[r.case_id] += 1
        sig_fire_count[r.signal] += 1

    signals_per_case_hist: dict[str, int] = {
        "0": 0, "1": 0, "2": 0, "3": 0, "4": 0, "5": 0, "6+": 0,
    }
    for cid in case_ids:
        count = sig_count_per_case.get(cid, 0)
        if count >= 6:
            signals_per_case_hist["6+"] += 1
        else:
            signals_per_case_hist[str(count)] += 1

    # 3. Per-alert-type variance (flag compressed variance)
    by_type: dict[str, list[int]] = defaultdict(list)
    for c in cases:
        by_type[c.alert_type].append(c.confidence_score)
    per_alert_type: list[dict[str, Any]] = []
    for at, scores in by_type.items():
        n = len(scores)
        avg = sum(scores) / n
        if n >= 2:
            variance = sum((s - avg) ** 2 for s in scores) / n
            stddev = variance ** 0.5
        else:
            stddev = 0.0
        per_alert_type.append({
            "alertType": at,
            "count": n,
            "avg": round(avg, 1),
            "stddev": round(stddev, 1),
            "compressed": bool(n >= 100 and stddev < 7),
        })
    per_alert_type.sort(key=lambda x: -x["count"])

    # 4. Noisy signals (fire on >50% of cases)
    noisy_signals: list[dict[str, Any]] = []
    for name, fires in sig_fire_count.items():
        pct = fires / total * 100
        if pct >= 50:
            noisy_signals.append({
                "name": name,
                "fires": fires,
                "pctOfCases": round(pct, 1),
            })
    noisy_signals.sort(key=lambda x: -x["pctOfCases"])

    # 5. Auto-close rate
    auto_closed = sum(
        1 for c in cases
        if "auto" in (c.disposition_set_by or "").lower()
    )
    auto_close_rate = round(auto_closed / total * 100, 1)

    # 6. Composite quality score (0-100)
    all_scores = [c.confidence_score for c in cases]
    score_avg = sum(all_scores) / total
    score_variance = sum((s - score_avg) ** 2 for s in all_scores) / total
    score_stddev = score_variance ** 0.5

    thin_evidence_pct = (
        signals_per_case_hist["0"]
        + signals_per_case_hist["1"]
        + signals_per_case_hist["2"]
        + signals_per_case_hist["3"]
    ) / total

    quality = 100.0
    # Stddev penalty: good >= 15, bad < 8. Lose 2 pts per missing stddev unit.
    quality -= max(0.0, (15.0 - score_stddev)) * 2.0
    # Thin evidence penalty: full 30 pt loss if 100% of cases are thin.
    quality -= thin_evidence_pct * 30.0
    # Noisy signals penalty: 10 pts per noisy signal.
    quality -= len(noisy_signals) * 10.0
    # Compressed alert types penalty: 5 pts per compressed type.
    compressed_count = sum(1 for a in per_alert_type if a["compressed"])
    quality -= compressed_count * 5.0
    quality = max(0.0, min(100.0, round(quality, 1)))

    return {
        "totalCases": total,
        "scoreHistogram": score_buckets,
        "signalsPerCase": signals_per_case_hist,
        "perAlertType": per_alert_type,
        "noisySignals": noisy_signals,
        "autoCloseRate": auto_close_rate,
        "qualityScore": quality,
        "scoreStddev": round(score_stddev, 1),
    }
