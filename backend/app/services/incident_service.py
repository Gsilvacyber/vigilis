"""Incident correlation engine.

Chains individual cases into multi-step attack incidents by:
1. Mapping each alert type to a kill-chain stage
2. Clustering cases by shared entities (user + IP) with weighted linking
3. Detecting clusters that span 2+ kill-chain stages
4. Computing incident-level confidence scores
5. Analyzing kill-chain gaps (present vs likely missing stages)
6. Recording linkage reasons for auditability
7. Generating descriptive titles and attack narratives

Implementation is split across the ``correlation`` sub-package:
  - ``correlation.kill_chain`` — stage definitions & gap analysis
  - ``correlation.clustering`` — entity extraction & case clustering
  - ``correlation.scoring`` — confidence, severity, risk assessment
  - ``correlation.narrative`` — title, summary, narrative, workflow
"""
from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

from sqlmodel import Session, select

from backend.app.db.models import (
    Case as CaseRow,
    Incident,
    IncidentCaseLink,
    Tenant as TenantRow,
)

_log = logging.getLogger(__name__)

# ── Re-export everything that external callers may import from here ──────
# This keeps the public API stable: every symbol that was importable from
# ``backend.app.services.incident_service`` before the refactor is still
# importable from exactly the same path.

from backend.app.services.correlation.kill_chain import (
    validate_temporal_order,
    StageEvent,
)

from backend.app.services.correlation import (  # noqa: F401 — re-exports
    KILL_CHAIN_STAGES,
    _ALERT_TYPE_TO_STAGE,
    _STAGE_LABELS,
    _STAGE_ORDER,
    _SEVERITY_RANK,
    _LINK_THRESHOLD,
    CORRELATION_WINDOW_HOURS,
    get_stage,
    stage_order,
    analyze_kill_chain_gaps as _analyze_kill_chain_gaps,
    extract_entities as _extract_entities,
    cluster_cases as _cluster_cases,
    ClusterResult as _ClusterResult,
    build_linkage_reasons as _build_linkage_reasons,
    build_link_strength_summary as _build_link_strength_summary,
    compute_confidence as _compute_confidence,
    compute_severity as _compute_severity,
    compute_risk as _compute_risk,
    generate_title as _generate_title,
    generate_summary as _generate_summary,
    build_narrative as _build_narrative,
    generate_recommended_actions as _generate_recommended_actions,
    predict_workflow as _predict_workflow,
    refine_cloud_stage as _refine_cloud_stage_fn,
)

# Backward-compatible private aliases (tests import the underscore names)
_refine_cloud_stage = _refine_cloud_stage_fn


# ── Cross-case compound scoring ──────────────────────────────────────────
def _apply_compound_boost(
    conf_score: int,
    cases: list,
    stage_set: dict[str, list],
) -> int:
    """Boost incident confidence when multiple cases compound suspicion.

    When N cases each score 40-50 individually, the *pattern* of repeated
    hits is far more suspicious than any single event.  This function
    applies two independent boosts:

    1. **Volume multiplier** — scales the max individual case score by a
       factor that grows with the number of qualifying cases.
    2. **Kill-chain breadth bonus** — rewards incidents that span multiple
       MITRE ATT&CK stages, because a wider spread across the kill chain
       is a stronger indicator of a real attack.

    The result replaces ``conf_score`` only when the boosted value is
    higher, and is always capped at 100.
    """
    AVG_THRESHOLD = 30
    case_scores = [getattr(c, "confidence_score", 0) or 0 for c in cases]
    n_cases = len(cases)

    if n_cases < 3:
        return conf_score

    avg_score = sum(case_scores) / n_cases if n_cases else 0
    if avg_score < AVG_THRESHOLD:
        return conf_score

    max_score = max(case_scores) if case_scores else 0

    # Volume multiplier
    if n_cases > 10:
        multiplier = 1.6
    elif n_cases >= 6:
        multiplier = 1.4
    else:                          # 3-5 cases
        multiplier = 1.2

    boosted = max_score * multiplier

    # Kill-chain breadth bonus
    n_stages = len(stage_set)
    if n_stages >= 3:
        boosted += 20
    elif n_stages >= 2:
        boosted += 10

    boosted = min(int(boosted), 100)
    return max(conf_score, boosted)


# ── Export payload generation (stays here — it's an API-layer helper) ─────

def generate_export_payload(
    incident_dict: dict[str, Any],
    fmt: str = "slack",
) -> dict[str, Any]:
    """Generate a shareable payload for an incident."""

    inc = incident_dict
    severity = inc.get("severity", "medium").upper()
    title = inc.get("title", "Unknown Incident")
    summary = inc.get("summary", "")
    conf = inc.get("confidenceScore", 0)
    risk = inc.get("riskLevel", "medium").upper()
    users = ", ".join(inc.get("entities", {}).get("users", [])) or "unknown"
    actions = inc.get("recommendedActions", [])
    workflow = inc.get("workflow", {})
    first = inc.get("firstSeen", "")
    last = inc.get("lastSeen", "")

    sev_emoji = {"CRITICAL": "\U0001f6a8", "HIGH": "\u26a0\ufe0f", "MEDIUM": "\U0001f7e1", "LOW": "\u2139\ufe0f"}.get(severity, "\u2753")

    if fmt == "slack":
        action_lines = "\n".join(f"  \u2022 {a['action']}" for a in actions[:5])
        disposition = workflow.get("disposition", "investigate")

        text = (
            f"{sev_emoji} *{severity} Incident* — {title}\n"
            f"{summary}\n\n"
            f"*Confidence:* {conf}%  |  *Risk:* {risk}  |  *User:* {users}\n"
            f"*First seen:* {first}  |  *Last seen:* {last}\n\n"
            f"*Recommended actions:*\n{action_lines}\n\n"
            f"*Workflow:* {disposition}"
        )

        return {
            "format": "slack",
            "text": text,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{sev_emoji} {severity} Incident"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*{title}*\n{summary}"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Confidence:* {conf}%"},
                        {"type": "mrkdwn", "text": f"*Risk:* {risk}"},
                        {"type": "mrkdwn", "text": f"*User:* {users}"},
                        {"type": "mrkdwn", "text": f"*Disposition:* {disposition}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Actions:*\n{action_lines}"},
                },
            ],
        }

    return {
        "format": "json",
        "incident": {
            "id": inc.get("id"),
            "title": title,
            "summary": summary,
            "severity": inc.get("severity"),
            "riskLevel": inc.get("riskLevel"),
            "confidenceScore": conf,
            "confidenceLabel": inc.get("confidenceLabel"),
            "entities": inc.get("entities"),
            "killChainStages": [s.get("label") for s in inc.get("killChainStages", [])],
            "recommendedActions": [a["action"] for a in actions],
            "workflow": workflow,
            "firstSeen": first,
            "lastSeen": last,
            "timeSpanSeconds": inc.get("timeSpanSeconds"),
        },
    }


# ── Public API ───────────────────────────────────────────────────────────

def correlate_incidents(
    session: Session,
    tenant_id: str,
    window_hours: int = CORRELATION_WINDOW_HOURS,
) -> list[dict[str, Any]]:
    """Analyze all cases for a tenant, create Incident records for multi-stage chains."""
    tenant = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()
    if not tenant:
        return []

    existing_links = session.exec(select(IncidentCaseLink)).all()

    # Fix 3: Only freeze cases linked to CLOSED incidents (not open ones)
    closed_incident_ids = set()
    for inc in session.exec(select(Incident).where(Incident.status == "closed")).all():
        closed_incident_ids.add(inc.id)

    frozen_case_ids = set()
    for link in existing_links:
        if link.incident_id in closed_incident_ids:
            frozen_case_ids.add(link.case_id)

    cases = list(session.exec(
        select(CaseRow).where(CaseRow.tenant_id == tenant.id)
    ).all())

    eligible = [c for c in cases if c.id not in frozen_case_ids]
    if not eligible:
        return _list_incidents_internal(session, tenant.id)

    cluster_results = _cluster_cases(eligible, window_hours, tenant_id=tenant_id)

    # Fix 2: Pre-fetch open incidents for merge checks
    existing_open_incidents = list(session.exec(
        select(Incident).where(
            Incident.tenant_id == tenant.id,
            Incident.status != "closed"
        )
    ).all())

    for cr in cluster_results:
        cluster = cr.cases

        # Fix 2: Check if this cluster's entities overlap with an existing OPEN incident
        cluster_users = set()
        for case in cluster:
            ent = case.entities or {}
            identity = ent.get("identity", {}) or {}
            upn = identity.get("upn", "")
            if upn and upn not in ("unknown", "unknown@upload"):
                cluster_users.add(upn.lower())

        matched_incident = None
        if cluster_users:
            for existing_inc in existing_open_incidents:
                inc_links = session.exec(
                    select(IncidentCaseLink).where(IncidentCaseLink.incident_id == existing_inc.id)
                ).all()
                inc_users = set()
                for link in inc_links:
                    inc_case = session.exec(select(CaseRow).where(CaseRow.id == link.case_id)).first()
                    if inc_case:
                        ent = inc_case.entities or {}
                        identity = ent.get("identity", {}) or {}
                        upn = identity.get("upn", "")
                        if upn:
                            inc_users.add(upn.lower())
                if cluster_users & inc_users:
                    matched_incident = existing_inc
                    break

        if matched_incident:
            # MERGE: Add these cases to the existing incident instead of creating new
            for case in cluster:
                existing_link = session.exec(
                    select(IncidentCaseLink).where(
                        IncidentCaseLink.incident_id == matched_incident.id,
                        IncidentCaseLink.case_id == case.id
                    )
                ).first()
                if not existing_link:
                    stage = get_stage(case.alert_type)
                    session.add(IncidentCaseLink(
                        incident_id=matched_incident.id,
                        case_id=case.id,
                        kill_chain_stage=stage,
                        stage_order=stage_order(stage),
                    ))
            session.commit()
            _log.info("Merged %d cases into existing incident %s", len(cluster), matched_incident.id)

            # ── Recalculate incident metadata after merge ──────────────
            # Title, summary, stages, severity, and confidence are stale from
            # initial creation.  Re-derive from all currently linked cases.
            _all_links = session.exec(
                select(IncidentCaseLink).where(
                    IncidentCaseLink.incident_id == matched_incident.id
                )
            ).all()
            _all_cases = [
                c for c in (session.get(CaseRow, lk.case_id) for lk in _all_links) if c
            ]
            if _all_cases:
                _m_stages: dict[str, list[CaseRow]] = {}
                _m_ents: dict[str, set[str]] = {"users": set(), "ips": set(), "devices": set()}
                for _mc in _all_cases:
                    _cat = _mc.alert_type.split(".")[0] if _mc.alert_type else ""
                    _st = _refine_cloud_stage(_mc) if _cat == "cloud" else get_stage(_mc.alert_type)
                    _m_stages.setdefault(_st, []).append(_mc)
                    _me = _extract_entities(_mc)
                    for _k in ("users", "ips", "devices"):
                        _m_ents[_k] |= _me[_k]

                _ordered = sorted(_m_stages.keys(), key=stage_order)
                _sorted_all = sorted(_all_cases, key=lambda c: c.event_time)
                _first = _sorted_all[0].event_time
                _last = _sorted_all[-1].event_time
                _span = int((_last - _first).total_seconds()) if len(_sorted_all) >= 2 else None

                matched_incident.title = _generate_title(_ordered, _m_ents)
                matched_incident.summary = _generate_summary(
                    _ordered, _m_ents, len(_all_cases), _span,
                    matched_incident.confidence_score,
                )
                matched_incident.case_count = len(_all_cases)
                matched_incident.alert_type_count = len(_m_stages)
                matched_incident.entities = {
                    "users": sorted(_m_ents["users"]),
                    "ips": sorted(_m_ents["ips"]),
                    "devices": sorted(_m_ents["devices"]),
                }
                matched_incident.kill_chain_stages = [
                    {
                        "stage": s, "label": _STAGE_LABELS.get(s, s),
                        "caseCount": len(_m_stages[s]),
                        "caseTypes": list(set(getattr(c, "alert_type", "") for c in _m_stages[s])),
                        "evidence": [getattr(c, "title", "") or getattr(c, "alert_type", "") for c in _m_stages[s]][:5],
                    }
                    for s in _ordered
                ]
                matched_incident.first_seen = _first
                matched_incident.last_seen = _last
                matched_incident.time_span_seconds = _span

                if len(_ordered) >= 2:
                    matched_incident.severity = _compute_severity(
                        _all_cases, len(_ordered), _ordered,
                    )
                    _cs, _cl, _cb = _compute_confidence(
                        _all_cases, _ordered, _m_ents, _span,
                    )

                    # ── Compound scoring boost on merge ─────────────────
                    _pre = _cs
                    _cs = _apply_compound_boost(_cs, _all_cases, _m_stages)
                    if _cs != _pre:
                        _cl = (
                            "critical" if _cs >= 85 else
                            "high" if _cs >= 65 else
                            "medium" if _cs >= 45 else "low"
                        )
                        _cb.append({
                            "factor": "Cross-case compound boost",
                            "points": _cs - _pre,
                            "maxPoints": 40,
                            "detail": (
                                f"{len(_all_cases)} cases, "
                                f"{len(_m_stages)} kill-chain stages (merge)"
                            ),
                        })

                    matched_incident.confidence_score = _cs
                    matched_incident.confidence_label = _cl
                    matched_incident.confidence_breakdown = _cb

                session.add(matched_incident)
                session.commit()

            continue  # Skip creating a new incident

        stage_set: dict[str, list[CaseRow]] = {}
        all_entities: dict[str, set[str]] = {"users": set(), "ips": set(), "devices": set()}

        for case in cluster:
            category = case.alert_type.split(".")[0] if case.alert_type else ""
            if category == "cloud":
                stage = _refine_cloud_stage(case)
            else:
                stage = get_stage(case.alert_type)
            stage_set.setdefault(stage, []).append(case)
            ent = _extract_entities(case)
            for key in ("users", "ips", "devices"):
                all_entities[key] |= ent[key]

        if len(stage_set) < 2:
            # ── High-volume single-stage pattern detection ──────────────
            total_alerts = sum(getattr(c, 'alert_count', 1) or 1 for c in cluster)
            max_score = max((getattr(c, 'confidence_score', 0) or 0) for c in cluster)

            if total_alerts >= 3 and max_score >= 50:
                sole_stage = list(stage_set.keys())[0]
                stage_label = _STAGE_LABELS.get(sole_stage, sole_stage)
                users_list = sorted(all_entities["users"])
                user_tag = users_list[0] if users_list else "unknown"

                if total_alerts >= 10 and max_score >= 85:
                    pattern_severity = "high"
                elif total_alerts >= 7 or max_score >= 80:
                    pattern_severity = "medium"
                else:
                    pattern_severity = "low"

                vol_bonus = min(total_alerts * 2, 20)
                avg_case_conf = sum(c.confidence_score for c in cluster) / len(cluster)
                pattern_conf = min(int(avg_case_conf + vol_bonus), 100)

                # ── Compound scoring boost for single-stage clusters ────
                pattern_conf = _apply_compound_boost(
                    pattern_conf, cluster, stage_set,
                )

                pattern_conf_label = (
                    "critical" if pattern_conf >= 85 else
                    "high" if pattern_conf >= 65 else
                    "medium" if pattern_conf >= 45 else "low"
                )

                sorted_cluster = sorted(cluster, key=lambda c: c.event_time)
                first_seen = sorted_cluster[0].event_time
                last_seen = sorted_cluster[-1].event_time
                time_span = None
                if len(sorted_cluster) >= 2:
                    time_span = int((last_seen - first_seen).total_seconds())

                title = f"High-volume {sole_stage} — {user_tag}"
                summary = (
                    f"Single-stage pattern: {total_alerts} alerts "
                    f"({len(cluster)} cases) in {stage_label}, "
                    f"confidence: {pattern_conf}%"
                )
                rec_actions = _generate_recommended_actions([sole_stage], all_entities)
                linkage = _build_linkage_reasons(cluster, cr.reasons, [sole_stage])
                link_str = _build_link_strength_summary(cr.max_link_score, cr.link_components)

                risk_factors = [{
                    "factor": "High event volume in single stage",
                    "impact": "medium" if total_alerts < 10 else "high",
                    "detail": f"{total_alerts} alerts of type {stage_label}",
                }]
                risk_level = "high" if total_alerts >= 10 and max_score >= 85 else "medium"

                workflow = _predict_workflow(
                    pattern_severity, pattern_conf, risk_level, [sole_stage], len(cluster),
                )

                narrative_lines = [
                    f"High-volume single-stage pattern detected: {stage_label}.",
                    f"Affected user(s): {', '.join(users_list) or 'unknown'}.",
                    f"{total_alerts} total alerts across {len(cluster)} case(s).",
                    f"Max individual confidence: {max_score}%.",
                ]
                narrative = "\n".join(narrative_lines)

                incident = Incident(
                    tenant_id=tenant.id,
                    title=title,
                    summary=summary,
                    severity=pattern_severity,
                    confidence_score=pattern_conf,
                    confidence_label=pattern_conf_label,
                    confidence_breakdown=[{
                        "factor": "Single-stage volume pattern",
                        "points": pattern_conf,
                        "maxPoints": 100,
                        "detail": f"{total_alerts} alerts, avg conf {avg_case_conf:.0f}%, vol bonus +{vol_bonus}",
                    }],
                    kill_chain_stages=[{
                        "stage": sole_stage,
                        "label": stage_label,
                        "caseCount": len(cluster),
                        "caseTypes": list(set(getattr(c, 'alert_type', '') for c in cluster)),
                        "evidence": [getattr(c, 'title', '') or getattr(c, 'alert_type', '') for c in cluster][:5],
                    }],
                    kill_chain_gaps=[],
                    entities={
                        "users": users_list,
                        "ips": sorted(all_entities["ips"]),
                        "devices": sorted(all_entities["devices"]),
                    },
                    linkage_reasons=linkage,
                    link_strength=link_str,
                    recommended_actions=rec_actions,
                    risk_level=risk_level,
                    risk_factors=risk_factors,
                    workflow=workflow,
                    narrative=narrative,
                    case_count=len(cluster),
                    alert_type_count=1,
                    time_span_seconds=time_span,
                    first_seen=first_seen,
                    last_seen=last_seen,
                )
                session.add(incident)
                session.flush()

                for case in sorted_cluster:
                    stage = get_stage(case.alert_type)
                    link = IncidentCaseLink(
                        incident_id=incident.id,
                        case_id=case.id,
                        kill_chain_stage=stage,
                        stage_order=stage_order(stage),
                    )
                    session.add(link)

            continue

        ordered_stages = sorted(stage_set.keys(), key=stage_order)
        severity = _compute_severity(cluster, len(ordered_stages), ordered_stages)

        sorted_cluster = sorted(cluster, key=lambda c: c.event_time)
        first_seen = sorted_cluster[0].event_time
        last_seen = sorted_cluster[-1].event_time
        time_span = None
        if len(sorted_cluster) >= 2:
            delta = last_seen - first_seen
            time_span = int(delta.total_seconds())

        conf_score, conf_label, conf_breakdown = _compute_confidence(
            cluster, ordered_stages, all_entities, time_span,
        )

        # ── Compound scoring boost for cross-case patterns ──────────
        pre_boost = conf_score
        conf_score = _apply_compound_boost(conf_score, cluster, stage_set)
        if conf_score != pre_boost:
            conf_label = (
                "critical" if conf_score >= 85 else
                "high" if conf_score >= 65 else
                "medium" if conf_score >= 45 else "low"
            )
            conf_breakdown.append({
                "factor": "Cross-case compound boost",
                "points": conf_score - pre_boost,
                "maxPoints": 40,
                "detail": (
                    f"{len(cluster)} cases (avg score "
                    f"{sum(c.confidence_score for c in cluster) / len(cluster):.0f}%), "
                    f"{len(stage_set)} kill-chain stages"
                ),
            })

        linkage = _build_linkage_reasons(cluster, cr.reasons, ordered_stages)
        link_str = _build_link_strength_summary(cr.max_link_score, cr.link_components)
        gaps = _analyze_kill_chain_gaps(ordered_stages)
        title = _generate_title(ordered_stages, all_entities)
        summary = _generate_summary(
            ordered_stages, all_entities, len(cluster), time_span, conf_score,
        )
        rec_actions = _generate_recommended_actions(ordered_stages, all_entities)
        risk_level, risk_factors = _compute_risk(
            ordered_stages, severity, len(cluster), all_entities,
        )
        workflow = _predict_workflow(
            severity, conf_score, risk_level, ordered_stages, len(cluster),
        )
        narrative = _build_narrative(
            cluster, ordered_stages, all_entities, linkage, gaps,
        )

        # Temporal kill chain validation
        _stage_events = []
        for _case in sorted_cluster:
            _s = get_stage(_case.alert_type)
            if _s and _case.event_time:
                _stage_events.append(StageEvent(
                    stage=_s,
                    event_time=_case.event_time,
                    case_id=str(_case.id),
                    alert_type=_case.alert_type,
                ))
        temporal = validate_temporal_order(_stage_events)
        if not temporal["valid"] and temporal["anomalies"]:
            anomaly_count = len(temporal["anomalies"])
            narrative += f"\n\nTemporal analysis: {anomaly_count} kill-chain ordering anomaly(ies) detected — stages occurred out of expected order."
            _log.info("Temporal anomalies in incident cluster: %s", temporal["anomalies"])

        users_list = sorted(all_entities["users"])

        incident = Incident(
            tenant_id=tenant.id,
            title=title,
            summary=summary,
            severity=severity,
            confidence_score=conf_score,
            confidence_label=conf_label,
            confidence_breakdown=conf_breakdown,
            kill_chain_stages=[
                {
                    "stage": s,
                    "label": _STAGE_LABELS.get(s, s),
                    "caseCount": len(stage_set[s]),
                    "caseTypes": list(set(getattr(c, 'alert_type', '') for c in stage_set[s])),
                    "evidence": [getattr(c, 'title', '') or getattr(c, 'alert_type', '') for c in stage_set[s]][:5],
                }
                for s in ordered_stages
            ],
            kill_chain_gaps=gaps,
            entities={
                "users": users_list,
                "ips": sorted(all_entities["ips"]),
                "devices": sorted(all_entities["devices"]),
            },
            linkage_reasons=linkage,
            link_strength=link_str,
            recommended_actions=rec_actions,
            risk_level=risk_level,
            risk_factors=risk_factors,
            workflow=workflow,
            narrative=narrative,
            case_count=len(cluster),
            alert_type_count=len(stage_set),
            time_span_seconds=time_span,
            first_seen=first_seen,
            last_seen=last_seen,
        )
        session.add(incident)
        session.flush()

        try:
            from backend.app.core.metrics import incidents_created
            incidents_created.inc()
        except Exception:
            pass

        for case in sorted_cluster:
            stage = get_stage(case.alert_type)
            link = IncidentCaseLink(
                incident_id=incident.id,
                case_id=case.id,
                kill_chain_stage=stage,
                stage_order=stage_order(stage),
            )
            session.add(link)

    session.commit()

    # ── Cross-case incident boost ────────────────────────────────────
    for inc_data in session.exec(
        select(Incident).where(Incident.tenant_id == tenant.id)
    ).all():
        if inc_data.confidence_score < 70:
            continue
        links = session.exec(
            select(IncidentCaseLink).where(IncidentCaseLink.incident_id == inc_data.id)
        ).all()
        for link in links:
            case_row = session.exec(
                select(CaseRow).where(CaseRow.id == link.case_id)
            ).first()
            if case_row and case_row.confidence_score < 75:
                boosted = min(case_row.confidence_score + 15, inc_data.confidence_score)
                case_row.confidence_score = boosted
                case_row.confidence_label = (
                    "critical" if boosted >= 85 else
                    "high" if boosted >= 60 else
                    "medium" if boosted >= 35 else "low"
                )
                session.add(case_row)
    session.commit()

    incidents = _list_incidents_internal(session, tenant.id)
    _log.info("Correlation found %d incidents for tenant %s", len(incidents), tenant_id)
    return incidents


def list_incidents(
    session: Session,
    tenant_id: str,
) -> list[dict[str, Any]]:
    """List all incidents for a tenant."""
    tenant = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()
    if not tenant:
        return []
    return _list_incidents_internal(session, tenant.id)


def get_incident_detail(
    session: Session,
    incident_id: UUID,
    tenant_id: str,
) -> Optional[dict[str, Any]]:
    """Get full incident detail with case timeline."""
    tenant = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()
    if not tenant:
        return None

    incident = session.get(Incident, incident_id)
    if not incident or incident.tenant_id != tenant.id:
        return None

    links = list(session.exec(
        select(IncidentCaseLink)
        .where(IncidentCaseLink.incident_id == incident.id)
    ).all())

    case_ids = [link.case_id for link in links]
    cases = []
    for cid in case_ids:
        case = session.get(CaseRow, cid)
        if case:
            cases.append(case)

    cases_sorted = sorted(cases, key=lambda c: c.event_time)
    link_map = {link.case_id: link for link in links}

    timeline = []
    for case in cases_sorted:
        link = link_map.get(case.id)
        stage = link.kill_chain_stage if link else get_stage(case.alert_type)
        timeline.append({
            "caseId": str(case.id),
            "alertType": case.alert_type,
            "title": case.title,
            "severity": case.severity,
            "confidenceScore": case.confidence_score,
            "confidenceLabel": case.confidence_label,
            "eventTime": case.event_time.isoformat(),
            "killChainStage": stage,
            "killChainLabel": _STAGE_LABELS.get(stage, stage),
            "stageOrder": stage_order(stage),
            "dispositionStatus": case.disposition_status,
            "entities": case.entities,
        })

    result = _incident_to_dict(incident, include_narrative=True, session=session)
    result["timeline"] = timeline
    return result


# ── Internal helpers ─────────────────────────────────────────────────────

def _incident_to_dict(
    incident: Incident,
    *,
    include_narrative: bool = False,
    session: Session | None = None,
) -> dict[str, Any]:
    """Convert an Incident ORM object to a JSON-serializable dict."""
    # Dynamically count linked cases (may grow via merge)
    live_case_count = incident.case_count
    if session is not None:
        link_count = len(session.exec(
            select(IncidentCaseLink).where(IncidentCaseLink.incident_id == incident.id)
        ).all())
        if link_count > 0:
            live_case_count = link_count

    d: dict[str, Any] = {
        "id": str(incident.id),
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity,
        "status": incident.status,
        "confidenceScore": incident.confidence_score,
        "confidenceLabel": incident.confidence_label,
        "confidenceBreakdown": incident.confidence_breakdown,
        "riskLevel": incident.risk_level,
        "riskFactors": incident.risk_factors,
        "workflow": incident.workflow,
        "killChainStages": incident.kill_chain_stages,
        "killChainGaps": incident.kill_chain_gaps,
        "entities": incident.entities,
        "linkageReasons": incident.linkage_reasons,
        "linkStrength": incident.link_strength,
        "recommendedActions": incident.recommended_actions,
        "caseCount": live_case_count,
        "alertTypeCount": incident.alert_type_count,
        "timeSpanSeconds": incident.time_span_seconds,
        "firstSeen": incident.first_seen.isoformat() if incident.first_seen else None,
        "lastSeen": incident.last_seen.isoformat() if incident.last_seen else None,
        "createdAt": incident.created_at.isoformat(),
    }
    if include_narrative:
        d["narrative"] = incident.narrative
    return d


def _list_incidents_internal(
    session: Session,
    tenant_db_id: UUID,
) -> list[dict[str, Any]]:
    incidents = list(session.exec(
        select(Incident).where(Incident.tenant_id == tenant_db_id)
    ).all())

    results = [_incident_to_dict(inc, session=session) for inc in incidents]
    results.sort(
        key=lambda r: (_SEVERITY_RANK.get(r["severity"], 0), r["confidenceScore"]),
        reverse=True,
    )
    return results


def auto_correlate_background(tenant_id: str) -> None:
    """Run incident correlation as a background task. Safe for FastAPI BackgroundTasks."""
    try:
        from backend.app.core.db import get_session
        with get_session() as session:
            correlate_incidents(session, tenant_id=tenant_id)
    except Exception:
        _log.exception("Auto-correlation background task failed for tenant %s", tenant_id)
