"""IOC Investigation Engine.

Given an indicator of compromise (IP, hash, email, domain, hostname, user),
searches all ingested cases and incidents, then builds a full investigation
dossier: related alerts, entity graph, timeline, geo data, risk context.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Any
from uuid import UUID

from sqlmodel import Session, select

from backend.app.db.models import (
    Case as CaseRow,
    Incident,
    IncidentCaseLink,
    Tenant as TenantRow,
)

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_EMAIL_RE = re.compile(r"^[\w.+-]+@[\w.-]+\.\w{2,}$")
_DOMAIN_RE = re.compile(r"^[\w.-]+\.\w{2,}$")


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    if _IP_RE.match(v):
        return "ip"
    if _SHA256_RE.match(v):
        return "sha256"
    if _MD5_RE.match(v):
        return "md5"
    if _EMAIL_RE.match(v):
        return "email"
    if _DOMAIN_RE.match(v) and " " not in v:
        return "domain"
    return "keyword"


def _extract_ips(entities: dict) -> list[dict]:
    return entities.get("ips") or []


def _extract_ip_addresses(entities: dict) -> list[str]:
    return [ip.get("ipAddress", "") for ip in _extract_ips(entities) if ip.get("ipAddress")]


def _extract_users(entities: dict) -> list[str]:
    users = []
    for key in ("identity", "actor"):
        sub = entities.get(key) or {}
        upn = sub.get("upn")
        if upn:
            users.append(upn)
        uid = sub.get("userId")
        if uid:
            users.append(uid)
        dn = sub.get("displayName")
        if dn:
            users.append(dn)
    return list(dict.fromkeys(users))


def _extract_hostnames(entities: dict) -> list[str]:
    device = entities.get("device") or {}
    h = device.get("hostname")
    return [h] if h else []


def _extract_hashes(entities: dict) -> list[str]:
    f = entities.get("file") or {}
    hashes = []
    if f.get("sha256"):
        hashes.append(f["sha256"])
    return hashes


def _extract_emails(entities: dict) -> list[str]:
    result = []
    for key in ("identity", "actor"):
        sub = entities.get(key) or {}
        upn = sub.get("upn")
        if upn and "@" in upn:
            result.append(upn)
    mb = entities.get("mailbox") or {}
    if mb.get("primaryAddress"):
        result.append(mb["primaryAddress"])
    if mb.get("forwardingAddress"):
        result.append(mb["forwardingAddress"])
    return list(dict.fromkeys(result))


def _case_matches_ioc(entities: dict, ioc_type: str, ioc_value: str) -> bool:
    v = ioc_value.lower()

    if ioc_type == "ip":
        return any(ip.lower() == v for ip in _extract_ip_addresses(entities))

    if ioc_type in ("sha256", "md5"):
        return any(h.lower() == v for h in _extract_hashes(entities))

    if ioc_type == "email":
        return any(e.lower() == v for e in _extract_emails(entities))

    if ioc_type == "domain":
        for email in _extract_emails(entities):
            if email.lower().endswith("@" + v):
                return True
        for h in _extract_hostnames(entities):
            if h.lower() == v:
                return True
        return False

    all_text = " ".join(
        _extract_users(entities) +
        _extract_ip_addresses(entities) +
        _extract_hostnames(entities) +
        _extract_emails(entities) +
        _extract_hashes(entities)
    ).lower()
    return v in all_text


def _case_to_summary(row: CaseRow) -> dict[str, Any]:
    entities = row.entities or {}
    return {
        "caseId": str(row.id),
        "alertType": row.alert_type,
        "title": row.title,
        "severity": row.severity,
        "confidenceScore": row.confidence_score,
        "confidenceLabel": row.confidence_label,
        "dispositionStatus": row.disposition_status,
        "eventTime": row.event_time.isoformat() if row.event_time else None,
        "users": _extract_users(entities),
        "ips": _extract_ip_addresses(entities),
        "hostnames": _extract_hostnames(entities),
        "geo": _extract_geo_from_entities(entities),
    }


def _extract_geo_from_entities(entities: dict) -> list[dict]:
    geos = []
    for ip_ent in _extract_ips(entities):
        geo = ip_ent.get("geo") or {}
        if geo.get("country") or geo.get("city"):
            geos.append({
                "ipAddress": ip_ent.get("ipAddress"),
                "country": geo.get("country"),
                "city": geo.get("city"),
                "isKnownVpn": geo.get("isKnownVpn"),
                "isTorExit": geo.get("isTorExit"),
            })
    return geos


def investigate_ioc(
    session: Session,
    ioc_value: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Search all cases for a given IOC and build an investigation dossier."""

    ioc_type = detect_ioc_type(ioc_value)
    ioc_clean = ioc_value.strip()

    tenant_row = session.exec(
        select(TenantRow).where(TenantRow.tenant_id == tenant_id)
    ).first()

    if tenant_row is None:
        return _empty_result(ioc_clean, ioc_type)

    all_cases = session.exec(
        select(CaseRow)
        .where(CaseRow.tenant_id == tenant_row.id)
        .order_by(CaseRow.event_time.asc())
    ).all()

    matched_cases: list[CaseRow] = []
    for case in all_cases:
        ents = case.entities or {}
        if _case_matches_ioc(ents, ioc_type, ioc_clean):
            matched_cases.append(case)

    if not matched_cases:
        return _empty_result(ioc_clean, ioc_type)

    case_summaries = [_case_to_summary(c) for c in matched_cases]

    all_users: list[str] = []
    all_ips: list[str] = []
    all_hostnames: list[str] = []
    all_geos: list[dict] = []
    severity_counts: Counter[str] = Counter()
    alert_type_counts: Counter[str] = Counter()
    score_sum = 0

    for c in matched_cases:
        ents = c.entities or {}
        all_users.extend(_extract_users(ents))
        all_ips.extend(_extract_ip_addresses(ents))
        all_hostnames.extend(_extract_hostnames(ents))
        all_geos.extend(_extract_geo_from_entities(ents))
        severity_counts[c.severity] += 1
        alert_type_counts[c.alert_type] += 1
        score_sum += c.confidence_score

    unique_users = list(dict.fromkeys(all_users))
    unique_ips = list(dict.fromkeys(all_ips))
    unique_hostnames = list(dict.fromkeys(all_hostnames))

    seen_geos: set[str] = set()
    unique_geos = []
    for g in all_geos:
        key = f"{g.get('ipAddress')}:{g.get('country')}:{g.get('city')}"
        if key not in seen_geos:
            seen_geos.add(key)
            unique_geos.append(g)

    timeline = []
    for c in matched_cases:
        timeline.append({
            "time": c.event_time.isoformat() if c.event_time else None,
            "alertType": c.alert_type,
            "severity": c.severity,
            "title": c.title,
            "caseId": str(c.id),
        })

    first_seen = matched_cases[0].event_time
    last_seen = matched_cases[-1].event_time
    time_span_seconds = None
    if first_seen and last_seen:
        time_span_seconds = int((last_seen - first_seen).total_seconds())

    max_sev_rank = max(
        {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(c.severity, 0)
        for c in matched_cases
    )
    risk_level = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}.get(max_sev_rank, "medium")

    case_ids = {c.id for c in matched_cases}
    links = session.exec(
        select(IncidentCaseLink).where(IncidentCaseLink.case_id.in_(case_ids))  # type: ignore[attr-defined]
    ).all()
    incident_ids = list({link.incident_id for link in links})

    related_incidents = []
    for inc_id in incident_ids:
        inc = session.exec(select(Incident).where(Incident.id == inc_id)).first()
        if inc:
            related_incidents.append({
                "incidentId": str(inc.id),
                "title": inc.title,
                "severity": inc.severity,
                "status": inc.status,
                "confidenceScore": inc.confidence_score,
                "caseCount": inc.case_count,
                "riskLevel": inc.risk_level,
            })

    avg_score = round(score_sum / len(matched_cases)) if matched_cases else 0

    return {
        "ioc": ioc_clean,
        "iocType": ioc_type,
        "found": True,
        "totalHits": len(matched_cases),
        "riskLevel": risk_level,
        "avgConfidenceScore": avg_score,
        "firstSeen": first_seen.isoformat() if first_seen else None,
        "lastSeen": last_seen.isoformat() if last_seen else None,
        "timeSpanSeconds": time_span_seconds,
        "entityGraph": {
            "users": unique_users,
            "ips": unique_ips,
            "hostnames": unique_hostnames,
            "userCount": len(unique_users),
            "ipCount": len(unique_ips),
            "hostnameCount": len(unique_hostnames),
        },
        "geoData": unique_geos,
        "severityDistribution": dict(severity_counts),
        "alertTypeDistribution": dict(alert_type_counts),
        "timeline": timeline,
        "cases": case_summaries,
        "relatedIncidents": related_incidents,
    }


def _empty_result(ioc: str, ioc_type: str) -> dict[str, Any]:
    return {
        "ioc": ioc,
        "iocType": ioc_type,
        "found": False,
        "totalHits": 0,
        "riskLevel": "unknown",
        "avgConfidenceScore": 0,
        "firstSeen": None,
        "lastSeen": None,
        "timeSpanSeconds": None,
        "entityGraph": {
            "users": [], "ips": [], "hostnames": [],
            "userCount": 0, "ipCount": 0, "hostnameCount": 0,
        },
        "geoData": [],
        "severityDistribution": {},
        "alertTypeDistribution": {},
        "timeline": [],
        "cases": [],
        "relatedIncidents": [],
    }
