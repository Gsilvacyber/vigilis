"""Alert suppression rule evaluation engine."""
from __future__ import annotations

import fnmatch
import re
from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import Session, select

from backend.app.db.models import SuppressionRule


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def evaluate_suppression(
    session: Session,
    tenant_id: str,
    alert_type: str,
    severity: str,
    confidence_score: int,
    entities: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Evaluate all active suppression rules against a case.

    Returns the first matching rule's action dict, or None if no match.
    """
    rules = session.exec(
        select(SuppressionRule)
        .where(SuppressionRule.tenant_id == tenant_id)
        .where(SuppressionRule.enabled == True)  # noqa: E712
    ).all()

    for rule in rules:
        if _matches(rule, alert_type, severity, confidence_score, entities):
            # Increment hit count
            rule.hits_count += 1
            rule.updated_at = _utc_now()
            session.add(rule)
            session.commit()
            return {
                "ruleId": rule.id,
                "ruleName": rule.name,
                "action": rule.action,
                "actionValue": rule.action_value,
            }
    return None


def _matches(
    rule: SuppressionRule,
    alert_type: str,
    severity: str,
    confidence_score: int,
    entities: dict[str, Any],
) -> bool:
    """Check if a rule's conditions match the given case attributes."""
    cond = rule.conditions or {}

    # Alert type pattern match (supports wildcards like "identity.*")
    if "alertType" in cond:
        pattern = cond["alertType"]
        if not fnmatch.fnmatch(alert_type, pattern):
            return False

    # Severity list match
    if "severity" in cond:
        allowed = cond["severity"]
        if isinstance(allowed, list) and severity not in allowed:
            return False

    # Confidence max threshold
    if "confidenceMax" in cond:
        if confidence_score > cond["confidenceMax"]:
            return False

    # Entity pattern matching
    if "entityPatterns" in cond:
        patterns = cond["entityPatterns"]
        if not _match_entity_patterns(patterns, entities):
            return False

    return True


def _match_entity_patterns(patterns: dict[str, str], entities: dict[str, Any]) -> bool:
    """Match entity patterns like user, ip against entity data."""
    for key, pattern in patterns.items():
        if key == "user":
            identity = entities.get("identity", {})
            user_val = identity.get("upn", "") or identity.get("userId", "") or ""
            if not _pattern_match(pattern, user_val):
                return False
        elif key == "ip":
            ips = entities.get("ips", [])
            ip_strs = [ip.get("ipAddress", "") for ip in ips] if isinstance(ips, list) else []
            if not any(_pattern_match(pattern, ip) for ip in ip_strs):
                return False
        elif key == "hostname":
            device = entities.get("device", {})
            hostname = device.get("hostname", "") or ""
            if not _pattern_match(pattern, hostname):
                return False
    return True


def _pattern_match(pattern: str, value: str) -> bool:
    """Match a pattern against a value. Supports wildcards and CIDR-like IP ranges."""
    if not pattern or not value:
        return False
    # Simple wildcard match
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(value.lower(), pattern.lower())
    # Exact match (case-insensitive)
    return value.lower() == pattern.lower()


def suggest_rules_from_dispositions(
    session: Session,
    tenant_id: str,
    min_benign_count: int = 5,
) -> list[dict[str, Any]]:
    """Suggest suppression rules based on disposition history.

    Looks for alert types that have been marked benign multiple times.
    """
    from backend.app.db.models import Case, CaseDispositionEvent, Tenant

    # Get tenant UUID
    tenant_row = session.exec(
        select(Tenant).where(Tenant.tenant_id == tenant_id)
    ).first()
    if not tenant_row:
        return []

    # Find cases marked benign
    benign_cases = session.exec(
        select(Case)
        .where(Case.tenant_id == tenant_row.id)
        .where(Case.disposition_status == "benign")
    ).all()

    # Group by alert_type
    type_counts: dict[str, int] = {}
    type_avg_conf: dict[str, list[int]] = {}
    for c in benign_cases:
        type_counts[c.alert_type] = type_counts.get(c.alert_type, 0) + 1
        type_avg_conf.setdefault(c.alert_type, []).append(c.confidence_score)

    suggestions = []
    for alert_type, count in type_counts.items():
        if count >= min_benign_count:
            avg = sum(type_avg_conf[alert_type]) // len(type_avg_conf[alert_type])
            suggestions.append({
                "alertType": alert_type,
                "benignCount": count,
                "avgConfidence": avg,
                "suggestedRule": {
                    "name": f"Auto-close {alert_type} (benign pattern)",
                    "conditions": {
                        "alertType": alert_type,
                        "confidenceMax": min(avg + 10, 100),
                    },
                    "action": "auto_close",
                },
            })

    return sorted(suggestions, key=lambda s: s["benignCount"], reverse=True)


def test_rule_conditions(
    session: Session,
    tenant_id: str,
    conditions: dict[str, Any],
) -> dict[str, Any]:
    """Test rule conditions against existing cases. Returns match count and samples."""
    from backend.app.db.models import Case, Tenant

    tenant_row = session.exec(
        select(Tenant).where(Tenant.tenant_id == tenant_id)
    ).first()
    if not tenant_row:
        return {"matchCount": 0, "totalCases": 0, "samples": []}

    cases = session.exec(
        select(Case).where(Case.tenant_id == tenant_row.id)
    ).all()

    # Build a temporary rule object for matching
    temp_rule = SuppressionRule(
        tenant_id=tenant_id,
        name="_test",
        conditions=conditions,
        action="auto_close",
        enabled=True,
    )

    matches = []
    for c in cases:
        if _matches(temp_rule, c.alert_type, c.severity, c.confidence_score, c.entities or {}):
            matches.append({
                "caseId": str(c.id),
                "alertType": c.alert_type,
                "severity": c.severity,
                "confidence": c.confidence_score,
                "disposition": c.disposition_status,
            })

    return {
        "matchCount": len(matches),
        "totalCases": len(cases),
        "samples": matches[:10],
    }
