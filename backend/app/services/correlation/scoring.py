"""Incident confidence scoring, severity, and risk assessment."""
from __future__ import annotations

from typing import Any

from backend.app.db.models import Case as CaseRow
from backend.app.services.correlation.clustering import extract_entities
from backend.app.services.correlation.kill_chain import stage_order

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def compute_confidence(
    cases: list[CaseRow],
    stages: list[str],
    all_entities: dict[str, set[str]],
    time_span_seconds: int | None,
) -> tuple[int, str, list[dict[str, Any]]]:
    """Compute incident-level confidence with per-factor breakdown.

    Returns (score, label, breakdown) where breakdown is a list of
    {"factor": str, "points": int, "maxPoints": int, "detail": str}.
    """
    breakdown: list[dict[str, Any]] = []

    # Base
    base = 20
    breakdown.append({
        "factor": "Base",
        "points": base,
        "maxPoints": 20,
        "detail": "Starting score for any multi-stage incident",
    })

    # Stage count (max +30)
    stage_count = len(stages)
    stage_pts = min(stage_count * 10, 30)
    breakdown.append({
        "factor": "Stage count",
        "points": stage_pts,
        "maxPoints": 30,
        "detail": f"{stage_count} distinct kill-chain stage{'s' if stage_count != 1 else ''} × 10",
    })

    # Case count (max +15)
    if len(cases) >= 5:
        case_pts = 15
    elif len(cases) >= 3:
        case_pts = 10
    else:
        case_pts = 5
    breakdown.append({
        "factor": "Case count",
        "points": case_pts,
        "maxPoints": 15,
        "detail": f"{len(cases)} linked case{'s' if len(cases) != 1 else ''}",
    })

    # Entity consistency (max +15)
    entity_pts = 0
    per_case_users = [extract_entities(c)["users"] for c in cases]
    non_empty = [u for u in per_case_users if u]
    if len(non_empty) >= 2:
        common_users = non_empty[0]
        for u in non_empty[1:]:
            common_users = common_users & u
        if common_users:
            entity_pts = 15
    breakdown.append({
        "factor": "Entity consistency",
        "points": entity_pts,
        "maxPoints": 15,
        "detail": "All cases share the same user" if entity_pts > 0 else "Cases do not all share a common user",
    })

    # Time proximity (max +10)
    time_pts = 0
    if time_span_seconds is not None:
        hours = time_span_seconds / 3600
        if hours < 1:
            time_pts = 10
        elif hours < 4:
            time_pts = 7
        elif hours < 12:
            time_pts = 4
        detail = f"Events span {hours:.1f}h"
    else:
        detail = "Single event (no span)"
    breakdown.append({
        "factor": "Time proximity",
        "points": time_pts,
        "maxPoints": 10,
        "detail": detail,
    })

    # Chain coherence (+5)
    stage_orders = [stage_order(s) for s in stages]
    coherence_pts = 5 if stage_orders == sorted(stage_orders) else 0
    breakdown.append({
        "factor": "Chain coherence",
        "points": coherence_pts,
        "maxPoints": 5,
        "detail": "Stages follow logical attack order" if coherence_pts > 0 else "Stages are not in expected progression order",
    })

    # Mean case confidence (max +5)
    avg_conf = 0.0
    case_conf_pts = 0
    if cases:
        avg_conf = sum(c.confidence_score for c in cases) / len(cases)
        if avg_conf >= 70:
            case_conf_pts = 5
        elif avg_conf >= 50:
            case_conf_pts = 3
    breakdown.append({
        "factor": "Mean case confidence",
        "points": case_conf_pts,
        "maxPoints": 5,
        "detail": f"Average case score: {avg_conf:.0f}%",
    })

    score = min(base + stage_pts + case_pts + entity_pts + time_pts + coherence_pts + case_conf_pts, 100)

    if score >= 85:
        label = "critical"
    elif score >= 65:
        label = "high"
    elif score >= 45:
        label = "medium"
    else:
        label = "low"

    return score, label, breakdown


def compute_severity(
    cases: list[CaseRow],
    stage_count: int,
    stages: list[str],
) -> str:
    """Incident-level severity with independent override logic."""
    stage_set = set(stages)
    max_rank = max(_SEVERITY_RANK.get(c.severity, 1) for c in cases)
    rank_to_sev = {0: "low", 1: "medium", 2: "high", 3: "critical"}

    if stage_count >= 4 and "exfiltration" in stage_set:
        return "critical"

    if "exfiltration" in stage_set:
        max_rank = max(max_rank, 2)

    if "privilege_escalation" in stage_set and "execution" in stage_set:
        max_rank = max(max_rank, 2)

    if stage_count >= 4:
        max_rank = min(max_rank + 2, 3)
    elif stage_count >= 3:
        max_rank = min(max_rank + 1, 3)

    return rank_to_sev.get(max_rank, "high")


# ── Risk assessment (separate from confidence) ──────────────────────

_HIGH_RISK_STAGES = {"exfiltration", "lateral_movement", "execution"}
_CRITICAL_COMBOS = [
    {"exfiltration", "credential_access"},
    {"exfiltration", "execution"},
    {"lateral_movement", "privilege_escalation"},
]


def compute_risk(
    stages: list[str],
    severity: str,
    case_count: int,
    entities: dict[str, set[str]],
) -> tuple[str, list[dict[str, str]]]:
    """Assess risk level (how bad) independent of confidence (how sure).

    Returns (risk_level, risk_factors).
    """
    from backend.app.services.correlation.kill_chain import _STAGE_LABELS, stage_order

    stage_set = set(stages)
    factors: list[dict[str, str]] = []
    risk_score = 0

    has_exfil = "exfiltration" in stage_set
    high_stages = stage_set & _HIGH_RISK_STAGES
    combo_match = any(combo <= stage_set for combo in _CRITICAL_COMBOS)

    if has_exfil:
        risk_score += 40
        factors.append({
            "factor": "Data exfiltration detected",
            "impact": "critical",
            "detail": "Active data theft indicates immediate business impact",
        })

    if combo_match:
        risk_score += 25
        factors.append({
            "factor": "High-risk stage combination",
            "impact": "critical",
            "detail": "Multiple dangerous stages suggest a coordinated attack",
        })

    if len(stages) >= 4:
        risk_score += 20
        factors.append({
            "factor": "Deep kill-chain penetration",
            "impact": "high",
            "detail": f"{len(stages)} stages — attacker has significant foothold",
        })
    elif len(stages) >= 3:
        risk_score += 10
        factors.append({
            "factor": "Multi-stage progression",
            "impact": "medium",
            "detail": f"{len(stages)} stages detected",
        })

    if len(high_stages) >= 2:
        risk_score += 15
        factors.append({
            "factor": "Multiple high-risk stages",
            "impact": "high",
            "detail": ", ".join(
                _STAGE_LABELS.get(s, s) for s in sorted(high_stages, key=stage_order)
            ),
        })

    user_count = len(entities.get("users", set()))
    if user_count > 1:
        risk_score += 10
        factors.append({
            "factor": "Multiple users affected",
            "impact": "high",
            "detail": f"{user_count} distinct users involved",
        })

    if case_count >= 5:
        risk_score += 5
        factors.append({
            "factor": "High event volume",
            "impact": "medium",
            "detail": f"{case_count} correlated events",
        })

    if not factors:
        factors.append({
            "factor": "Standard multi-stage incident",
            "impact": "medium",
            "detail": "No additional risk amplifiers detected",
        })

    if risk_score >= 60:
        level = "critical"
    elif risk_score >= 35:
        level = "high"
    elif risk_score >= 15:
        level = "medium"
    else:
        level = "low"

    return level, factors
