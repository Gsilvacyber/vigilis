"""Title, summary, narrative, and workflow generation for incidents."""
from __future__ import annotations

from typing import Any

from backend.app.db.models import Case as CaseRow
from backend.app.services.correlation.kill_chain import (
    _STAGE_LABELS,
    get_stage,
    stage_order,
)


# ── Title generation ─────────────────────────────────────────────────

_ATTACK_PATTERNS: list[tuple[set[str], str]] = [
    ({"initial_access", "credential_access", "exfiltration"},
     "Account compromise and data exfiltration"),
    ({"initial_access", "privilege_escalation", "exfiltration"},
     "Account compromise and data exfiltration"),
    ({"initial_access", "privilege_escalation", "execution", "exfiltration"},
     "Full attack chain: compromise to exfiltration"),
    ({"initial_access", "privilege_escalation", "execution"},
     "Account takeover with code execution"),
    ({"initial_access", "credential_access", "lateral_movement"},
     "Credential abuse and lateral movement"),
    ({"persistence", "credential_access", "lateral_movement"},
     "Account compromise and mailbox persistence"),
    ({"initial_access", "persistence"},
     "Account compromise and mailbox persistence"),
    ({"credential_access", "persistence"},
     "Credential theft and mailbox persistence"),
    ({"credential_access", "privilege_escalation"},
     "Credential theft and privilege escalation"),
    ({"credential_access", "lateral_movement"},
     "Credential abuse and lateral movement"),
    ({"execution", "exfiltration"},
     "Malicious execution and data theft"),
    ({"initial_access", "lateral_movement"},
     "Unauthorized access and lateral movement"),
    ({"privilege_escalation", "execution"},
     "Privilege escalation and code execution"),
]


def generate_title(
    stages: list[str],
    entities: dict[str, set[str]],
) -> str:
    """Generate a descriptive incident title based on attack pattern."""
    stage_set = set(stages)

    title_base = None
    for pattern, desc in _ATTACK_PATTERNS:
        if pattern <= stage_set:
            title_base = desc
            break

    if title_base is None:
        stage_labels = [_STAGE_LABELS.get(s, s) for s in stages[:3]]
        title_base = " and ".join(stage_labels) if len(stage_labels) <= 2 else (
            ", ".join(stage_labels[:-1]) + ", and " + stage_labels[-1]
        )

    users_list = sorted(entities.get("users", set()))
    if users_list:
        user_str = users_list[0].split("@")[0]
        if len(users_list) > 1:
            user_str += f" (+{len(users_list) - 1})"
        return f"{title_base} — {user_str}"
    return title_base


def generate_summary(
    stages: list[str],
    entities: dict[str, set[str]],
    case_count: int,
    time_span_seconds: int | None,
    confidence_score: int,
) -> str:
    """One-liner: '4-stage attack chain affecting alice (4 cases, 1.2h window, confidence: 87%)'."""
    stage_count = len(stages)

    users = sorted(entities.get("users", set()))
    if users:
        user_str = users[0].split("@")[0]
        if len(users) > 1:
            user_str += f" (+{len(users) - 1})"
        target = f" affecting {user_str}"
    else:
        target = ""

    if time_span_seconds is not None and time_span_seconds > 0:
        hours = time_span_seconds / 3600
        if hours < 1:
            window = f"{int(time_span_seconds / 60)}m window"
        else:
            window = f"{hours:.1f}h window"
    else:
        window = "single event"

    return (
        f"{stage_count}-stage attack chain{target} "
        f"({case_count} case{'s' if case_count != 1 else ''}, "
        f"{window}, confidence: {confidence_score}%)"
    )


def build_narrative(
    cases: list[CaseRow],
    stages: list[str],
    entities: dict[str, set[str]],
    linkage_reasons: list[dict[str, str]],
    gaps: list[dict[str, Any]],
) -> str:
    """Build a human-readable attack storyline from a case cluster."""
    sorted_cases = sorted(cases, key=lambda c: c.event_time)

    users_str = ", ".join(sorted(entities["users"])) or "unknown user"
    ips_str = ", ".join(sorted(entities["ips"])) or "unknown IP"

    stage_labels = [_STAGE_LABELS.get(s, s) for s in stages]
    chain_str = " → ".join(stage_labels)

    time_start = sorted_cases[0].event_time.strftime("%H:%M:%S")
    time_end = sorted_cases[-1].event_time.strftime("%H:%M:%S")
    span = sorted_cases[-1].event_time - sorted_cases[0].event_time
    span_min = max(1, int(span.total_seconds() / 60))

    lines = [
        f"Multi-stage attack detected involving {users_str} from {ips_str}.",
        f"Kill chain progression: {chain_str}.",
        f"{len(cases)} events over {span_min} minute(s) ({time_start} – {time_end}).",
        "",
    ]

    # Linkage evidence
    lines.append("Correlation evidence:")
    for r in linkage_reasons:
        weight_icon = {"strong": "[!]", "moderate": "[~]", "supporting": "[.]"}.get(
            r.get("weight", ""), "[?]"
        )
        lines.append(f"  {weight_icon} {r['detail']}")
    lines.append("")

    # Kill chain gaps
    missing = [g for g in gaps if g["status"] == "missing"]
    if missing:
        lines.append("Open investigation gaps:")
        for g in missing:
            lines.append(f"  \u2716 {g['label']} \u2014 not yet observed, likely occurred")
        lines.append("")

    # Timeline
    lines.append("Timeline:")
    for c in sorted_cases:
        ts = c.event_time.strftime("%H:%M:%S")
        stage = _STAGE_LABELS.get(get_stage(c.alert_type), c.alert_type)
        sev = c.severity.upper()
        lines.append(f"  [{ts}] {stage}: {c.title} (severity: {sev}, score: {c.confidence_score})")

    return "\n".join(lines)


# ── Recommended actions ─────────────────────────────────────────────

_STAGE_ACTIONS: dict[str, list[str]] = {
    "initial_access": [
        "Review authentication logs for anomalous sign-ins",
        "Check email forwarding rules for unauthorized changes",
    ],
    "credential_access": [
        "Reset credentials for affected accounts immediately",
        "Revoke active sessions and OAuth tokens",
        "Enable MFA if not already enforced",
    ],
    "privilege_escalation": [
        "Review role and permission changes",
        "Remove unauthorized privilege grants",
        "Audit admin group memberships",
    ],
    "execution": [
        "Isolate affected endpoint from the network",
        "Collect forensic artifacts (memory, disk image)",
        "Run full malware scan on affected systems",
    ],
    "lateral_movement": [
        "Isolate affected devices to contain spread",
        "Check for additional compromised accounts",
        "Review network segmentation controls",
    ],
    "exfiltration": [
        "Investigate data exfiltration volume and targets",
        "Block identified exfiltration channels",
        "Assess data exposure and notify stakeholders if needed",
    ],
    "persistence": [
        "Search for backdoor accounts or scheduled tasks",
        "Review startup scripts and registry modifications",
    ],
    "collection": [
        "Check for unusual file access patterns",
        "Review data staging locations",
    ],
    "reconnaissance": [
        "Monitor for follow-up exploitation attempts",
    ],
}


def generate_recommended_actions(
    stages: list[str],
    entities: dict[str, set[str]],
) -> list[dict[str, str]]:
    """Generate prioritized response actions based on kill chain stages present."""
    actions: list[dict[str, str]] = []
    seen: set[str] = set()

    priority_order = [
        "exfiltration", "execution", "lateral_movement",
        "credential_access", "privilege_escalation",
        "initial_access", "persistence", "collection", "reconnaissance",
    ]

    for stage in priority_order:
        if stage not in stages:
            continue
        for action_text in _STAGE_ACTIONS.get(stage, []):
            if action_text not in seen:
                seen.add(action_text)
                actions.append({
                    "action": action_text,
                    "stage": stage,
                    "priority": "immediate" if stage in (
                        "exfiltration", "execution", "lateral_movement", "credential_access"
                    ) else "recommended",
                })

    return actions


# ── Analyst workflow prediction ─────────────────────────────────────

def predict_workflow(
    severity: str,
    confidence_score: int,
    risk_level: str,
    stages: list[str],
    case_count: int,
) -> dict[str, Any]:
    """Predict how a SOC analyst would handle this incident."""
    stage_set = set(stages)

    would_escalate = (
        severity in ("critical", "high")
        and confidence_score >= 65
    ) or (
        risk_level == "critical"
    )

    escalation_reason = []
    if severity == "critical":
        escalation_reason.append("Critical severity")
    if risk_level == "critical":
        escalation_reason.append("Critical risk")
    if confidence_score >= 85:
        escalation_reason.append("Very high confidence")
    if "exfiltration" in stage_set:
        escalation_reason.append("Active data exfiltration")
    if not escalation_reason and severity == "high":
        escalation_reason.append("High severity incident")

    would_contain = (
        "execution" in stage_set
        or "lateral_movement" in stage_set
        or "exfiltration" in stage_set
    )

    containment_actions = []
    if "execution" in stage_set:
        containment_actions.append("Isolate endpoint")
    if "lateral_movement" in stage_set:
        containment_actions.append("Network segmentation")
    if "credential_access" in stage_set:
        containment_actions.append("Credential reset")
    if "exfiltration" in stage_set:
        containment_actions.append("Block exfiltration channel")

    auto_containable = (
        confidence_score >= 80
        and would_contain
        and case_count >= 3
    )

    return {
        "wouldEscalate": would_escalate,
        "escalationReasons": escalation_reason,
        "escalationTarget": "Tier 2 / Incident Response" if would_escalate else "Tier 1 review",
        "wouldAutoContain": auto_containable,
        "containmentActions": containment_actions,
        "autoContainReason": (
            "High confidence + clear containment path"
            if auto_containable
            else "Manual review required before containment"
        ),
        "estimatedTriage": "< 2 min (automated)" if auto_containable else "5-15 min (manual)",
        "disposition": (
            "auto-escalate" if would_escalate and auto_containable
            else "escalate" if would_escalate
            else "investigate" if confidence_score >= 50
            else "monitor"
        ),
    }
