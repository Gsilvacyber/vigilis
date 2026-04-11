"""Alert-to-case grouping engine for Vigilis.

Groups enriched alerts into incident cases using category-aware
composite keys. Each alert is enriched individually first, then
grouped by entity anchor + alert type + contextual key + time window.

Two modes:
  grouping=False  →  1 alert = 1 case  (debug mode)
  grouping=True   →  N alerts = 1 case  (SOC mode)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def _hash_grouping_key(key: str) -> str:
    """Create a stable, collision-resistant ID from a grouping key.

    The full grouping key can exceed 50 chars (email + alert_type + bucket),
    so we hash it to produce a fixed-length identifier that preserves
    uniqueness across days and alert types.
    """
    return hashlib.sha256(key.encode()).hexdigest()[:32]

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
from backend.app.services.alert_mapper import (
    _DEVICE_FIELDS,
    _EMAIL_METADATA_FIELDS,
    _IDENTITY_FIELDS,
    _IP_FIELDS,
    extract_alert_type_category,
    extract_event_time,
    _find_field,
)

# ── Severity helpers ─────────────────────────────────────────────────────

_SEVERITY_RANK = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.lower().strip(), 2)


def _max_severity(*severities: str) -> str:
    best = max(severities, key=_severity_rank)
    return best.lower().strip()


# ── Data structures ──────────────────────────────────────────────────────

@dataclass
class EnrichedAlert:
    """An individual alert that has been enriched but not yet grouped."""
    index: int                              # original row index
    row: dict[str, Any]                     # original CSV/JSON row
    alert_type: str                         # detected alert type
    severity: str                           # parsed severity
    case_data: CaseV0_2                     # fully enriched case object
    score: int = 0                          # confidence score
    label: str = "low"                      # confidence label
    signals_fired: int = 0
    ready_for_action: bool = False
    event_time: datetime | None = None      # extracted timestamp
    grouping_key: str = ""                  # computed composite key
    validation_warnings: list[str] = field(default_factory=list)


@dataclass
class AlertGroup:
    """A group of related alerts that form a single incident case."""
    key: str                                # composite grouping key
    grouping_reason: str                    # human-readable explanation
    alerts: list[EnrichedAlert] = field(default_factory=list)

    # Computed from alerts
    primary_alert_type: str = ""
    highest_severity: str = "medium"
    highest_score: int = 0
    best_label: str = "low"
    earliest_time: datetime | None = None
    latest_time: datetime | None = None
    entity_anchor: str = ""                 # the primary entity (user, device, etc.)
    member_indices: list[int] = field(default_factory=list)
    case_id: str | None = None              # set after case creation


# ── Grouping key computation (category-aware) ────────────────────────────

from backend.app.core.config import settings as _settings

DEFAULT_WINDOW_MINUTES = _settings.grouping_window_minutes


def _time_bucket(dt: datetime | None, window_minutes: int) -> str:
    """Quantize a datetime into fixed-width time buckets."""
    if dt is None:
        return "no_time"
    epoch = int(dt.timestamp())
    bucket = epoch // (window_minutes * 60)
    return str(bucket)


def _adaptive_time_bucket(
    dt: datetime | None,
    window_minutes: int,
    anchor: str,
    alert_type: str,
    bucket_counts: dict[tuple[str, str, str], int],
) -> str:
    """Sliding-window time bucket based on first-seen anchor.

    OLD: Fixed epoch division (epoch // window_sec) created hard boundaries
    that split 75-minute attacks into 2 groups at the 60-min mark.

    NEW: Anchor-based sliding window.  The first alert for an entity+type
    sets the anchor timestamp.  Subsequent alerts within window_minutes of
    that anchor join the same bucket.  This keeps multi-phase attacks
    together regardless of when they start relative to epoch boundaries.

    Works correctly with out-of-order data because it checks the anchor
    time, not arrival order.
    """
    if dt is None:
        return "no_time"
    epoch = int(dt.timestamp())
    window_sec = window_minutes * 60
    entity_key = (anchor.lower(), alert_type)

    # Check if this entity+type already has an anchor bucket
    for (e_anchor, e_type, bucket_id), info in bucket_counts.items():
        if (e_anchor, e_type) == entity_key:
            # info stores (anchor_epoch, count)
            if isinstance(info, tuple):
                anchor_epoch, count = info
            else:
                # Backwards compat: old format stored just a count
                anchor_epoch = int(bucket_id) * window_sec
                count = info

            # Check if this alert is within the window of the existing anchor
            if abs(epoch - anchor_epoch) <= window_sec:
                bucket_counts[(e_anchor, e_type, bucket_id)] = (anchor_epoch, count + 1)
                return bucket_id

    # No existing anchor — create one using epoch-based bucket ID
    bucket = epoch // window_sec
    bucket_id = str(bucket)
    bucket_counts[(anchor.lower(), alert_type, bucket_id)] = (epoch, 1)
    return bucket_id


def compute_grouping_key(
    row: dict[str, Any],
    alert_type: str,
    event_time: datetime | None,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    bucket_counts: dict[tuple[str, str, str], int] | None = None,
) -> tuple[str, str]:
    """Compute a category-aware grouping key and human-readable reason.

    Returns (key, reason) tuple.

    Key strategy by category:
      identity → user + alert_type + source_ip + time_bucket
      endpoint → device + alert_type + user_if_present + time_bucket
      email    → recipient + alert_type + sender + time_bucket
      cloud    → user/account + alert_type + source_ip_if_present + time_bucket
      network  → source_ip + alert_type + device_if_present + time_bucket

    Uses adaptive time bucketing: alerts near a bucket boundary may be
    assigned to the adjacent bucket if it already has alerts for the
    same entity + alert type.
    """
    category = extract_alert_type_category(alert_type)

    # Pre-extract anchor for adaptive bucketing (need it before time_b)
    user = (_find_field(row, _IDENTITY_FIELDS) or "").lower().strip()
    ip = (_find_field(row, _IP_FIELDS) or "").lower().strip()
    device = (_find_field(row, _DEVICE_FIELDS) or "").lower().strip()
    _pre_anchor = user or device or ip or "unknown"

    if bucket_counts is None:
        bucket_counts = {}
    time_b = _adaptive_time_bucket(event_time, window_minutes, _pre_anchor, alert_type, bucket_counts)

    recipient = ""
    sender = ""

    # Email-specific: extract recipient and sender
    if category == "email":
        for k, v in row.items():
            key = k.lower().strip()
            leaf = key.rsplit(".", 1)[-1] if "." in key else key
            if leaf in ("mailto", "mail_to", "recipient", "to") and v:
                recipient = str(v).lower().strip()
            if leaf in ("mailfrom", "mail_from", "sender", "from") and v:
                sender = str(v).lower().strip()

    # Category-aware key construction
    #
    # Design principles:
    #   - Identity: group by user (IP is secondary — same user from
    #     different IPs is still one investigation)
    #   - Endpoint: group by user when present (same user on multiple
    #     devices = one investigation), else by device
    #   - Cloud: group by user/account (IP optional — API calls may
    #     come from different IPs)
    #   - Email: group by recipient + sender domain
    #   - Network: group by source_ip
    #   - Empty user → fall through to device → IP → "unknown"

    if category == "identity":
        anchor = user or device or ip or "unknown"
        key = f"{anchor}|{alert_type}|{time_b}"
        reason = f"user={anchor}, alert_type={alert_type}, bucket={time_b}"

    elif category == "endpoint":
        # Prefer user over device — same user doing registry_modification
        # on 3 different hosts is one investigation, not three
        anchor = user or device or "unknown"
        key = f"{anchor}|{alert_type}|{time_b}"
        reason = f"{'user' if user else 'device'}={anchor}, alert_type={alert_type}, bucket={time_b}"

    elif category == "email":
        anchor = recipient or user or "unknown"
        context = sender or "any_sender"
        key = f"{anchor}|{alert_type}|{context}|{time_b}"
        reason = f"recipient={anchor}, alert_type={alert_type}, sender={context}, bucket={time_b}"

    elif category == "cloud":
        # Group by user/account only — IP is optional, API calls may
        # originate from different IPs for the same session
        anchor = user or ip or "unknown"
        key = f"{anchor}|{alert_type}|{time_b}"
        reason = f"account={anchor}, alert_type={alert_type}, bucket={time_b}"

    elif category == "network":
        anchor = ip or device or "unknown"
        context = device if ip else ""
        key = f"{anchor}|{alert_type}|{context}|{time_b}"
        reason = f"source_ip={anchor}, alert_type={alert_type}"
        if context:
            reason += f", device={context}"
        reason += f", bucket={time_b}"

    elif category == "dlp":
        anchor = user or "unknown"
        context = str(row.get("_dataClassification") or row.get("classification") or "unclassified").lower()
        key = f"{anchor}|{alert_type}|{context}|{time_b}"
        reason = f"user={anchor}, alert_type={alert_type}, classification={context}, bucket={time_b}"

    else:
        # Fallback: best available entity
        anchor = user or device or ip or "unknown"
        key = f"{anchor}|{alert_type}|{time_b}"
        reason = f"entity={anchor}, alert_type={alert_type}, bucket={time_b}"

    return key, reason


# ── Grouping logic ───────────────────────────────────────────────────────

def _extract_public_ips(row: dict[str, Any]) -> list[str]:
    """Extract all public IPs from a row's ip fields."""
    import ipaddress as _ipaddress

    ips: list[str] = []
    for key in ("ips", "ip", "ipAddress", "sourceIp", "source_ip"):
        val = row.get(key)
        if val is None:
            continue
        if isinstance(val, list):
            for item in val:
                addr = item.get("ipAddress", "") if isinstance(item, dict) else str(item)
                if addr:
                    try:
                        if not _ipaddress.ip_address(addr).is_private:
                            ips.append(addr)
                    except ValueError:
                        pass
        elif isinstance(val, str) and val:
            try:
                if not _ipaddress.ip_address(val).is_private:
                    ips.append(val)
            except ValueError:
                pass
    return ips


def _extract_user_from_row(row: dict[str, Any]) -> str:
    """Extract user UPN from a row."""
    identity = row.get("identity") or row.get("user") or {}
    if isinstance(identity, dict):
        return (identity.get("upn") or identity.get("email") or "").lower().strip()
    return str(identity).lower().strip()


def _detect_batch_spray(
    alerts: list[EnrichedAlert],
    window_minutes: int,
) -> tuple[list[AlertGroup], set[int]]:
    """Detect spray patterns: same public IP, 3+ distinct users.

    Returns (spray_groups, consumed_indices) where each spray_group is
    a single AlertGroup containing all matching alerts reclassified as
    identity.passwordSpray.
    """
    ip_buckets: dict[str, list[EnrichedAlert]] = {}
    for alert in alerts:
        for ip in _extract_public_ips(alert.row):
            ip_buckets.setdefault(ip, []).append(alert)

    spray_groups: list[AlertGroup] = []
    consumed: set[int] = set()

    for ip, bucket in ip_buckets.items():
        users = {_extract_user_from_row(a.row) for a in bucket} - {""}
        if len(users) >= 3:
            for a in bucket:
                a.alert_type = "identity.passwordSpray"
                consumed.add(a.index)

            time_b = _time_bucket(
                bucket[0].event_time if bucket[0].event_time else None,
                window_minutes,
            )
            key = f"spray|{ip}|{time_b}"
            group = AlertGroup(
                key=key,
                grouping_reason=f"Password spray from {ip} targeting {len(users)} users",
                alerts=list(bucket),
                primary_alert_type="identity.passwordSpray",
                entity_anchor=ip,
            )
            _recompute_group_metadata(group)
            spray_groups.append(group)

    return spray_groups, consumed


def group_enriched_alerts(
    alerts: list[EnrichedAlert],
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> list[AlertGroup]:
    """Group enriched alerts into incident cases by composite key."""
    # Per-call bucket state — no cross-request contamination
    bucket_counts: dict[tuple[str, str, str], int] = {}

    # ── Spray detection (pre-grouping) ────────────────────────────────
    spray_groups, spray_consumed = _detect_batch_spray(alerts, window_minutes)

    # Compute keys and assign (skip alerts consumed by spray detection)
    groups_dict: dict[str, tuple[AlertGroup, str]] = {}  # key -> (group, reason)

    for alert in alerts:
        if alert.index in spray_consumed:
            continue
        alert.event_time = extract_event_time(alert.row)
        key, reason = compute_grouping_key(
            alert.row, alert.alert_type, alert.event_time, window_minutes,
            bucket_counts=bucket_counts,
        )
        alert.grouping_key = key

        if key not in groups_dict:
            groups_dict[key] = (AlertGroup(key=key, grouping_reason=reason), reason)
        group, _ = groups_dict[key]
        group.alerts.append(alert)

    # Finalize each group's computed fields
    result: list[AlertGroup] = []
    for key, (group, reason) in groups_dict.items():
        group.grouping_reason = reason
        group.member_indices = [a.index for a in group.alerts]

        # Primary alert type = most frequent
        type_counts: dict[str, int] = {}
        for a in group.alerts:
            type_counts[a.alert_type] = type_counts.get(a.alert_type, 0) + 1
        group.primary_alert_type = max(type_counts, key=type_counts.get)  # type: ignore[arg-type]

        # Severity & score
        group.highest_severity = group.alerts[0].severity
        group.highest_score = group.alerts[0].score
        group.best_label = group.alerts[0].label

        for a in group.alerts:
            if _severity_rank(a.severity) > _severity_rank(group.highest_severity):
                group.highest_severity = a.severity
            if a.score > group.highest_score:
                group.highest_score = a.score
                group.best_label = a.label

        # Time range
        times = [a.event_time for a in group.alerts if a.event_time]
        if times:
            group.earliest_time = min(times)
            group.latest_time = max(times)

        # Entity anchor from first alert
        anchor = _find_field(group.alerts[0].row, _IDENTITY_FIELDS) \
            or _find_field(group.alerts[0].row, _DEVICE_FIELDS) \
            or _find_field(group.alerts[0].row, _IP_FIELDS) \
            or "unknown"
        group.entity_anchor = anchor

        result.append(group)

    # Include spray groups in the result
    result.extend(spray_groups)

    # ── Alert-level deduplication ─────────────────────────────────────────
    # Remove exact duplicate alerts within each group. Duplicates are
    # identified by (user, alert_type, 10-min-proximity timestamp, source_id).
    for group in result:
        group.alerts = _dedup_within_group(group.alerts)
        group.member_indices = [a.index for a in group.alerts]

    # ── Same-type user grouping (second pass) ──────────────────────────────
    # Merge groups that share the same user AND the same alert type within
    # the same time window. Groups with different alert types for the same
    # user stay separate so the incident correlator can detect multi-stage
    # attacks (each alert type = one kill-chain stage).
    result = _merge_same_user_groups(result, window_minutes)

    # Sort by earliest time (most recent first), then by score
    result.sort(key=lambda g: (
        -(g.earliest_time.timestamp() if g.earliest_time else 0),
        -g.highest_score,
    ))
    return result


def _alert_fingerprint(alert: EnrichedAlert) -> str:
    """Compute a content fingerprint for deduplication.

    Uses a 10-minute time bucket so events within 10 minutes of each other
    with the same user + alert_type are considered duplicates, even if
    source IDs differ (common when the same alert arrives from separate
    API calls or data sources).
    """
    identity = alert.row.get("identity") or alert.row.get("user") or ""
    if isinstance(identity, dict):
        identity = identity.get("upn", "")
    # 10-minute bucket for proximity-based dedup
    if alert.event_time:
        epoch = int(alert.event_time.timestamp())
        ts = str(epoch // 600)
    else:
        ts = ""
    src_id = ""
    for k in ("source_alert_id", "sourceAlertId", "alert_id", "event_id"):
        if k in alert.row:
            src_id = str(alert.row[k])
            break
    return f"{identity}|{alert.alert_type}|{ts}|{src_id}"


def _dedup_within_group(alerts: list[EnrichedAlert]) -> list[EnrichedAlert]:
    """Collapse duplicate alerts within a group, keeping the highest-scored."""
    seen: dict[str, EnrichedAlert] = {}
    for alert in alerts:
        fp = _alert_fingerprint(alert)
        if fp not in seen or alert.score > seen[fp].score:
            seen[fp] = alert
    return list(seen.values())


def _extract_group_upn(group: AlertGroup) -> str:
    """Extract UPN from a group, checking identity fields and mailbox fields."""
    user = str(group.entity_anchor or "").lower().strip()
    if "@" in user:
        return user

    # Fallback: scan alerts for UPN in identity or mailbox fields
    for alert in group.alerts:
        row = alert.row
        identity = row.get("identity") or {}
        if isinstance(identity, dict):
            upn = (identity.get("upn") or identity.get("email") or "").lower().strip()
            if "@" in upn:
                return upn
        mailbox = row.get("mailbox") or {}
        if isinstance(mailbox, dict):
            addr = (mailbox.get("primaryAddress") or "").lower().strip()
            if "@" in addr:
                return addr
    return ""


def _merge_same_user_groups(
    groups: list[AlertGroup],
    window_minutes: int,
) -> list[AlertGroup]:
    """Second pass: merge groups sharing the same user AND same alert type
    within the same time window.

    Only merges groups that already share a primary alert type. Groups with
    different alert types for the same user stay separate so the incident
    correlator can detect multi-stage attacks (each alert type = one
    kill-chain stage).

    Extracts UPN from identity and mailbox fields so that email alerts
    (which may have the user in mailbox.primaryAddress) merge with identity
    alerts for the same user when they share the same alert type.
    """
    user_buckets: dict[str, list[int]] = {}
    for i, group in enumerate(groups):
        upn = _extract_group_upn(group)
        if not upn:
            continue
        bucket = _time_bucket(group.earliest_time, window_minutes)
        # Include alert type in the merge key so only same-type groups merge
        key = f"{upn}|{group.primary_alert_type}|{bucket}"
        user_buckets.setdefault(key, []).append(i)

    consumed: set[int] = set()
    for key, indices in user_buckets.items():
        if len(indices) <= 1:
            continue
        primary_idx = indices[0]
        primary = groups[primary_idx]
        for idx in indices[1:]:
            secondary = groups[idx]
            primary.alerts.extend(secondary.alerts)
            primary.member_indices.extend(secondary.member_indices)
            consumed.add(idx)

        _recompute_group_metadata(primary)

    return [g for i, g in enumerate(groups) if i not in consumed]


def _recompute_group_metadata(group: AlertGroup) -> None:
    """Recompute computed fields after merging groups."""
    # Primary alert type = most frequent
    type_counts: dict[str, int] = {}
    for a in group.alerts:
        type_counts[a.alert_type] = type_counts.get(a.alert_type, 0) + 1
    group.primary_alert_type = max(type_counts, key=type_counts.get)  # type: ignore[arg-type]

    # Severity & score
    group.highest_severity = group.alerts[0].severity
    group.highest_score = group.alerts[0].score
    group.best_label = group.alerts[0].label
    for a in group.alerts:
        if _severity_rank(a.severity) > _severity_rank(group.highest_severity):
            group.highest_severity = a.severity
        if a.score > group.highest_score:
            group.highest_score = a.score
            group.best_label = a.label

    # Time range
    times = [a.event_time for a in group.alerts if a.event_time]
    if times:
        group.earliest_time = min(times)
        group.latest_time = max(times)

    # Update grouping reason
    alert_types = sorted({a.alert_type for a in group.alerts})
    group.grouping_reason = (
        f"user={group.entity_anchor}, merged {len(alert_types)} alert types: "
        f"{', '.join(alert_types)}"
    )


def _compute_quality_flags(
    entities: Any, score: int, severity: str, signals: list,
) -> list[str]:
    """Compute quality flags for a case."""
    flags: list[str] = []
    identity = entities.identity if hasattr(entities, 'identity') else (entities or {}).get('identity', {})
    upn = ""
    if hasattr(identity, 'upn'):
        upn = identity.upn or ""
    elif isinstance(identity, dict):
        upn = identity.get('upn', '') or ""
    if upn in ("unknown@upload", "unknown", "") or not upn:
        flags.append("INCOMPLETE_DATA")
    if score < 30 and severity in ("critical", "high"):
        flags.append("LOW_CONFIDENCE")
    if not signals:
        flags.append("NO_SIGNALS")
    return flags


# ── Build grouped case ───────────────────────────────────────────────────

def build_grouped_case(
    group: AlertGroup,
    tenant_id: str,
    filename: str,
) -> CaseV0_2:
    """Construct a single case from a group of enriched alerts."""
    # Use the highest-scoring alert as the "primary" for entities/enrichment
    primary = max(group.alerts, key=lambda a: a.score)
    primary_case = primary.case_data

    now = datetime.now(timezone.utc)
    alert_count = len(group.alerts)
    category = extract_alert_type_category(group.primary_alert_type)

    # Title
    if alert_count == 1:
        title = primary_case.title
    else:
        title = (
            f"{category.title()} incident: {alert_count} alerts"
            f" — {group.entity_anchor}"
        )

    # Description — build analyst-friendly narrative
    if alert_count == 1:
        description = primary_case.description
    else:
        # Use the primary alert's description/context if available
        primary_desc = primary_case.description or ""
        primary_ctx = ""
        if hasattr(primary_case, 'outputs') and primary_case.outputs:
            primary_ctx = ""

        # Build a narrative from the alert types
        alert_types = sorted({a.alert_type for a in group.alerts})
        type_labels = {
            "identity.suspiciousSignIn": "suspicious sign-in",
            "identity.passwordSpray": "password spray",
            "identity.mfaFatigue": "MFA fatigue attack",
            "identity.oauthConsentRisk": "OAuth consent risk",
            "identity.privilegeElevation": "privilege escalation",
            "endpoint.malwareDetection": "malware detection",
            "endpoint.suspiciousProcess": "suspicious process execution",
            "email.forwardingRule": "email forwarding rule",
            "cloud.secretStoreAccessAnomaly": "secret store access anomaly",
            "network.impossibleGeoAccess": "impossible travel",
        }
        readable_types = [type_labels.get(at, at.split(".")[-1]) for at in alert_types]

        time_range = ""
        if group.earliest_time and group.latest_time:
            t0 = group.earliest_time.strftime("%H:%M")
            t1 = group.latest_time.strftime("%H:%M")
            time_range = f" between {t0}–{t1}"

        entity = group.entity_anchor
        if len(readable_types) == 1:
            description = f"{alert_count} {readable_types[0]} events from {entity}{time_range}"
        else:
            description = f"{alert_count} related events from {entity}: {', '.join(readable_types)}{time_range}"

        # Append primary description if it's real content (not generic)
        if primary_desc and len(primary_desc) > 30 and "alert" not in primary_desc.lower()[:20]:
            description += f". {primary_desc[:120]}"

    # Aggregate sources
    sources: list[Source] = []
    for a in group.alerts:
        for s in a.case_data.sources:
            sources.append(s)
    if not sources:
        sources.append(Source(
            sourceSystem="custom",
            sourceName=f"upload:{filename}",
            sourceAlertId=f"group:{_hash_grouping_key(group.key)}",
            sourceSeverity=group.highest_severity,
        ))

    # Merge confidence signals (deduplicate by signal name, keep highest weight)
    signal_map: dict[str, tuple[int, str | None, str | None]] = {}
    for a in group.alerts:
        for sig in a.case_data.confidence.explanation:
            existing = signal_map.get(sig.signal)
            if existing is None or sig.weight > existing[0]:
                signal_map[sig.signal] = (
                    sig.weight,
                    getattr(sig, "label", None),
                    getattr(sig, "tier", None),
                )
    merged_signals = [
        ConfidenceSignal(signal=s, weight=w, label=lbl, tier=t)
        for s, (w, lbl, t) in signal_map.items()
    ]

    # Enrichment notes
    enrichment_notes = list(primary_case.enrichment.enrichmentNotes)
    if alert_count > 1:
        enrichment_notes.insert(
            0,
            f"Grouped from {alert_count} related alerts. "
            f"Reason: {group.grouping_reason}"
        )

    # Timestamps
    event_time = group.earliest_time or now
    timestamps = Timestamps(
        eventTime=event_time,
        ingestedTime=now,
        enrichedTime=now,
    )

    return CaseV0_2(
        caseId=uuid4(),
        tenantId=tenant_id,
        customer=primary_case.customer,
        sources=sources,
        alertType=group.primary_alert_type,
        title=title,
        description=description,
        timestamps=timestamps,
        severity=group.highest_severity,
        confidence=Confidence(
            score=group.highest_score,
            label=group.best_label,
            explanation=merged_signals,
        ),
        disposition=Disposition(status="open"),
        bulkTarget=primary_case.bulkTarget,
        entities=primary_case.entities,
        enrichment=Enrichment(
            recentActivity=primary_case.enrichment.recentActivity,
            relatedAlerts=primary_case.enrichment.relatedAlerts,
            riskScore=primary_case.enrichment.riskScore,
            enrichmentNotes=enrichment_notes,
            impactSummary=primary_case.enrichment.impactSummary,
            caseReadiness=primary_case.enrichment.caseReadiness,
            qualityFlags=_compute_quality_flags(
                primary_case.entities, group.highest_score,
                group.highest_severity, merged_signals,
            ),
        ),
        recommendedPlaybook=primary_case.recommendedPlaybook,
        recommendedActions=primary_case.recommendedActions,
        outputs=Outputs(mitre=primary_case.outputs.mitre if hasattr(primary_case.outputs, 'mitre') else None),
        audit=primary_case.audit,
        retention=Retention(),
    )
