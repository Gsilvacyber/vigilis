"""Historical user correlation — checks if this user has previous cases."""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from backend.app.services.enrichment.base import Signal

_log = logging.getLogger(__name__)


def _to_naive_utc(dt: datetime | None) -> datetime | None:
    """Normalize a datetime to timezone-naive UTC.

    DB-stored event times come back as naive (both sqlite and postgres
    strip tz). Comparison against tz-aware Python datetimes raises
    TypeError and gets silently swallowed by the try/except, so we
    normalize both sides to naive UTC before comparing.
    """
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def check_user_history(
    user_upn: str,
    event_time: datetime,
    tenant_id: str = "",
) -> list[Signal]:
    """Check DB for recent cases from the same user. Returns signals if patterns found."""
    if not user_upn or user_upn in ("unknown", "unknown@upload", ""):
        return []

    signals: list[Signal] = []
    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import Case as CaseRow

        with get_session() as session:
            from sqlmodel import select

            cutoff_30d = event_time - timedelta(days=30)
            cutoff_7d = event_time - timedelta(days=7)

            # Query cases in last 30 days
            stmt = (
                select(CaseRow)
                .where(CaseRow.event_time >= cutoff_30d)
                .where(CaseRow.event_time < event_time)
            )
            # Apply tenant filter if available
            if tenant_id:
                from backend.app.db.models import Tenant as TenantRow
                tenant_row = session.exec(
                    select(TenantRow).where(TenantRow.tenant_id == tenant_id)
                ).first()
                if tenant_row:
                    stmt = stmt.where(CaseRow.tenant_id == tenant_row.id)

            recent_cases = session.exec(stmt).all()

            # Filter for matching UPN in entities JSON
            user_cases = []
            for case in recent_cases:
                entities = case.entities or {}
                identity = entities.get("identity", {}) or {}
                case_upn = identity.get("upn", "") or ""
                if case_upn.lower() == user_upn.lower():
                    user_cases.append(case)

            # Time-locality semantics: fire only on RECENT confirmed threats.
            # Old logic fired on any history in 30d, which made the signal fire on
            # 97.7% of cases in production — pure noise floor. Now it only fires
            # when the user has multiple confirmed threats in the last 6h, which
            # is actually actionable (= active compromise in progress).
            # Disposition-only: no confidence_score fallback (cascade risk).
            event_time_naive = _to_naive_utc(event_time)
            recent_cutoff_6h = event_time_naive - timedelta(hours=6)
            recent_confirmed = [
                c for c in user_cases
                if c.event_time is not None
                and _to_naive_utc(c.event_time) >= recent_cutoff_6h
                and c.disposition_status in ("true_positive", "escalated")
            ]
            if len(recent_confirmed) >= 2:
                signals.append(Signal(
                    name="repeat_offender",
                    weight=10,
                    fired=True,
                    label=f"User {user_upn} had {len(recent_confirmed)} analyst-confirmed threats in the last 6h — active compromise",
                    tier="verified",
                ))

            # Check for critical cases in last 7 days
            critical_recent = [
                c for c in user_cases
                if c.event_time >= cutoff_7d and c.confidence_score >= 85
            ]
            if critical_recent:
                signals.append(Signal(
                    name="escalating_threat",
                    weight=15,
                    fired=True,
                    label=f"User {user_upn} had {len(critical_recent)} critical case(s) in last 7 days",
                ))

            # Sustained daily activity (same user, cases on 3+ consecutive days)
            if len(user_cases) >= 3:
                case_dates = sorted(set(c.event_time.date() for c in user_cases if c.event_time))
                consecutive = 1
                max_consecutive = 1
                for i in range(1, len(case_dates)):
                    if (case_dates[i] - case_dates[i-1]).days == 1:
                        consecutive += 1
                        max_consecutive = max(max_consecutive, consecutive)
                    else:
                        consecutive = 1
                if max_consecutive >= 3:
                    signals.append(Signal(
                        name="sustained_activity",
                        weight=12,
                        fired=True,
                        label=f"User {user_upn} active on {max_consecutive} consecutive days",
                    ))

            # Escalating data transfer (increasing bytes over time)
            transfer_cases = [c for c in user_cases if c.alert_type in ("network.dataExfiltration", "network.impossibleGeoAccess")]
            if len(transfer_cases) >= 2:
                signals.append(Signal(
                    name="escalating_exfiltration",
                    weight=15,
                    fired=True,
                    label=f"User {user_upn} has {len(transfer_cases)} data transfer cases — possible escalating exfiltration",
                ))

    except Exception:
        _log.debug("Historical user correlation failed (non-fatal)", exc_info=True)

    return signals


def check_internal_ip_reputation(
    ip_address: str,
    event_time: datetime,
    tenant_id: str = "",
) -> list[Signal]:
    """Check if an internal IP has been involved in previous incidents/cases.

    WHY: OTX/AbuseIPDB return nothing for RFC 1918 addresses.  This is the
    ONLY enrichment that internal IPs get.  Without it, insider threat cases
    have zero threat intel — the biggest enrichment gap in the platform.

    Checks:
    1. Has this IP appeared in high-confidence (>=60) cases before?
    2. Has this IP appeared in cases linked to incidents?
    3. Is this IP in a sensitive subnet pattern? (lab, finance, DC, etc.)
    """
    if not ip_address or ip_address in ("0.0.0.0", "127.0.0.1"):
        return []

    # Only enrich internal IPs — external IPs get OTX/AbuseIPDB instead
    import ipaddress as _ipa
    try:
        addr = _ipa.ip_address(ip_address)
        if not (addr.is_private or addr.is_loopback):
            return []  # External IP — handled by threat_intel.py
    except ValueError:
        return []

    signals: list[Signal] = []

    # ── Sensitive subnet detection ──────────────────────────────────────
    # Known-sensitive internal network patterns.  These are heuristic but
    # cover common enterprise layouts.  Asset criticality handles hostnames;
    # this handles IP-only alerts where hostname is missing.
    _SENSITIVE_SUBNETS = {
        "10.200.": ("research_lab_network", "Source IP in research/lab subnet (10.200.x.x)"),
        "10.100.": ("financial_network", "Source IP in financial systems subnet (10.100.x.x)"),
        "10.50.": ("trading_network", "Source IP in trading/high-value subnet (10.50.x.x)"),
        "10.10.": ("server_network", "Source IP in server/infrastructure subnet (10.10.x.x)"),
        "172.16.0.": ("dmz_network", "Source IP in DMZ subnet (172.16.0.x)"),
        "192.168.10.": ("server_network", "Source IP in server subnet (192.168.10.x)"),
    }
    for prefix, (signal_name, label) in _SENSITIVE_SUBNETS.items():
        if ip_address.startswith(prefix):
            signals.append(Signal(
                name="sensitive_subnet",
                weight=8,
                fired=True,
                label=label,
            ))
            break

    # ── Historical IP reputation from DB ────────────────────────────────
    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import Case as CaseRow, Incident, IncidentCaseLink
        from sqlmodel import select

        with get_session() as session:
            cutoff = event_time - timedelta(days=30)

            # Find cases with this IP in the last 30 days
            cases = session.exec(
                select(CaseRow).where(CaseRow.event_time >= cutoff)
            ).all()

            ip_cases = []
            for case in cases:
                entities = case.entities or {}
                for ip_obj in entities.get("ips", []) or []:
                    if isinstance(ip_obj, dict) and ip_obj.get("ipAddress") == ip_address:
                        ip_cases.append(case)
                        break

            # Check /24 subnet (catches DHCP-rotated IPs on same segment)
            subnet_cases: list = []
            try:
                subnet = _ipa.ip_network(f"{ip_address}/24", strict=False)
                subnet_prefix = str(subnet.network_address).rsplit(".", 1)[0] + "."
                for case in cases:
                    if case in ip_cases:
                        continue  # already counted as exact match
                    entities = case.entities or {}
                    for ip_obj in entities.get("ips", []) or []:
                        if isinstance(ip_obj, dict):
                            case_ip = ip_obj.get("ipAddress", "")
                            if case_ip and case_ip.startswith(subnet_prefix):
                                subnet_cases.append(case)
                                break
            except ValueError:
                pass

            all_ip_cases = ip_cases + subnet_cases

            # Signal: IP appeared in previous high-confidence cases
            high_conf_cases = [c for c in ip_cases if c.confidence_score >= 60]
            if len(high_conf_cases) >= 2:
                signals.append(Signal(
                    name="internal_ip_repeat_offender",
                    weight=12,
                    fired=True,
                    label=f"Internal IP {ip_address} appeared in {len(high_conf_cases)} high-confidence cases (last 30 days)",
                ))
            elif subnet_cases:
                # Subnet-level matches (weaker signal than exact IP)
                high_conf_subnet = [c for c in subnet_cases if c.confidence_score >= 60]
                if len(high_conf_subnet) >= 2:
                    signals.append(Signal(
                        name="internal_ip_repeat_offender",
                        weight=8,
                        fired=True,
                        label=f"Internal subnet {subnet_prefix}0/24 appeared in {len(high_conf_subnet)} high-confidence cases (last 30 days)",
                    ))

            # Signal: IP appeared in cases linked to incidents
            if ip_cases:
                case_ids = {c.id for c in ip_cases}
                incident_links = session.exec(select(IncidentCaseLink)).all()
                linked_case_ids = {link.case_id for link in incident_links}
                incident_overlap = case_ids & linked_case_ids
                if incident_overlap:
                    signals.append(Signal(
                        name="internal_ip_in_incident",
                        weight=15,
                        fired=True,
                        label=f"Internal IP {ip_address} previously linked to {len(incident_overlap)} incident-related case(s)",
                    ))

            # Signal: cross-domain indicator (IP appears in both identity AND endpoint cases)
            alert_types_on_ip = set()
            for c in all_ip_cases:
                if c.alert_type:
                    alert_types_on_ip.add(c.alert_type.split(".")[0])
            if len(alert_types_on_ip) >= 2:
                signals.append(Signal(
                    name="internal_ip_cross_domain",
                    weight=10,
                    fired=True,
                    label=f"Internal IP {ip_address} has cases across {len(alert_types_on_ip)} domains: {', '.join(sorted(alert_types_on_ip))}",
                    tier="verified",
                ))

    except Exception:
        _log.debug("Internal IP reputation check failed (non-fatal)", exc_info=True)

    return signals


def check_hostname_history(
    hostname: str,
    event_time: datetime,
    tenant_id: str = "",
) -> list[Signal]:
    """Check if this hostname has appeared in previous cases.

    For ransomware cases, knowing that FILE-SVR-01 was involved in a
    previous suspicious process case is VERIFIED enrichment — it's a
    real DB query, not keyword matching.
    """
    if not hostname or hostname in ("unknown-host", "unknown", ""):
        return []

    signals: list[Signal] = []
    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import Case as CaseRow, Tenant as TenantRow
        from sqlmodel import select

        with get_session() as session:
            cutoff = event_time - timedelta(days=30)
            cases = session.exec(
                select(CaseRow).where(CaseRow.event_time >= cutoff)
            ).all()

            # Find cases with this hostname
            host_cases = []
            for case in cases:
                entities = case.entities or {}
                device = entities.get("device", {}) or {}
                case_host = (device.get("hostname") or "").lower()
                if case_host == hostname.lower():
                    host_cases.append(case)

            # Time-locality semantics: fire ONLY on analyst-dispositioned threats.
            # No confidence_score fallback — that created a cascade effect during
            # re-enrichment (high-scoring cases trigger the signal for nearby cases,
            # which is circular). Disposition-only means the signal is dormant
            # until real analysts provide ground truth. That's the correct
            # fail-safe behavior.
            event_time_naive = _to_naive_utc(event_time)
            recent_cutoff_6h = event_time_naive - timedelta(hours=6)
            recent_confirmed = [
                c for c in host_cases
                if c.event_time is not None
                and _to_naive_utc(c.event_time) >= recent_cutoff_6h
                and c.disposition_status in ("true_positive", "escalated")
            ]
            if len(recent_confirmed) >= 2:
                signals.append(Signal(
                    name="host_repeat_target",
                    weight=15,
                    fired=True,
                    label=f"Host {hostname} had {len(recent_confirmed)} analyst-confirmed threats in last 6h — active target",
                    tier="verified",
                ))

            # Check if hostname was in RECENT confirmed incidents (not all-time).
            # Old logic fired on any host ever linked to any incident — which was
            # 99.4% of cases. New logic: only fire if the incident contains
            # analyst-dispositioned positive cases in the last 24h.
            if host_cases:
                from backend.app.db.models import IncidentCaseLink
                recent_cutoff_24h = event_time_naive - timedelta(hours=24)
                recent_host = [
                    c for c in host_cases
                    if c.event_time is not None
                    and _to_naive_utc(c.event_time) >= recent_cutoff_24h
                    and c.disposition_status in ("true_positive", "escalated")
                ]
                if recent_host:
                    recent_ids = {c.id for c in recent_host}
                    links = session.exec(select(IncidentCaseLink)).all()
                    linked = {l.case_id for l in links}
                    if recent_ids & linked:
                        signals.append(Signal(
                            name="host_in_prior_incident",
                            weight=18,
                            fired=True,
                            label=f"Host {hostname} is in a recent incident with {len(recent_ids & linked)} confirmed threat(s) in last 24h",
                            tier="verified",
                        ))

    except Exception:
        _log.debug("Hostname history check failed (non-fatal)", exc_info=True)

    return signals
