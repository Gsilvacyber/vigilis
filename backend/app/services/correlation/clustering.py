"""Entity extraction, link scoring, and case clustering."""
from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any

from backend.app.core.config import settings as _settings
from backend.app.db.models import Case as CaseRow

CORRELATION_WINDOW_HOURS = _settings.correlation_window_hours
_USER_LINK_WEIGHT = 3
_IP_LINK_WEIGHT = 2  # increased from 1 — shared public IP is a strong signal
_DEVICE_LINK_WEIGHT = 2
_LINK_THRESHOLD = 2  # minimum weight to consider entities linked


# ── IP classification (over-correlation guardrails) ──────────────────────

def _is_private_ip_str(ip: str) -> bool:
    """Quick check if IP is private/internal."""
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.") or ip.startswith("127.") or not ip


_COMMON_NAT_PREFIXES = {"10.", "172.16.", "172.17.", "172.18.", "172.19.",
                         "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                         "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                         "172.30.", "172.31.", "192.168."}


def _is_private_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return any(addr.startswith(p) for p in _COMMON_NAT_PREFIXES)


def _ip_link_weight(addr: str) -> int:
    """Private/NAT IPs get zero weight to prevent false correlation."""
    if _is_private_ip(addr):
        return 0
    return _IP_LINK_WEIGHT


# ── Entity extraction from case rows ─────────────────────────────────────

def extract_entities(case: CaseRow) -> dict[str, set[str]]:
    """Pull user, IP, and device identifiers from a case's entities JSON."""
    ent = case.entities or {}
    users: set[str] = set()
    ips: set[str] = set()
    devices: set[str] = set()

    identity = ent.get("identity") or {}
    upn = identity.get("upn", "")
    if upn and upn not in ("unknown@upload", "unknown"):
        users.add(upn.lower())

    for ip_obj in ent.get("ips") or []:
        addr = ip_obj.get("ipAddress", "")
        if addr and addr != "0.0.0.0":
            ips.add(addr)

    device = ent.get("device") or {}
    hostname = device.get("hostname", "")
    if hostname and hostname != "unknown-host":
        devices.add(hostname.lower())

    return {"users": users, "ips": ips, "devices": devices}


def _compute_link_strength(
    a: dict[str, set[str]],
    b: dict[str, set[str]],
) -> tuple[int, list[str]]:
    """Weighted entity overlap. Returns (score, list of reasons).

    User match is weighted 3x higher than IP match.
    Private/NAT IPs contribute zero weight.
    """
    score = 0
    reasons: list[str] = []

    shared_users = a["users"] & b["users"]
    if shared_users:
        score += _USER_LINK_WEIGHT
        reasons.append(f"Same user: {', '.join(sorted(shared_users))}")

    shared_ips = a["ips"] & b["ips"]
    for ip in shared_ips:
        w = _ip_link_weight(ip)
        if w > 0:
            score += w
            reasons.append(f"Same public IP: {ip}")

    shared_devices = a.get("devices", set()) & b.get("devices", set())
    if shared_devices:
        score += _DEVICE_LINK_WEIGHT
        reasons.append(f"Same device: {', '.join(sorted(shared_devices))}")

    return score, reasons


# ── Clustering ───────────────────────────────────────────────────────────

class ClusterResult:
    __slots__ = ("cases", "reasons", "max_link_score", "link_components")

    def __init__(self) -> None:
        self.cases: list[CaseRow] = []
        self.reasons: set[str] = set()
        self.max_link_score: int = 0
        self.link_components: list[dict[str, Any]] = []


def _detect_spray_patterns(
    cases: list[CaseRow],
    window_hours: int,
) -> tuple[list[list[CaseRow]], list[list[CaseRow]]]:
    """Detect password spray: same public IP, 3+ different users, within window.

    Returns (spray_clusters, consumed_case_lists) where each spray_cluster
    is a list of cases forming the spray pattern.
    """
    from backend.app.services.enrichment.base import _is_private_ip

    ip_buckets: dict[str, list[CaseRow]] = {}
    for case in cases:
        ent = case.entities or {}
        for ip_obj in ent.get("ips") or []:
            addr = ip_obj.get("ipAddress", "")
            if addr and not _is_private_ip(addr):
                ip_buckets.setdefault(addr, []).append(case)

    spray_clusters: list[list[CaseRow]] = []
    consumed: list[list[CaseRow]] = []

    for ip, ip_cases in ip_buckets.items():
        users = set()
        for c in ip_cases:
            ident = (c.entities or {}).get("identity", {})
            upn = ident.get("upn", "")
            if upn and "@" in upn:
                users.add(upn.lower())

        if len(users) >= 3 and len(ip_cases) >= 3:
            # Don't classify phishing victims as spray
            case_types = set(
                getattr(c, 'alert_type', None) for c in ip_cases
            )
            if "email.phishingDetected" in case_types:
                continue  # This is a phishing campaign, not a password spray
            spray_clusters.append(ip_cases)
            consumed.append(ip_cases)

    return spray_clusters, consumed


def merge_entities(cases: list[CaseRow]) -> dict[str, set[str]]:
    """Merge entities from multiple cases into a single entity dict."""
    merged: dict[str, set[str]] = {"users": set(), "ips": set(), "devices": set()}
    for case in cases:
        ent = extract_entities(case)
        merged["users"] |= ent["users"]
        merged["ips"] |= ent["ips"]
        merged["devices"] |= ent["devices"]
    return merged


def _build_link_components(
    a: dict[str, set[str]],
    b: dict[str, set[str]],
) -> list[dict[str, Any]]:
    """Build the individual score components for a link between two entity sets."""
    components: list[dict[str, Any]] = []

    shared_users = a["users"] & b["users"]
    if shared_users:
        components.append({
            "factor": "User match",
            "score": _USER_LINK_WEIGHT,
            "detail": ", ".join(sorted(shared_users)),
        })

    shared_ips = a["ips"] & b["ips"]
    for ip in sorted(shared_ips):
        w = _ip_link_weight(ip)
        components.append({
            "factor": "Private IP" if w == 0 else "Public IP match",
            "score": w,
            "detail": ip,
        })

    return components


def cluster_cases(
    cases: list[CaseRow],
    window_hours: int = CORRELATION_WINDOW_HOURS,
    tenant_id: str = "",
) -> list[ClusterResult]:
    """Group cases into clusters by weighted entity overlap within a time window."""
    if not cases:
        return []

    # Tenant safety: ensure all cases belong to the same tenant.
    # The caller (correlate_incidents) pre-filters by tenant FK, so this is
    # a defensive assertion, not a filter. We compare tenant_id values on
    # the case objects themselves (UUID FK) to ensure no cross-tenant mixing.
    if len(cases) > 1:
        tenant_ids = set(getattr(c, 'tenant_id', None) for c in cases)
        tenant_ids.discard(None)
        if len(tenant_ids) > 1:
            import logging
            logging.getLogger(__name__).warning(
                "Cross-tenant cases detected in clustering: %s. Filtering to largest group.",
                tenant_ids,
            )
            # Keep only the most common tenant's cases
            from collections import Counter
            most_common_tid = Counter(getattr(c, 'tenant_id', None) for c in cases).most_common(1)[0][0]
            cases = [c for c in cases if getattr(c, 'tenant_id', None) == most_common_tid]

    sorted_cases = sorted(cases, key=lambda c: c.event_time)

    # ── Password spray pattern detection (pre-clustering) ──────────────
    spray_clusters, spray_consumed = _detect_spray_patterns(
        sorted_cases, window_hours
    )

    clusters: list[list[CaseRow]] = [sc for sc in spray_clusters]
    cluster_entities: list[dict[str, set[str]]] = [
        merge_entities(sc) for sc in spray_clusters
    ]
    # Initialize results for pre-seeded spray clusters so indices stay in sync
    results: list[ClusterResult] = []
    for sc in spray_clusters:
        r = ClusterResult()
        r.cases = clusters[len(results)]
        r.reasons = {"Password spray cluster"}
        results.append(r)
    spray_ids = {id(c) for sc in spray_consumed for c in sc}

    # ── VPN/Proxy detection (pre-clustering) ─────────────────────────
    # Count distinct users per public IP across ALL eligible cases.
    # If a public IP has 5+ distinct users, it's likely a shared corporate
    # VPN, cloud NAT, or proxy.  Exclude it from IP-based correlation to
    # prevent false mega-incidents where unrelated users cluster together.
    _ip_user_map: dict[str, set[str]] = {}
    for _c in sorted_cases:
        _ent = _c.entities or {}
        _upn = ((_ent.get("identity") or {}).get("upn") or "").lower()
        if not _upn or _upn in ("unknown", "unknown@upload"):
            continue
        for _ip_obj in _ent.get("ips", []) or []:
            _addr = _ip_obj.get("ipAddress", "") if isinstance(_ip_obj, dict) else str(_ip_obj)
            if _addr and not _is_private_ip(_addr):
                _ip_user_map.setdefault(_addr, set()).add(_upn)

    _SHARED_IP_THRESHOLD = 5  # 5+ distinct users = shared egress
    shared_egress_ips: set[str] = set()
    for _addr, _users in _ip_user_map.items():
        if len(_users) >= _SHARED_IP_THRESHOLD:
            shared_egress_ips.add(_addr)

    if shared_egress_ips:
        import logging
        logging.getLogger(__name__).info(
            "VPN/proxy detection: %d shared egress IP(s) excluded from correlation: %s",
            len(shared_egress_ips), shared_egress_ips,
        )

    for case in sorted_cases:
        # Skip cases already consumed by spray detection
        if id(case) in spray_ids:
            continue

        # Adaptive threshold: lower for internal-only cases (insider threats).
        # Thresholds lowered after the Day 6 noisy-signal removal which
        # dropped average case scores from ~66 to ~38. The old threshold of
        # 45 excluded 68% of cases from correlation.
        _threshold = 30  # default for external IPs (was 45)
        case_ips = []
        ent_raw = case.entities or {}
        for ip_obj in ent_raw.get("ips", []) or []:
            if isinstance(ip_obj, dict):
                case_ips.append(ip_obj.get("ipAddress", ""))
            elif isinstance(ip_obj, str):
                case_ips.append(ip_obj)

        all_internal = all(_is_private_ip_str(ip) for ip in case_ips if ip) if case_ips else True
        if all_internal:
            _threshold = 20  # lower threshold for insider threat cases (was 30)

        if case.confidence_score < _threshold:
            # Rescue: pull in low-confidence cases that share a user with an
            # existing cluster.  This prevents phishing campaigns from losing
            # their forwarding-rule/persistence stage because it scored slightly
            # below threshold.  Guard: the existing cluster must have at least
            # one case above the full threshold.
            _ent_rescue = extract_entities(case)
            rescued = False
            if shared_egress_ips:
                _ent_rescue["ips"] = _ent_rescue["ips"] - shared_egress_ips
            # Rescue by user OR device match (device-based rescue added to
            # catch endpoint alerts that share a hostname but may not have
            # a user identity, e.g. Sysmon process events).
            if case.confidence_score >= 15:
                for i, cluster in enumerate(clusters):
                    cluster_has_strong = any(
                        c.confidence_score >= _threshold for c in cluster
                    )
                    if not cluster_has_strong:
                        continue
                    # User-based rescue (original)
                    if _ent_rescue["users"] and _ent_rescue["users"] & cluster_entities[i]["users"]:
                        cluster.append(case)
                        cluster_entities[i]["users"] |= _ent_rescue["users"]
                        cluster_entities[i]["ips"] |= _ent_rescue["ips"]
                        cluster_entities[i]["devices"] |= _ent_rescue.get("devices", set())
                        results[i].reasons.add(
                            "User-linked rescue (below threshold but same user)"
                        )
                        results[i].reasons.add(f"Within {CORRELATION_WINDOW_HOURS}h time window")
                        rescued = True
                        break
                    # Device-based rescue (NEW — catches endpoint-only cases)
                    rescue_devices = _ent_rescue.get("devices", set())
                    if rescue_devices and rescue_devices & cluster_entities[i].get("devices", set()):
                        cluster.append(case)
                        cluster_entities[i]["users"] |= _ent_rescue["users"]
                        cluster_entities[i]["ips"] |= _ent_rescue["ips"]
                        cluster_entities[i]["devices"] |= rescue_devices
                        results[i].reasons.add(
                            "Device-linked rescue (below threshold but same host)"
                        )
                        results[i].reasons.add(f"Within {CORRELATION_WINDOW_HOURS}h time window")
                        rescued = True
                        break
            if not rescued:
                continue

        # Skip IR/defensive response cases from incident clustering.
        _case_desc = case.description or ""
        _is_ir = any(kw in _case_desc.lower() for kw in [
            "ir response", "security team responding", "correct ir step",
            "emergency lockdown", "key disabled", "session killed",
            "remediation", "containment", "admin revoke",
        ])
        if _is_ir:
            continue

        # Skip cases that have been dispositioned as benign/closed
        _case_status = getattr(case, 'disposition_status', None) or ''
        if _case_status in ('benign', 'closed', 'auto_closed', 'false_positive'):
            continue

        ent = extract_entities(case)
        # Strip shared VPN/proxy IPs so they don't cause false correlation
        if shared_egress_ips:
            ent["ips"] = ent["ips"] - shared_egress_ips
        merged = False

        for i, cluster in enumerate(clusters):
            earliest = min(c.event_time for c in cluster)
            window = timedelta(hours=window_hours)

            in_window = (case.event_time - earliest) <= window
            if not in_window:
                continue

            strength, reasons = _compute_link_strength(ent, cluster_entities[i])
            shared_users = ent["users"] & cluster_entities[i]["users"]

            if strength >= _LINK_THRESHOLD:
                cluster.append(case)
                cluster_entities[i]["users"] |= ent["users"]
                results[i].reasons.update(reasons)
                results[i].reasons.add(f"Within {window_hours}h time window")
                if strength > results[i].max_link_score:
                    results[i].max_link_score = strength
                    results[i].link_components = _build_link_components(ent, cluster_entities[i])
                merged = True
                break

            # ── IP-only correlation (no shared users) ────────────────
            if not shared_users:
                shared_public_ips = set()
                for ip in ent["ips"] & cluster_entities[i]["ips"]:
                    if not _is_private_ip(ip):
                        shared_public_ips.add(ip)
                if shared_public_ips:
                    cluster.append(case)
                    cluster_entities[i]["users"] |= ent["users"]
                    ip_reason = f"Same public IP (no shared user): {', '.join(sorted(shared_public_ips))}"
                    results[i].reasons.add(ip_reason)
                    results[i].reasons.add(f"Within {window_hours}h time window")
                    ip_score = sum(_ip_link_weight(ip) for ip in shared_public_ips)
                    if ip_score > results[i].max_link_score:
                        results[i].max_link_score = ip_score
                        results[i].link_components = _build_link_components(ent, cluster_entities[i])
                    merged = True
                    break

        if not merged:
            clusters.append([case])
            cluster_entities.append({
                "users": set(ent["users"]),
                "ips": set(ent["ips"]),
                "devices": set(ent["devices"]),
            })
            r = ClusterResult()
            r.cases = clusters[-1]
            results.append(r)

    return results


def build_linkage_reasons(
    cases: list[CaseRow],
    cluster_reasons: set[str],
    stages: list[str],
) -> list[dict[str, str]]:
    """Build structured linkage reasons for auditability."""
    from backend.app.services.correlation.kill_chain import _STAGE_LABELS

    reasons: list[dict[str, str]] = []

    for r in sorted(cluster_reasons):
        if r.startswith("Same user"):
            reasons.append({"type": "shared_user", "detail": r, "weight": "strong"})
        elif r.startswith("Same public IP"):
            reasons.append({"type": "shared_ip", "detail": r, "weight": "moderate"})
        elif "time window" in r:
            reasons.append({"type": "time_proximity", "detail": r, "weight": "supporting"})

    if len(stages) >= 2:
        stage_labels = [_STAGE_LABELS.get(s, s) for s in stages]
        reasons.append({
            "type": "kill_chain_progression",
            "detail": f"Distinct kill-chain stages: {' → '.join(stage_labels)}",
            "weight": "strong",
        })

    return reasons


def build_link_strength_summary(
    max_score: int,
    components: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a structured link strength summary for the UI."""
    return {
        "totalScore": max_score,
        "threshold": _LINK_THRESHOLD,
        "passed": max_score >= _LINK_THRESHOLD,
        "components": components,
    }
