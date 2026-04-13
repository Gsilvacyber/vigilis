from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Callable

from backend.app.services.enrichment.base import (
    EnrichmentDebug,
    EnrichmentResult,
    Signal,
)
from backend.app.services.enrichment.scoring import (
    compute_confidence,
    get_severity_base,
)
from backend.app.services.enrichment.playbooks import get_playbook
from backend.app.services.enrichment.actions import get_actions
from backend.app.services.enrichment.asset_criticality import (
    compute_asset_criticality,
    compute_user_risk,
)
from backend.app.services.enrichment.cross_alert import (
    CrossAlertSignal,
    _extract_entity_keys,
    get_scanner,
)
from backend.app.services.enrichment.threat_intel import (
    get_threat_intel_enricher,
)
from backend.app.services.enrichment.telemetry import get_collector as _get_telemetry_collector
from backend.app.services.enrichment.mappers.identity import IDENTITY_EXTRACTORS
from backend.app.services.enrichment.mappers.endpoint import ENDPOINT_EXTRACTORS
from backend.app.services.enrichment.mappers.email import EMAIL_EXTRACTORS
from backend.app.services.enrichment.mappers.cloud import CLOUD_EXTRACTORS
from backend.app.services.enrichment.mappers.network import NETWORK_EXTRACTORS
from backend.app.services.enrichment.mappers.dlp import DLP_EXTRACTORS

logger = logging.getLogger("vigilis.enrichment")

_EXTRACTORS: dict[str, Callable[..., list[Signal]]] = {
    **IDENTITY_EXTRACTORS,
    **ENDPOINT_EXTRACTORS,
    **EMAIL_EXTRACTORS,
    **CLOUD_EXTRACTORS,
    **NETWORK_EXTRACTORS,
    **DLP_EXTRACTORS,
}

# ── Signal telemetry ──────────────────────────────────────────────────
# Backed by TelemetryCollector (DB persistence + in-memory buffer).
# Backward-compatible: _TELEMETRY and get_telemetry still work.

from backend.app.services.enrichment.telemetry import _TELEMETRY  # noqa: F401

__all__ = ["enrich", "enrich_debug", "EnrichmentResult", "EnrichmentDebug",
           "Signal", "get_telemetry"]


def get_telemetry() -> list[dict[str, Any]]:
    """Return the in-memory signal telemetry buffer (read-only copy)."""
    return _get_telemetry_collector().get_buffer()


def _run_enrichment(
    alert_type: str,
    severity: str,
    raw_alert: dict[str, Any],
    event_time: datetime,
    tenant_id: str | None = None,
) -> tuple[EnrichmentResult, list[Signal]]:
    extractor = _EXTRACTORS.get(alert_type)
    if extractor is None:
        logger.info("No extractor for alert_type=%s — returning base score", alert_type)
        return EnrichmentResult(
            confidence_score=get_severity_base(severity),
            confidence_label="medium",
            confidence_explanation=[],
            recommended_playbook=[],
            recommended_actions=[],
            enrichment_notes=[f"No enrichment rules for {alert_type}"],
        ), []

    # Sysmon translation: raw endpoint telemetry -> structured MITRE fields.
    # Runs BEFORE the extractor so downstream tier upgrades can see the added
    # fields. For non-Sysmon alerts this is a fast no-op.
    try:
        from backend.app.services.enrichment.sysmon_translator import translate_sysmon_event
        _added = translate_sysmon_event(raw_alert)
        if _added:
            logger.debug("sysmon_translator: added %d structured fields", _added)
    except Exception:
        logger.debug("Sysmon translation skipped (non-fatal)", exc_info=True)

    # Run extractor with retry on failure.
    # WHY: A bad regex or unexpected field type in one extractor should not
    # silently return base score. We retry once (in case of transient issue),
    # then return a degraded result with ENRICHMENT_FAILED quality flag so
    # analysts know enrichment didn't run — not that the alert is low-priority.
    import time as _time
    _enrich_start = _time.monotonic()

    signals: list[Signal] = []
    enrichment_failed = False
    for attempt in range(2):  # 1 retry
        try:
            signals = extractor(raw_alert, severity, event_time)
            break
        except Exception:
            if attempt == 0:
                logger.warning(
                    "Extractor failed for %s (attempt 1/2), retrying",
                    alert_type, exc_info=True,
                )
            else:
                logger.error(
                    "Extractor failed for %s after 2 attempts — returning degraded result",
                    alert_type, exc_info=True,
                )
                enrichment_failed = True

    # Post-extraction tier upgrade: for signals that have a tiered version,
    # re-check structured fields and promote from "inferred" to "observed"/"verified"
    # This avoids editing every Signal() call across all mappers.
    try:
        from backend.app.services.enrichment.base import (
            has_insider_threat_context_tiered,
            has_domain_admin_context_tiered,
            has_lateral_movement_context_tiered,
            has_ad_attack_context_tiered,
            has_data_exfil_context_tiered,
            has_container_escape_context_tiered,
            has_persistence_context_tiered,
            has_dns_tunnel_context_tiered,
            has_c2_beaconing_context_tiered,
            has_ransomware_context_tiered,
            has_shadow_copy_deletion_tiered,
        )
        _tier_upgrades = {
            # Tier-aware signals from earlier refactor
            "insider_threat": has_insider_threat_context_tiered,
            "domain_admin_target": has_domain_admin_context_tiered,
            "domain_admin_context": has_domain_admin_context_tiered,
            "lateral_movement": has_lateral_movement_context_tiered,
            # Phase 5 tier-aware signals
            "ad_attack": has_ad_attack_context_tiered,
            "data_exfiltration": has_data_exfil_context_tiered,
            "data_exfiltration_context": has_data_exfil_context_tiered,
            "insider_data_exfil": has_data_exfil_context_tiered,
            "container_escape": has_container_escape_context_tiered,
            "persistence": has_persistence_context_tiered,
            "persistence_mechanism": has_persistence_context_tiered,
            "dns_tunnel": has_dns_tunnel_context_tiered,
            "dns_tunnel_process": has_dns_tunnel_context_tiered,
            "c2_beaconing": has_c2_beaconing_context_tiered,
            # Phase 6: Sysmon translator enrichment
            "ransomware_chain": has_ransomware_context_tiered,
            "ransomware_context": has_ransomware_context_tiered,
            "shadow_copy_deletion": has_shadow_copy_deletion_tiered,
        }
        for sig in signals:
            if sig.name in _tier_upgrades and sig.fired:
                _, actual_tier = _tier_upgrades[sig.name](raw_alert)
                if actual_tier != "inferred":
                    sig.tier = actual_tier
    except Exception:
        pass  # Non-fatal — tier upgrade is best-effort

    source_tool = raw_alert.get("_sourceSiem") or raw_alert.get("_sourceTool")

    # Threat intel enrichment (Phase 4)
    ti_enricher = get_threat_intel_enricher()
    ti_signals = ti_enricher.enrich(raw_alert)
    for ti in ti_signals:
        existing_names = {s.name for s in signals}
        if ti.name not in existing_names:
            signals.append(Signal(ti.name, ti.weight, True, ti.label))
    # Capture structured TI notes (adversary names, campaigns, references)
    _ti_extra_notes = ti_enricher.last_ti_notes

    # IP Identity Lookup via ip-api.com — identifies WHO owns each external IP
    # FREE, no API key, works from Docker, returns: org, ISP, reverse DNS, proxy/hosting flags
    # This is GENUINE enrichment — tells analyst "this is Dropbox" or "this is a Tor proxy"
    _ip_identity_notes: list[str] = []
    try:
        import ipaddress as _ipa
        import httpx as _httpx
        for _ip_obj in raw_alert.get("ips", []) or []:
            if isinstance(_ip_obj, dict):
                _addr = _ip_obj.get("ipAddress", "")
                if _addr and _addr != "0.0.0.0":
                    try:
                        if not _ipa.ip_address(_addr).is_private:
                            _ip_resp = _httpx.get(
                                f"http://ip-api.com/json/{_addr}?fields=status,org,isp,as,reverse,hosting,proxy",
                                timeout=5,
                            )
                            if _ip_resp.status_code == 200:
                                _ip_data = _ip_resp.json()
                                _org = _ip_data.get("org", "")
                                _isp = _ip_data.get("isp", "")
                                _reverse = _ip_data.get("reverse", "")
                                _is_proxy = _ip_data.get("proxy", False)
                                _is_hosting = _ip_data.get("hosting", False)

                                # Inject identity into IP entity for UI display
                                if _org:
                                    _ip_obj["organization"] = _org
                                if _reverse:
                                    _ip_obj["reverseDns"] = _reverse
                                if _is_proxy:
                                    _ip_obj["isProxy"] = True

                                # Build enrichment note
                                _parts = [f"IP {_addr}"]
                                if _org:
                                    _parts.append(f"owned by {_org}")
                                if _isp and _isp != _org:
                                    _parts.append(f"ISP: {_isp}")
                                if _reverse:
                                    _parts.append(f"hostname: {_reverse}")
                                if _is_proxy:
                                    _parts.append("PROXY/VPN detected")
                                if _is_hosting:
                                    _parts.append("hosting/datacenter IP")
                                _ip_identity_notes.append("IP Identity: " + ", ".join(_parts))

                                # Fire VERIFIED signals based on IP identity
                                _existing_names = {s.name for s in signals}
                                if _is_proxy and "known_proxy_vpn" not in _existing_names:
                                    signals.append(Signal("known_proxy_vpn", 15, True,
                                        f"IP {_addr} is a known proxy/VPN ({_org})", "verified"))
                                # Check if destination is personal cloud storage
                                _cloud_services = {"dropbox", "google drive", "onedrive", "mega", "box", "icloud"}
                                if _org and any(svc in _org.lower() for svc in _cloud_services):
                                    if "destination_personal_cloud" not in _existing_names:
                                        signals.append(Signal("destination_personal_cloud", 15, True,
                                            f"Destination is personal cloud: {_org}", "verified"))
                    except (ValueError, _httpx.TimeoutException):
                        pass
    except Exception:
        logger.debug("IP identity lookup failed (non-fatal)", exc_info=True)

    # Domain intelligence (WHOIS/RDAP) — adds domain age + registrar signals.
    # "Domain registered 2 days ago" is one of the strongest phishing/C2 indicators.
    try:
        from backend.app.services.enrichment.domain_intel import enrich_with_domain_intel
        _domain_added = enrich_with_domain_intel(raw_alert)
        if _domain_added:
            logger.debug("Domain intel: added %d fields", _domain_added)
            _existing_names = {s.name for s in signals}
            if raw_alert.get("_domainVeryNew") and "domain_very_new" not in _existing_names:
                signals.append(Signal("domain_very_new", 22, True,
                    f"Domain registered < 7 days ago ({raw_alert.get('_domainAgeDays', '?')} days)",
                    "verified"))
            elif raw_alert.get("_domainNewlyRegistered") and "domain_newly_registered" not in _existing_names:
                signals.append(Signal("domain_newly_registered", 18, True,
                    f"Domain registered < 30 days ago ({raw_alert.get('_domainAgeDays', '?')} days)",
                    "verified"))
            if raw_alert.get("_domainSuspiciousTld") and "domain_suspicious_tld" not in _existing_names:
                signals.append(Signal("domain_suspicious_tld", 12, True,
                    "Domain uses a suspicious TLD commonly associated with phishing/malware",
                    "inferred"))
            if raw_alert.get("_domainKnownSafe") and "domain_known_safe" not in _existing_names:
                signals.append(Signal("domain_known_safe", -10, True,
                    f"Domain is a known-safe provider ({raw_alert.get('_domainRegistrar', '')})",
                    "verified"))
    except Exception:
        logger.debug("Domain intel lookup failed (non-fatal)", exc_info=True)

    # Historical user correlation (Phase 4)
    try:
        from backend.app.services.enrichment.historical import check_user_history
        _identity_data = raw_alert.get("identity")
        if isinstance(_identity_data, dict):
            _hist_upn = _identity_data.get("upn", "")
        else:
            _hist_upn = raw_alert.get("user", "")
        historical_signals = check_user_history(str(_hist_upn or ""), event_time)
        for hs in historical_signals:
            existing_names = {s.name for s in signals}
            if hs.name not in existing_names:
                signals.append(Signal(hs.name, hs.weight, True, hs.label))
    except Exception:
        logger.debug("Historical user correlation skipped (non-fatal)", exc_info=True)

    # Peer comparison — "this user has 5x more alerts than the tenant average"
    try:
        from backend.app.services.enrichment.historical import check_peer_comparison
        _identity_data_peer = raw_alert.get("identity")
        _peer_upn = ""
        if isinstance(_identity_data_peer, dict):
            _peer_upn = _identity_data_peer.get("upn", "")
        if _peer_upn:
            peer_signals = check_peer_comparison(
                str(_peer_upn), alert_type, event_time, tenant_id=tenant_id or "",
            )
            existing_names = {s.name for s in signals}
            for ps in peer_signals:
                if ps.name not in existing_names:
                    signals.append(ps)
    except Exception:
        logger.debug("Peer comparison skipped (non-fatal)", exc_info=True)

    # Internal IP reputation (fills the enrichment gap for RFC 1918 addresses)
    # WHY: OTX/AbuseIPDB return nothing for private IPs.  This is the ONLY
    # enrichment that insider threat cases get — checking if the internal IP
    # has appeared in previous incidents or is in a sensitive subnet.
    try:
        from backend.app.services.enrichment.historical import check_internal_ip_reputation
        _all_ips: list[str] = []
        for _ip_obj in raw_alert.get("ips", []) or []:
            if isinstance(_ip_obj, dict):
                _all_ips.append(_ip_obj.get("ipAddress", ""))
            elif isinstance(_ip_obj, str):
                _all_ips.append(_ip_obj)
        # Also check flat IP fields
        for _fld in ("ip", "src_ip", "source_ip"):
            _fv = raw_alert.get(_fld)
            if _fv and isinstance(_fv, str):
                _all_ips.append(_fv)
        for _ip in _all_ips:
            if _ip and _ip != "0.0.0.0":
                ip_rep_signals = check_internal_ip_reputation(_ip, event_time)
                for irs in ip_rep_signals:
                    existing_names = {s.name for s in signals}
                    if irs.name not in existing_names:
                        signals.append(Signal(irs.name, irs.weight, True, irs.label))
    except Exception:
        logger.debug("Internal IP reputation check skipped (non-fatal)", exc_info=True)

    # Hostname history (VERIFIED — has this device been targeted before?)
    try:
        from backend.app.services.enrichment.historical import check_hostname_history
        _device = raw_alert.get("device") or {}
        _hostname = _device.get("hostname", "") if isinstance(_device, dict) else ""
        if _hostname and _hostname not in ("unknown-host", "unknown"):
            host_signals = check_hostname_history(_hostname, event_time)
            for hs in host_signals:
                existing_names = {s.name for s in signals}
                if hs.name not in existing_names:
                    signals.append(Signal(hs.name, hs.weight, True, hs.label))
    except Exception:
        logger.debug("Hostname history check skipped (non-fatal)", exc_info=True)

    # User transfer baseline (VERIFIED signals from DB query)
    # This answers: "Is this transfer volume normal for this user?"
    try:
        from backend.app.services.enrichment.user_baseline import check_user_transfer_baseline
        _identity_data = raw_alert.get("identity") or {}
        _baseline_upn = _identity_data.get("upn", "") if isinstance(_identity_data, dict) else ""
        _raw_bytes = raw_alert.get("bytes") or raw_alert.get("_bytes") or 0
        try:
            _current_bytes = int(float(_raw_bytes)) if _raw_bytes else 0
        except (ValueError, TypeError):
            _current_bytes = 0
        # Also check _transferSizeMB
        if not _current_bytes and raw_alert.get("_transferSizeMB"):
            _current_bytes = int(raw_alert["_transferSizeMB"]) * 1024 * 1024

        if _baseline_upn and _current_bytes > 0:
            baseline_signals = check_user_transfer_baseline(
                _baseline_upn, _current_bytes, event_time,
                alert_type=alert_type, tenant_id=tenant_id or "",
            )
            for bs in baseline_signals:
                existing_names = {s.name for s in signals}
                if bs.name not in existing_names:
                    signals.append(Signal(bs.name, bs.weight, True, bs.label))
    except Exception:
        logger.debug("User baseline check skipped (non-fatal)", exc_info=True)

    # Entity graph — behavioral analysis from our OWN data (VERIFIED signals)
    # Query relationship history BEFORE storing new ones for this case
    try:
        from backend.app.services.enrichment.entity_graph import check_entity_relationships
        graph_signals = check_entity_relationships(raw_alert, event_time, tenant_id)
        existing_names = {s.name for s in signals}
        for gs in graph_signals:
            if gs.name not in existing_names:
                signals.append(gs)
    except Exception:
        logger.debug("Entity graph check skipped (non-fatal)", exc_info=True)

    # Process-based enrichment (for endpoint alerts with NO external IPs)
    # Ransomware, malware, lateral movement alerts get verified signals from
    # host↔process relationships instead of IP-based threat intel
    try:
        from backend.app.services.enrichment.entity_graph import check_process_relationships
        proc_signals = check_process_relationships(raw_alert, event_time, tenant_id)
        existing_names = {s.name for s in signals}
        for ps in proc_signals:
            if ps.name not in existing_names:
                signals.append(ps)
    except Exception:
        logger.debug("Process relationship check skipped (non-fatal)", exc_info=True)

    # Frequency anomaly — detects entity-pair usage spikes above baseline
    # (fires AFTER novelty fades; complements new_entity_relationship)
    try:
        from backend.app.services.enrichment.entity_graph import check_frequency_anomaly
        freq_signals = check_frequency_anomaly(raw_alert, event_time, tenant_id)
        existing_names = {s.name for s in signals}
        for fs in freq_signals:
            if fs.name not in existing_names:
                signals.append(fs)
    except Exception:
        logger.debug("Frequency anomaly check skipped (non-fatal)", exc_info=True)

    # Phase 3: State drift signal check — only for endpoint.stateDrift events
    if alert_type == "endpoint.stateDrift":
        try:
            from backend.app.services.enrichment.entity_graph import check_state_drift
            drift_signals = check_state_drift(raw_alert, event_time, tenant_id)
            existing_names = {s.name for s in signals}
            for ds in drift_signals:
                if ds.name not in existing_names:
                    signals.append(ds)
        except Exception:
            logger.debug("State drift check skipped (non-fatal)", exc_info=True)

    # Asset criticality and user risk (Phase 2)
    asset_weight, asset_tier = compute_asset_criticality(raw_alert)
    user_weight, user_risk_tier = compute_user_risk(raw_alert)

    # Cross-alert intelligence (Phase 3)
    entity_keys = _extract_entity_keys(raw_alert)
    scanner = get_scanner()
    scanner.register_alert(alert_type, entity_keys, event_time)
    cross_signals = scanner.scan_for_patterns(entity_keys)
    cross_alert_flags: list[str] = []
    _seen_cross_names: set[str] = set()
    for cs in cross_signals:
        if cs.name in _seen_cross_names:
            continue
        _seen_cross_names.add(cs.name)
        signals.append(Signal(cs.name, cs.weight, True, cs.label))
        cross_alert_flags.append(cs.name)

    # Fetch calibration adjustments from analyst feedback (learning loop)
    _weight_adj: dict[str, float] | None = None
    _disabled: set[str] | None = None
    if tenant_id:
        try:
            from backend.app.services.calibration import get_weight_adjustments
            from backend.app.core.db import get_session
            with get_session() as _cal_session:
                _weight_adj = get_weight_adjustments(_cal_session, tenant_id)
        except Exception:
            logger.debug("Calibration fetch failed (non-fatal)", exc_info=True)
        # Day 5 Lite: per-tenant signal denylist (hard on/off switch, separate
        # from the learning loop's soft weight adjustments)
        try:
            from backend.app.services.config_service import get_disabled_signals
            _dl = get_disabled_signals(tenant_id)
            if _dl:
                _disabled = _dl
        except Exception:
            logger.debug("Disabled signals fetch failed (non-fatal)", exc_info=True)

    score, label, explanation = compute_confidence(
        severity, signals, source_tool=source_tool,
        asset_weight=asset_weight, user_weight=user_weight,
        tenant_weight_adjustments=_weight_adj,
        disabled_signals=_disabled,
    )

    # Admin noise suppression: reduce score for authorized admin tools
    # Check structured fields + description (description was previously missed)
    _admin_ctx = " ".join([
        str(raw_alert.get("_additionalContext") or ""),
        str(raw_alert.get("_alertStatus") or ""),
        str(raw_alert.get("description") or ""),
        str(raw_alert.get("_description") or ""),
    ]).lower()
    admin_auth_keywords = ["authorized", "change ticket", "chg0", "chg-", "ct-", "scheduled", "maintenance", "patch management", "approved", "planned", "sccm", "wsus"]
    admin_tool_keywords = ["nmap", "psexec", "gpupdate", "get-windowsupdate", "vuln scan", "vulnerability scan", "deploy-patch", "reset-expired", "sccm"]

    is_admin_tool = any(kw in _admin_ctx for kw in admin_tool_keywords)
    is_authorized = any(kw in _admin_ctx for kw in admin_auth_keywords)

    # Change ticket reference alone is sufficient proof of authorization
    import re as _re
    _has_change_ticket = bool(_re.search(r'(chg|ct|cr|inc)\W?\d{3,}', _admin_ctx, _re.IGNORECASE))
    if (is_admin_tool and is_authorized) or _has_change_ticket:
        signals.append(Signal(
            name="authorized_admin_activity",
            weight=-15,
            fired=True,
            label="Authorized administrative activity detected — reduced risk"
        ))

    # Asymmetric detection mitigation
    raw_str = str(raw_alert).lower() if raw_alert else ""
    blocked_keywords = ["blocked", "quarantined", "prevented", "denied", "rejected", "stopped"]
    detected_keywords = ["detected", "flagged", "alerted", "observed"]

    if any(kw in raw_str for kw in blocked_keywords):
        # Threat was STOPPED — significant risk reduction
        score = max(0, score - 15)
    elif any(kw in raw_str for kw in detected_keywords):
        # Threat was SEEN but may still be active — minor reduction
        score = max(0, score - 5)

    # Source detail bonus: EDR with process-level detail scores slightly higher
    detail_keywords = ["process_name", "command_line", "parent_process", "file_hash", "sha256"]
    detail_count = sum(1 for kw in detail_keywords if kw in raw_str)
    if detail_count >= 2:
        score = min(100, score + 3)

    # Transfer size bonus (from structured field, not regex)
    _bytes_val = raw_alert.get("bytes") or raw_alert.get("_transferSizeMB")
    if _bytes_val:
        try:
            _bytes = int(float(str(_bytes_val)))
            if _bytes >= 1073741824:  # 1GB
                score = min(100, score + 8)
            elif _bytes >= 524288000:  # 500MB
                score = min(100, score + 5)
            elif _bytes >= 104857600:  # 100MB
                score = min(100, score + 3)
        except (ValueError, TypeError):
            pass

    # Recompute label after adjustments
    from backend.app.services.enrichment.scoring import _LABEL_THRESHOLDS
    for threshold, lbl in _LABEL_THRESHOLDS:
        if score >= threshold:
            label = lbl
            break

    playbook = get_playbook(alert_type)
    actions = get_actions(alert_type, signals, cross_signals=cross_signals,
                          entity_keys=entity_keys, score=score)
    notes = [s.label for s in signals if s.fired]

    # Ensure threat intel results are visible in enrichment notes
    for signal in signals:
        if signal.fired and signal.label and any(
            kw in signal.label.lower()
            for kw in ['otx', 'virustotal', 'abuseipdb', 'pulse', 'threat intel']
        ):
            if signal.label not in notes:
                notes.append(signal.label)

    # Add structured threat intel notes (adversary names, campaigns, references)
    for ti_note in _ti_extra_notes:
        if ti_note not in notes:
            notes.append(ti_note)

    # Add IP identity results (identifies services like Dropbox, Google, Tor proxies)
    for ip_note in _ip_identity_notes:
        if ip_note not in notes:
            notes.append(ip_note)

    if asset_tier != "standard":
        notes.append(f"Asset tier: {asset_tier} ({asset_weight:+d})")
    if user_risk_tier != "standard_user":
        notes.append(f"User risk: {user_risk_tier} ({user_weight:+d})")

    if enrichment_failed:
        notes.insert(0, "ENRICHMENT_FAILED: extractor error — score may be inaccurate")

    # Emit telemetry (DB-persisted + in-memory buffer)
    _get_telemetry_collector().record(
        alert_type, severity, signals, score, source_tool,
        asset_tier=asset_tier, user_risk_tier=user_risk_tier,
        cross_alert_flags=cross_alert_flags,
    )

    result = EnrichmentResult(
        confidence_score=score,
        confidence_label=label,
        confidence_explanation=explanation,
        recommended_playbook=playbook,
        recommended_actions=actions,
        enrichment_notes=notes,
        asset_tier=asset_tier,
        user_risk_tier=user_risk_tier,
    )

    # ── Prometheus instrumentation ──────────────────────────────────────
    try:
        from backend.app.core.metrics import enrichment_latency, signals_fired
        _duration = _time.monotonic() - _enrich_start
        enrichment_latency.labels(alert_type=alert_type).observe(_duration)
        for s in signals:
            if s.fired and s.weight > 0:
                _tier = getattr(s, "tier", "inferred") or "inferred"
                signals_fired.labels(signal_name=s.name, tier=_tier).inc()
    except Exception:
        pass  # Metrics are best-effort, never fail enrichment

    return result, signals


def enrich(
    alert_type: str,
    severity: str,
    raw_alert: dict[str, Any],
    event_time: datetime,
    tenant_id: str | None = None,
) -> EnrichmentResult:
    result, _ = _run_enrichment(alert_type, severity, raw_alert, event_time, tenant_id=tenant_id)
    return result


def enrich_debug(
    alert_type: str,
    severity: str,
    raw_alert: dict[str, Any],
    event_time: datetime,
    tenant_id: str | None = None,
) -> EnrichmentDebug:
    result, signals = _run_enrichment(alert_type, severity, raw_alert, event_time, tenant_id=tenant_id)
    base = get_severity_base(severity)
    boost = sum(s.weight for s in signals if s.fired)
    return EnrichmentDebug(
        result=result,
        all_signals=signals,
        severity_base=base,
        signal_boost=boost,
    )
