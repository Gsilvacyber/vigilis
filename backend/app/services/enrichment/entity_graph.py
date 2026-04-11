"""Entity Graph — the detection brain.

Tracks relationships between entities across cases:
  user ↔ host     ("admin logged into DC-01")
  host ↔ process  ("DC-01 ran psexec.exe")
  process ↔ ip    ("psexec.exe connected to 10.10.50.20")
  ip ↔ domain     ("162.125.1.1 is dropbox.com")

During enrichment, we query: "Has this relationship been seen before?"
  first_seen = never → NEW relationship signal (verified)
  count = 1-2       → RARE relationship signal (verified)
  count > 50        → NORMAL (noise reduction possible)

This is the single most important enrichment module because it gives us
BEHAVIORAL context from our OWN data — no external API needed.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import UUID

from backend.app.services.enrichment.base import Signal

_log = logging.getLogger(__name__)


# ── Relationship Extraction ─────────────────────────────────────────────
# Given a case's raw alert data, extract entity pairs and upsert them
# into the EntityRelationship table.

def extract_and_store_relationships(
    raw_alert: dict[str, Any],
    case_id: UUID | None = None,
    tenant_id: str | None = None,
) -> int:
    """Extract entity pairs from a case and upsert into EntityRelationship table.

    Call this AFTER enrichment is complete and the case is persisted.
    Returns the number of relationships upserted.

    Entity pairs extracted:
      - user ↔ host      (identity.upn ↔ device.hostname)
      - user ↔ ip        (identity.upn ↔ each external IP)
      - host ↔ process   (device.hostname ↔ process name from raw fields)
      - host ↔ ip        (device.hostname ↔ each external IP)
      - process ↔ ip     (process name ↔ destination IP)
      - ip ↔ domain      (IP ↔ domain from enrichment notes or raw fields)
    """
    pairs = _extract_pairs(raw_alert)
    if not pairs:
        return 0

    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import EntityRelationship
        from sqlmodel import select

        count = 0
        with get_session() as session:
            for rel_type, a_type, a_val, b_type, b_val in pairs:
                # Normalize values for consistent lookups
                a_val = a_val.strip().lower()
                b_val = b_val.strip().lower()

                if not a_val or not b_val or a_val == b_val:
                    continue

                # Upsert: increment count if exists, create if new
                existing = session.exec(
                    select(EntityRelationship).where(
                        EntityRelationship.entity_a_type == a_type,
                        EntityRelationship.entity_a_value == a_val,
                        EntityRelationship.entity_b_type == b_type,
                        EntityRelationship.entity_b_value == b_val,
                    )
                ).first()

                now = datetime.now(timezone.utc)
                if existing:
                    existing.count += 1
                    existing.last_seen = now
                    if case_id:
                        existing.last_case_id = case_id
                    session.add(existing)
                else:
                    session.add(EntityRelationship(
                        entity_a_type=a_type,
                        entity_a_value=a_val,
                        entity_b_type=b_type,
                        entity_b_value=b_val,
                        relationship_type=rel_type,
                        count=1,
                        first_seen=now,
                        last_seen=now,
                        tenant_id=tenant_id,
                        last_case_id=case_id,
                    ))
                count += 1

            session.commit()

        _log.debug("Entity graph: stored %d relationships for case %s", count, case_id)
        return count

    except Exception:
        _log.exception("Entity graph: failed to store relationships")
        return 0


def _extract_pairs(
    raw_alert: dict[str, Any],
) -> list[tuple[str, str, str, str, str]]:
    """Extract (relationship_type, a_type, a_value, b_type, b_value) tuples.

    Reads from structured entity fields that the enrichment pipeline
    already populates: identity, device, ips, plus raw alert fields.
    """
    pairs: list[tuple[str, str, str, str, str]] = []

    # Extract entity values from the alert
    # Handle both dict (from rawAlert) and Pydantic model (from result.entities)
    identity = raw_alert.get("identity") or {}
    if isinstance(identity, dict):
        upn = identity.get("upn", "") or ""
    elif hasattr(identity, "upn"):
        upn = getattr(identity, "upn", "") or ""
    else:
        upn = ""

    device = raw_alert.get("device") or {}
    if isinstance(device, dict):
        hostname = device.get("hostname", "") or ""
    elif hasattr(device, "hostname"):
        hostname = getattr(device, "hostname", "") or ""
    else:
        hostname = ""

    # Collect IPs (external only — private IPs are noise for graph)
    ips_list = raw_alert.get("ips") or []
    external_ips: list[str] = []
    for ip_entry in ips_list:
        if isinstance(ip_entry, dict):
            ip_addr = ip_entry.get("ipAddress", "") or ""
        elif isinstance(ip_entry, str):
            ip_addr = ip_entry
        else:
            continue
        if ip_addr and not _is_private_ip(ip_addr):
            external_ips.append(ip_addr)

    # Also check raw fields for IPs we might have missed
    for field in ("dst_ip", "_dstIp", "destinationIp", "sourceIp", "_srcIp"):
        raw_ip = raw_alert.get(field, "") or ""
        if raw_ip and not _is_private_ip(raw_ip) and raw_ip not in external_ips:
            external_ips.append(raw_ip)

    # Extract process name from raw fields
    process_name = ""
    for field in ("process", "_processName", "processName", "imagePath",
                  "_imagePath", "commandLine", "_commandLine"):
        raw_proc = raw_alert.get(field, "") or ""
        if raw_proc:
            # Extract just the executable name from paths
            proc = raw_proc.strip().strip('"')
            if "\\" in proc:
                proc = proc.rsplit("\\", 1)[-1]
            elif "/" in proc:
                proc = proc.rsplit("/", 1)[-1]
            # If it's a command line, take the first token
            if " " in proc:
                proc = proc.split()[0]
            if proc and len(proc) > 2:
                process_name = proc
                break

    # Extract domain from raw fields or enrichment
    domain = ""
    for field in ("domain", "_domain", "destinationDomain", "_dstDomain"):
        raw_domain = raw_alert.get(field, "") or ""
        if raw_domain and "." in raw_domain:
            domain = raw_domain
            break

    # Build relationship pairs
    # 1. user ↔ host
    if upn and hostname:
        pairs.append(("user_host", "user", upn, "host", hostname))

    # 2. user ↔ ip (each external IP the user interacted with)
    if upn:
        for ip in external_ips[:5]:  # Cap at 5 to avoid noise
            pairs.append(("user_ip", "user", upn, "ip", ip))

    # 3. host ↔ process
    if hostname and process_name:
        pairs.append(("host_process", "host", hostname, "process", process_name))

    # 4. host ↔ ip
    if hostname:
        for ip in external_ips[:5]:
            pairs.append(("host_ip", "host", hostname, "ip", ip))

    # 5. process ↔ ip
    if process_name:
        for ip in external_ips[:3]:
            pairs.append(("process_ip", "process", process_name, "ip", ip))

    # 6. ip ↔ domain
    if domain:
        for ip in external_ips[:3]:
            pairs.append(("ip_domain", "ip", ip, "domain", domain))

    # 7. Phase 3: state drift relationships (host↔service, host↔task, etc.)
    # Only populated when _stateCategory is set (i.e., from endpoint.stateDrift)
    if raw_alert.get("_stateCategory"):
        try:
            pairs.extend(_extract_state_drift_pairs(raw_alert))
        except Exception:
            pass

    return pairs


# ── Relationship Query for Enrichment Signals ──────────────────────────
# Query the entity graph BEFORE storing new relationships.
# This answers: "Have we seen these entity combinations before?"

def check_entity_relationships(
    raw_alert: dict[str, Any],
    event_time: datetime,
    tenant_id: str | None = None,
) -> list[Signal]:
    """Query entity graph for behavioral signals.

    Called during enrichment (BEFORE relationships are stored for this case).
    Returns verified signals based on relationship novelty and frequency.

    Signals produced:
      - new_entity_relationship: Entity pair NEVER seen before (weight 20, verified)
      - rare_entity_relationship: Entity pair seen 1-2 times (weight 15, verified)
      - entity_graph_anomaly: Multiple NEW relationships in one case (weight 18, verified)
    """
    pairs = _extract_pairs(raw_alert)
    if not pairs:
        return []

    # Cold-start suppression: if the entity graph has fewer than 20 total
    # relationships, we don't have enough behavioral baseline to make
    # meaningful "new" vs "rare" judgments. Without this, fresh deployments
    # flag EVERY alert as novel, inflating scores on benign activity.
    try:
        from backend.app.core.db import get_session as _gs
        from backend.app.db.models import EntityRelationship as _ER
        from sqlmodel import select as _sel, func as _fn
        with _gs() as _cs:
            total_rels = _cs.exec(_sel(_fn.count(_ER.id))).one()
        if total_rels < 20:
            _log.debug(
                "Entity graph cold-start: only %d relationships, suppressing signals",
                total_rels,
            )
            return []
    except Exception:
        pass  # If count check fails, proceed with normal logic

    signals: list[Signal] = []
    new_count = 0
    rare_count = 0
    relationship_details: list[str] = []

    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import EntityRelationship
        from sqlmodel import select

        with get_session() as session:
            for rel_type, a_type, a_val, b_type, b_val in pairs:
                a_val = a_val.strip().lower()
                b_val = b_val.strip().lower()
                if not a_val or not b_val or a_val == b_val:
                    continue

                existing = session.exec(
                    select(EntityRelationship).where(
                        EntityRelationship.entity_a_type == a_type,
                        EntityRelationship.entity_a_value == a_val,
                        EntityRelationship.entity_b_type == b_type,
                        EntityRelationship.entity_b_value == b_val,
                    )
                ).first()

                if existing is None:
                    # NEVER seen before — this is a novel relationship
                    new_count += 1
                    relationship_details.append(
                        f"{a_type}:{a_val} ↔ {b_type}:{b_val} (NEW)"
                    )
                elif existing.count <= 2:
                    # Seen 1-2 times — still rare
                    rare_count += 1
                    relationship_details.append(
                        f"{a_type}:{a_val} ↔ {b_type}:{b_val} "
                        f"(seen {existing.count}x, first: {existing.first_seen:%Y-%m-%d})"
                    )
                # count > 2 = normal, no signal

    except Exception:
        _log.debug("Entity graph query failed (non-fatal)", exc_info=True)
        return []

    # Fire signals based on findings
    from backend.app.services.enrichment.weights import W

    if new_count >= 1:
        # At least one entity relationship never seen before
        # More impactful for identity types (user_host, user_ip)
        weight = W.get("new_entity_relationship", 20)
        label = (
            f"New entity relationship detected: "
            f"{new_count} never-before-seen entity pair(s)"
        )
        if new_count == 1 and relationship_details:
            label = f"New entity relationship: {relationship_details[0]}"
        signals.append(Signal(
            name="new_entity_relationship",
            weight=weight,
            fired=True,
            label=label,
            tier="verified",
        ))

    if rare_count >= 1:
        weight = W.get("rare_entity_relationship", 15)
        label = f"Rare entity relationship: {rare_count} pair(s) seen ≤2 times previously"
        signals.append(Signal(
            name="rare_entity_relationship",
            weight=weight,
            fired=True,
            label=label,
            tier="verified",
        ))

    # Compound signal: multiple NEW relationships = highly anomalous
    if new_count >= 3:
        weight = W.get("entity_graph_anomaly", 18)
        signals.append(Signal(
            name="entity_graph_anomaly",
            weight=weight,
            fired=True,
            label=(
                f"Entity graph anomaly: {new_count} new relationships in single case — "
                f"strongly suggests novel/unauthorized behavior"
            ),
            tier="verified",
        ))

    return signals


# ── Process-Based Enrichment (for endpoint alerts without external IPs) ──
# Ransomware, malware, lateral movement alerts often have NO external IP.
# The entity graph can still provide verified signals from host↔process data.

_SERVER_PREFIXES = ("dc-", "ad-", "srv-", "server-", "sql-", "db-", "file-",
                    "fs-", "nas-", "backup-", "mail-", "exchange-", "ca-")

_HIGH_RISK_PROCESSES = frozenset({
    "vssadmin.exe", "bcdedit.exe", "wbadmin.exe",  # ransomware indicators
    "mimikatz.exe", "rubeus.exe", "sharphound.exe",  # AD attack tools
    "psexec.exe", "psexec64.exe", "crackmapexec",  # lateral movement
    "cobalt", "beacon.exe", "cobaltstrike",  # C2
    "procdump.exe", "procdump64.exe",  # credential dumping
    "certutil.exe", "bitsadmin.exe",  # LOLBins used in attacks
    "wmic.exe", "mshta.exe", "regsvr32.exe",  # LOLBins
})


def check_process_relationships(
    raw_alert: dict[str, Any],
    event_time: datetime,
    tenant_id: str | None = None,
) -> list[Signal]:
    """Check host↔process relationships in entity graph for endpoint alerts.

    This is specifically for alerts that have NO external IPs — ransomware,
    malware, persistence, lateral movement. The entity graph can still tell us:
      - "Has this process EVER been seen on this host?" (verified)
      - "Is this a high-risk process on a server/DC?" (verified)

    Signals produced:
      - process_on_new_host: Process never seen on this host (weight 18, verified)
      - rare_process_on_server: Rare process on server infrastructure (weight 20, verified)
      - known_tool_on_dc: Known attack tool on domain controller (weight 25, verified)
    """
    signals: list[Signal] = []

    # Cold-start suppression: known_tool_on_dc always fires (too important),
    # but process_on_new_host requires ≥10 total relationships to avoid
    # flagging every process as "new" on fresh deployment
    _suppress_novelty = False
    try:
        from backend.app.core.db import get_session as _gs2
        from backend.app.db.models import EntityRelationship as _ER2
        from sqlmodel import select as _sel2, func as _fn2
        with _gs2() as _cs2:
            _total = _cs2.exec(_sel2(_fn2.count(_ER2.id))).one()
        _suppress_novelty = _total < 10
    except Exception:
        pass

    # Extract hostname and process
    device = raw_alert.get("device") or {}
    hostname = ""
    if isinstance(device, dict):
        hostname = (device.get("hostname") or "").strip().lower()
    elif hasattr(device, "hostname"):
        hostname = (getattr(device, "hostname", "") or "").strip().lower()

    process_name = ""
    for field in ("process", "_processName", "processName", "imagePath",
                  "_imagePath", "commandLine", "_commandLine"):
        raw_proc = str(raw_alert.get(field, "") or "").strip().strip('"')
        if raw_proc:
            if "\\" in raw_proc:
                raw_proc = raw_proc.rsplit("\\", 1)[-1]
            elif "/" in raw_proc:
                raw_proc = raw_proc.rsplit("/", 1)[-1]
            if " " in raw_proc:
                raw_proc = raw_proc.split()[0]
            if raw_proc and len(raw_proc) > 2:
                process_name = raw_proc.lower()
                break

    # Also check file.fileName
    if not process_name:
        f = raw_alert.get("file") or {}
        if isinstance(f, dict):
            fname = (f.get("fileName") or "").strip().lower()
            if fname and len(fname) > 2:
                process_name = fname

    if not hostname or not process_name:
        return []

    is_server = any(hostname.startswith(p) for p in _SERVER_PREFIXES)
    is_dc = hostname.startswith(("dc-", "ad-"))
    is_high_risk = process_name in _HIGH_RISK_PROCESSES

    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import EntityRelationship
        from sqlmodel import select
        from backend.app.services.enrichment.weights import W

        with get_session() as session:
            existing = session.exec(
                select(EntityRelationship).where(
                    EntityRelationship.entity_a_type == "host",
                    EntityRelationship.entity_a_value == hostname,
                    EntityRelationship.entity_b_type == "process",
                    EntityRelationship.entity_b_value == process_name,
                )
            ).first()

            # Signal 1: Process never seen on this host (suppressed during cold-start)
            if existing is None and not _suppress_novelty:
                weight = W.get("process_on_new_host", 18)
                signals.append(Signal(
                    name="process_on_new_host",
                    weight=weight,
                    fired=True,
                    label=f"Process '{process_name}' has NEVER been seen on {hostname}",
                    tier="verified",
                ))

            # Signal 2: Rare process on server infrastructure
            if is_server and (existing is None or existing.count <= 2):
                weight = W.get("rare_process_on_server", 20)
                count_str = "never" if existing is None else f"{existing.count}x"
                signals.append(Signal(
                    name="rare_process_on_server",
                    weight=weight,
                    fired=True,
                    label=f"Rare process '{process_name}' on server {hostname} (seen {count_str})",
                    tier="verified",
                ))

            # Signal 3: Known attack tool on domain controller
            if is_dc and is_high_risk:
                weight = W.get("known_tool_on_dc", 25)
                signals.append(Signal(
                    name="known_tool_on_dc",
                    weight=weight,
                    fired=True,
                    label=f"CRITICAL: Attack tool '{process_name}' on domain controller {hostname}",
                    tier="verified",
                ))

    except Exception:
        _log.debug("Process relationship check failed (non-fatal)", exc_info=True)

    return signals


# ── Phase 3: State Drift Detection ───────────────────────────────────────
# Inspects endpoint.stateDrift events (from export_state.ps1) and fires
# verified-tier signals when new configuration items appear in suspicious
# locations. This is the persistence detection layer that complements the
# event stream with a picture of the host's standing configuration.

def check_state_drift(
    raw_alert: dict[str, Any],
    event_time: datetime,
    tenant_id: str | None = None,
) -> list[Signal]:
    """Inspect state drift events and fire signals on suspicious additions.

    Only runs when alertType is `endpoint.stateDrift` and the event carries
    `_stateCategory` / `_driftAction` fields. Returns verified-tier signals
    for items in sensitive locations or running suspicious commands.

    Signals produced:
      - unusual_service_path: service binary outside standard paths (weight 20)
      - userland_autorun: autorun in C:\\Users\\*\\AppData\\* (weight 22)
      - script_scheduled_task: task runs powershell/cmd directly (weight 20)
      - state_drift: base weight 8 (always fires for any drift)
    """
    signals: list[Signal] = []

    category = str(raw_alert.get("_stateCategory") or "").lower()
    action = str(raw_alert.get("_driftAction") or "").lower()

    if not category or action != "added":
        # Only fire signals on additions. Modifications and removals can
        # be useful later but often legitimate.
        return signals

    from backend.app.services.enrichment.weights import W

    # Base signal — every drift fires a low-weight observed signal
    signals.append(Signal(
        name="state_drift",
        weight=W.get("state_drift", 8),
        fired=True,
        label=f"State drift detected: {action} {category} '{raw_alert.get('_driftItem', 'unknown')}'",
        tier="observed",
    ))

    item = str(raw_alert.get("_driftItem") or "")
    details = raw_alert.get("_driftDetails") or {}
    # Details may come as either a dict or a string
    details_str = ""
    if isinstance(details, dict):
        details_str = " ".join(str(v) for v in details.values() if v).lower()
    elif isinstance(details, str):
        details_str = details.lower()

    # ── Unusual service path ─────────────────────────────────────────────
    if category == "service":
        # Fix: operator precedence bug (flagged in audit).
        # Previously: `str(X or Y if cond else Z)` — parsed as `str(X or (Y if cond else Z))`
        # which returned 'None' as a string when both X and Y were None.
        svc_path = ""
        direct = raw_alert.get("_servicePath")
        if direct:
            svc_path = str(direct).lower()
        elif isinstance(details, dict):
            p = details.get("pathName")
            if p:
                svc_path = str(p).lower()
        elif details_str:
            svc_path = details_str
        if svc_path:
            safe_prefixes = (
                "c:\\windows\\",
                "c:\\program files\\",
                "c:\\program files (x86)\\",
                "c:/windows/",
                "c:/program files/",
                "%systemroot%",
                "%programfiles%",
            )
            in_safe_path = any(svc_path.startswith(p) for p in safe_prefixes)
            if not in_safe_path:
                signals.append(Signal(
                    name="unusual_service_path",
                    weight=W.get("unusual_service_path", 20),
                    fired=True,
                    label=f"New service '{item}' points to non-standard path: {svc_path}",
                    tier="verified",
                ))
                raw_alert["_unusualServicePath"] = True

    # ── Userland autorun (attacker persistence) ──────────────────────────
    if category == "autorun":
        autorun_target = details_str
        # Any autorun pointing to %APPDATA% / %TEMP% / %USERPROFILE% is suspicious.
        # All registry-sourced paths use Windows backslashes — only those variants.
        userland_patterns = (
            "appdata\\local",
            "appdata\\roaming",
            "\\temp\\",
            "\\users\\public\\",
            "%appdata%",
            "%temp%",
            "%userprofile%",
        )
        if any(p in autorun_target for p in userland_patterns):
            signals.append(Signal(
                name="userland_autorun",
                weight=W.get("userland_autorun", 22),
                fired=True,
                label=f"New autorun in userland path: {item} -> {autorun_target[:100]}",
                tier="verified",
            ))
            raw_alert["_userlandAutorun"] = True

    # ── Scheduled task running a shell/script interpreter ────────────────
    if category == "scheduled_task":
        task_cmd = details_str
        shell_patterns = (
            "powershell.exe",
            "powershell ",
            "pwsh.exe",
            "cmd.exe",
            "cmd ",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
        )
        if any(p in task_cmd for p in shell_patterns):
            signals.append(Signal(
                name="script_scheduled_task",
                weight=W.get("script_scheduled_task", 20),
                fired=True,
                label=f"New scheduled task '{item}' runs shell/script: {task_cmd[:100]}",
                tier="verified",
            ))
            raw_alert["_scriptScheduledTask"] = True

    # ── Local user added to Administrators group ─────────────────────────
    if category == "local_user" and "admin" in item.lower():
        signals.append(Signal(
            name="privilege_escalation_drift",
            weight=W.get("privilege_escalation_drift", 18),
            fired=True,
            label=f"New local user in admin group: {item}",
            tier="verified",
        ))
        raw_alert["_privilegeEscalation"] = True

    return signals


# Phase 3: extended entity graph extraction for stateDrift events.
# Wire into _extract_pairs so state snapshot drift populates new rel types.
_STATE_DRIFT_RELATIONSHIP_MAP = {
    "service": "host_service",
    "scheduled_task": "host_scheduled_task",
    "autorun": "host_autorun",
    "local_user": "host_local_user",
    "installed_program": "host_installed_program",
    "listening_port": "host_listening_port",
}


def _extract_state_drift_pairs(
    raw_alert: dict[str, Any],
) -> list[tuple[str, str, str, str, str]]:
    """Extract state-drift entity relationships when alertType is stateDrift.

    Returns (relationship_type, a_type, a_value, b_type, b_value) tuples.
    These feed into `extract_and_store_relationships` so the graph learns
    which services/tasks/autoruns exist on which hosts.
    """
    pairs: list[tuple[str, str, str, str, str]] = []

    category = str(raw_alert.get("_stateCategory") or "").lower()
    item = str(raw_alert.get("_driftItem") or "")
    if not category or not item:
        return pairs

    rel_type = _STATE_DRIFT_RELATIONSHIP_MAP.get(category)
    if not rel_type:
        return pairs

    device = raw_alert.get("device") or {}
    hostname = ""
    if isinstance(device, dict):
        hostname = (device.get("hostname") or "").strip().lower()
    elif hasattr(device, "hostname"):
        hostname = (getattr(device, "hostname", "") or "").strip().lower()

    if hostname and item:
        # The "b" entity is the drift item — normalize category for the type
        b_type = {
            "service": "service",
            "scheduled_task": "task",
            "autorun": "autorun",
            "local_user": "user",
            "installed_program": "program",
            "listening_port": "port",
        }.get(category, "item")
        pairs.append((rel_type, "host", hostname, b_type, item))

    return pairs


# ── Utility ──────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    """Check if an IP is RFC 1918 private or loopback."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip.strip())
        return addr.is_private or addr.is_loopback
    except (ValueError, AttributeError):
        return False


def get_entity_graph_stats(tenant_id: str | None = None) -> dict[str, Any]:
    """Return graph statistics for health/status endpoints."""
    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import EntityRelationship
        from sqlmodel import select, func

        with get_session() as session:
            # Total relationships
            total_q = select(func.count(EntityRelationship.id))
            if tenant_id:
                total_q = total_q.where(EntityRelationship.tenant_id == tenant_id)
            total = session.exec(total_q).one()

            # By relationship type
            type_q = (
                select(EntityRelationship.relationship_type,
                       func.count(EntityRelationship.id))
                .group_by(EntityRelationship.relationship_type)
            )
            if tenant_id:
                type_q = type_q.where(EntityRelationship.tenant_id == tenant_id)
            by_type = {rtype: cnt for rtype, cnt in session.exec(type_q).all()}

            # Unique entities
            unique_a = session.exec(
                select(func.count(func.distinct(EntityRelationship.entity_a_value)))
            ).one()

            return {
                "total_relationships": total,
                "by_type": by_type,
                "unique_entities": unique_a,
            }
    except Exception:
        return {"total_relationships": 0, "by_type": {}, "unique_entities": 0}
