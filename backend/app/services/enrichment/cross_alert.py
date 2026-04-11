"""Cross-Alert Intelligence: detect patterns when the same entity triggers
multiple alerts within a sliding time window.

This layer sits ABOVE individual enrichment but BELOW incident correlation.
It rewards signal convergence — the same user or host appearing across
different alert domains (identity + endpoint, identity + cloud, etc.) within
minutes is far more suspicious than isolated alerts.

Thread-safe: uses a lock around the sliding window so batch ingestion
can register alerts concurrently.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass
class CrossAlertSignal:
    name: str
    weight: int
    label: str
    entity_key: str
    contributing_alerts: list[str]


@dataclass
class _WindowEntry:
    alert_type: str
    entity_key: str
    timestamp: datetime
    domain: str


def _extract_domain(alert_type: str) -> str:
    """Get the top-level domain from an alert type (e.g., 'identity' from 'identity.suspiciousSignIn')."""
    return alert_type.split(".")[0] if "." in alert_type else alert_type


def _extract_entity_keys(raw_alert: dict[str, Any]) -> list[str]:
    """Pull deduped entity keys from a raw alert: UPN, hostname, public source IPs."""
    from backend.app.services.enrichment.base import _is_private_ip

    keys: list[str] = []

    identity = raw_alert.get("identity") or {}
    upn = identity.get("upn") or ""
    if upn and "@" in upn:
        keys.append(upn.lower())

    device = raw_alert.get("device") or {}
    hostname = device.get("hostname") or ""
    if hostname:
        keys.append(hostname.upper())

    import ipaddress as _ipa
    for ip_obj in raw_alert.get("ips") or raw_alert.get("ipAddresses") or []:
        if isinstance(ip_obj, dict):
            addr = ip_obj.get("ipAddress", "")
            if not addr:
                continue
            try:
                _ipa.ip_address(addr)
            except (ValueError, TypeError):
                continue
            if not _is_private_ip(addr):
                keys.append(addr)

    return list(dict.fromkeys(keys))


class CrossAlertScanner:
    """Thread-safe sliding window scanner for cross-alert pattern detection."""

    def __init__(self, window_minutes: int = 15):
        self._window = timedelta(minutes=window_minutes)
        self._entries: list[_WindowEntry] = []
        self._entity_index: dict[str, list[_WindowEntry]] = defaultdict(list)
        self._lock = threading.Lock()

    def _prune(self, now: datetime) -> None:
        cutoff = now - self._window
        to_remove = [e for e in self._entries if e.timestamp < cutoff]
        for entry in to_remove:
            self._entries.remove(entry)
            bucket = self._entity_index.get(entry.entity_key, [])
            if entry in bucket:
                bucket.remove(entry)
            if not bucket:
                self._entity_index.pop(entry.entity_key, None)

    def register_alert(
        self,
        alert_type: str,
        entity_keys: list[str],
        timestamp: datetime,
    ) -> None:
        with self._lock:
            now = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
            self._prune(now)
            domain = _extract_domain(alert_type)
            for key in entity_keys:
                entry = _WindowEntry(
                    alert_type=alert_type,
                    entity_key=key,
                    timestamp=now,
                    domain=domain,
                )
                self._entries.append(entry)
                self._entity_index[key].append(entry)

    def scan_for_patterns(self, entity_keys: list[str]) -> list[CrossAlertSignal]:
        signals: list[CrossAlertSignal] = []
        seen_patterns: set[str] = set()

        with self._lock:
            for key in entity_keys:
                entries = self._entity_index.get(key, [])
                if len(entries) < 2:
                    continue

                domains = {e.domain for e in entries}
                alert_types = [e.alert_type for e in entries]
                unique_types = list(dict.fromkeys(alert_types))

                pattern_key_multi = f"multiVector:{key}"
                if len(domains) >= 2 and pattern_key_multi not in seen_patterns:
                    seen_patterns.add(pattern_key_multi)
                    signals.append(CrossAlertSignal(
                        name="_multiVectorAttack",
                        weight=12,
                        label=(
                            f"Multi-vector attack: entity '{key}' triggered alerts "
                            f"across {len(domains)} domains ({', '.join(sorted(domains))})"
                        ),
                        entity_key=key,
                        contributing_alerts=unique_types,
                    ))

                pattern_key_corr = f"corroboration:{key}"
                if len(entries) >= 2 and len(domains) == 1 and pattern_key_corr not in seen_patterns:
                    seen_patterns.add(pattern_key_corr)
                    signals.append(CrossAlertSignal(
                        name="_crossAlertCorroboration",
                        weight=8,
                        label=(
                            f"Cross-alert corroboration: entity '{key}' triggered "
                            f"{len(entries)} alerts in the {list(domains)[0]} domain"
                        ),
                        entity_key=key,
                        contributing_alerts=unique_types,
                    ))

                now = max(e.timestamp for e in entries)
                five_min_ago = now - timedelta(minutes=5)
                recent = [e for e in entries if e.timestamp >= five_min_ago]
                pattern_key_rapid = f"rapid:{key}"
                if len(recent) >= 3 and pattern_key_rapid not in seen_patterns:
                    seen_patterns.add(pattern_key_rapid)
                    signals.append(CrossAlertSignal(
                        name="_rapidEscalation",
                        weight=10,
                        label=(
                            f"Rapid escalation: entity '{key}' triggered "
                            f"{len(recent)} alerts within 5 minutes"
                        ),
                        entity_key=key,
                        contributing_alerts=list(dict.fromkeys(e.alert_type for e in recent)),
                    ))

                # DLP + data transfer combo: if same entity has both
                # data exfiltration AND (large data transfer OR suspicious sign-in)
                entry_types = {e.alert_type for e in entries}
                has_exfil = any("dataExfiltration" in t or "exfil" in t.lower() for t in entry_types)
                has_transfer_or_signin = any(
                    "large_data_transfer" in t or "largeDataTransfer" in t
                    or "suspiciousSignIn" in t or "suspicious_signin" in t
                    for t in entry_types
                )
                pattern_key_dlp = f"dlp_corroborated:{key}"
                if has_exfil and has_transfer_or_signin and pattern_key_dlp not in seen_patterns:
                    seen_patterns.add(pattern_key_dlp)
                    signals.append(CrossAlertSignal(
                        name="_dlpCorroborated",
                        weight=15,
                        label=(
                            f"DLP corroborated: entity '{key}' has both data exfiltration "
                            f"and transfer/sign-in alerts — likely insider data theft"
                        ),
                        entity_key=key,
                        contributing_alerts=list(dict.fromkeys(e.alert_type for e in entries)),
                    ))

        return signals

    def get_domain_pair(self, entity_keys: list[str]) -> tuple[str, ...]:
        """Return sorted tuple of domains seen for the given entity keys."""
        domains: set[str] = set()
        with self._lock:
            for key in entity_keys:
                for entry in self._entity_index.get(key, []):
                    domains.add(entry.domain)
        return tuple(sorted(domains))

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._entity_index.clear()


# Module-level singleton
_scanner = CrossAlertScanner()


def get_scanner() -> CrossAlertScanner:
    return _scanner


def reset_scanner(window_minutes: int = 15) -> CrossAlertScanner:
    global _scanner
    _scanner = CrossAlertScanner(window_minutes=window_minutes)
    return _scanner
