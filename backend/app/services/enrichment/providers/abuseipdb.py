"""AbuseIPDB threat intelligence provider."""
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

import httpx

from backend.app.services.enrichment.threat_intel import ThreatIntelResult

_log = logging.getLogger(__name__)


class _DailyCounter:
    """Counter that resets at UTC midnight."""

    def __init__(self, daily_limit: int = 1000):
        self._limit = daily_limit
        self._count = 0
        self._day = 0
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        today = datetime.now(timezone.utc).toordinal()
        with self._lock:
            if self._day != today:
                self._day = today
                self._count = 0
            if self._count >= self._limit:
                return False
            self._count += 1
            return True


class AbuseIPDBProvider:
    """AbuseIPDB threat intelligence provider (IP-only)."""

    def __init__(self, api_key: str, daily_limit: int = 1000):
        self._client = httpx.Client(
            base_url="https://api.abuseipdb.com/api/v2",
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10.0,
        )
        self._counter = _DailyCounter(daily_limit)

    def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        if not self._counter.acquire():
            _log.warning(
                "AbuseIPDB daily limit reached, skipping %s", ip
            )
            return None
        try:
            resp = self._client.get(
                "/check", params={"ipAddress": ip, "maxAgeInDays": 90}
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return self._parse(data, ip)
        except httpx.HTTPError as e:
            _log.warning("AbuseIPDB API error for %s: %s", ip, e)
            return None

    def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        return None  # AbuseIPDB is IP-only

    def check_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        return None  # AbuseIPDB is IP-only

    def _parse(self, data: dict, ip: str) -> Optional[ThreatIntelResult]:
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        is_tor = data.get("isTor", False)
        country = data.get("countryCode", "")
        # NEW: Extract fields we were previously discarding
        isp = data.get("isp", "")
        usage_type = data.get("usageType", "")   # Data Center / ISP / Commercial / etc.
        domain = data.get("domain", "")
        is_public = data.get("isPublic", True)

        if score < 25 and not is_tor and usage_type != "Data Center/Web Hosting/Transit":
            return None  # Clean and not suspicious infrastructure

        tags = []
        is_malicious = False
        if score > 50 and reports > 5:
            is_malicious = True
            tags.append("abuseipdb_malicious")
        elif score >= 25:
            tags.append("abuseipdb_suspicious")
        if is_tor:
            tags.append("abuseipdb_tor")
        # NEW: Tag datacenter/hosting IPs (often used for attack infrastructure)
        if usage_type and "data center" in usage_type.lower():
            tags.append("abuseipdb_datacenter")
        # NEW: Tag based on usage type patterns
        if usage_type and ("vpn" in usage_type.lower() or "proxy" in usage_type.lower()):
            tags.append("abuseipdb_vpn_proxy")

        # Build richer details string
        parts = [f"AbuseIPDB: score={score}/100, {reports} reports"]
        if country:
            parts.append(f"country={country}")
        if isp:
            parts.append(f"ISP: {isp}")
        if usage_type:
            parts.append(f"type: {usage_type}")
        if domain:
            parts.append(f"domain: {domain}")
        if is_tor:
            parts.append("TOR exit node")

        return ThreatIntelResult(
            is_malicious=is_malicious,
            confidence=score / 100,
            source="abuseipdb",
            tags=tags,
            details=", ".join(parts),
        )
