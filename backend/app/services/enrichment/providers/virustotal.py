"""VirusTotal threat intelligence provider."""
import logging
import threading
import time
from typing import Optional

import httpx

from backend.app.services.enrichment.threat_intel import ThreatIntelResult

_log = logging.getLogger(__name__)


class _RateLimiter:
    """Sliding window rate limiter."""

    def __init__(self, max_requests: int = 4, window_seconds: int = 60):
        self._max = max_requests
        self._window = window_seconds
        self._timestamps: list[float] = []
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 15.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                now = time.monotonic()
                self._timestamps = [
                    t for t in self._timestamps if now - t < self._window
                ]
                if len(self._timestamps) < self._max:
                    self._timestamps.append(now)
                    return True
            time.sleep(0.5)
        return False


class VirusTotalProvider:
    """VirusTotal API v3 threat intelligence provider."""

    def __init__(self, api_key: str, rate_limit: int = 4):
        self._api_key = api_key
        self._client = httpx.Client(
            base_url="https://www.virustotal.com/api/v3",
            headers={"x-apikey": api_key},
            timeout=10.0,
        )
        self._limiter = _RateLimiter(max_requests=rate_limit)

    def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        return self._check("ip_addresses", ip, "ip")

    def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        return self._check("domains", domain, "domain")

    def check_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        return self._check("files", file_hash, "hash")

    def _check(
        self, endpoint: str, indicator: str, indicator_type: str
    ) -> Optional[ThreatIntelResult]:
        if not self._limiter.acquire(timeout=15):
            _log.warning(
                "VirusTotal rate limit exceeded, skipping %s", indicator
            )
            return None
        try:
            resp = self._client.get(f"/{endpoint}/{indicator}")
            if resp.status_code == 404:
                return None  # Not in VT database
            if resp.status_code == 429:
                _log.warning(
                    "VirusTotal 429 rate limited for %s", indicator
                )
                return None
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            return self._parse(data, indicator, indicator_type)
        except httpx.HTTPError as e:
            _log.warning("VirusTotal API error for %s: %s", indicator, e)
            return None

    def _parse(
        self, attrs: dict, indicator: str, indicator_type: str
    ) -> Optional[ThreatIntelResult]:
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        reputation = attrs.get("reputation", 0)

        if malicious == 0 and suspicious == 0:
            return None  # Clean

        confidence = malicious / total
        is_malicious = malicious > 5
        tags = []
        if is_malicious:
            tags.append(f"vt_malicious_{indicator_type}")
        elif malicious > 0 or suspicious > 0:
            tags.append(f"vt_suspicious_{indicator_type}")
        if reputation < -50:
            tags.append("vt_bad_reputation")
        vt_tags = attrs.get("tags", [])
        if "tor" in [t.lower() for t in vt_tags]:
            tags.append("tor_exit_node")

        details = (
            f"VirusTotal: {malicious}/{total} engines flagged "
            f"{indicator_type} {indicator}; reputation={reputation}"
        )

        return ThreatIntelResult(
            is_malicious=is_malicious,
            confidence=confidence,
            source="virustotal",
            tags=tags,
            details=details,
        )
