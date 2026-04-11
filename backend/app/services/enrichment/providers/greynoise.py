"""GreyNoise Community API provider — classifies IPs as benign/malicious/unknown.

GreyNoise scans the entire internet and tells you whether an IP is a known
scanner, bot, or benign service (search engines, CDNs, security researchers).

WHY THIS MATTERS:
  If an IP is classified as "benign" by GreyNoise (e.g., Googlebot), we can
  REDUCE the confidence score — it's not an attacker, it's a crawler.
  If classified as "malicious," we get VERIFIED threat intel without OTX.

API: https://api.greynoise.io/v3/community/{ip}
Rate limit: 50 requests/day (community, no key), 500/day (free key)
Commercial: Free community tier is fine for development. Enterprise for prod.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from backend.app.services.enrichment.threat_intel import ThreatIntelResult

_log = logging.getLogger(__name__)

_GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
_TIMEOUT = 10  # seconds


class GreyNoiseProvider:
    """GreyNoise Community API — IP classification (benign/malicious/unknown)."""

    def __init__(self, api_key: str | None = None):
        self._api_key = api_key
        self._headers: dict[str, str] = {"Accept": "application/json"}
        if api_key:
            self._headers["key"] = api_key

    def check_ip(self, ip: str) -> ThreatIntelResult | None:
        """Query GreyNoise for IP classification.

        Returns:
          - ThreatIntelResult with is_malicious=True if classified "malicious"
          - ThreatIntelResult with is_malicious=False, tags=["greynoise_benign"]
            if classified "benign" (this is a NOISE REDUCTION signal)
          - None if unknown or API error
        """
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.get(
                    _GREYNOISE_COMMUNITY_URL.format(ip=ip),
                    headers=self._headers,
                )

            if resp.status_code == 404:
                return None  # IP not in GreyNoise database
            if resp.status_code != 200:
                _log.debug("GreyNoise API returned %d for %s", resp.status_code, ip)
                return None

            data = resp.json()
            classification = data.get("classification", "unknown")
            noise = data.get("noise", False)
            riot = data.get("riot", False)  # Rule It Out Test — known benign
            name = data.get("name", "")
            link = data.get("link", "")

            if classification == "malicious":
                return ThreatIntelResult(
                    is_malicious=True,
                    confidence=0.85,
                    source="greynoise",
                    tags=["greynoise_malicious"],
                    details=f"GreyNoise: IP {ip} classified as malicious ({name})",
                )
            elif classification == "benign" or riot:
                # Benign IP — identify the SERVICE, not just "benign"
                service_name = name or "unknown service"
                service_detail = f"GreyNoise: IP {ip} identified as {service_name}"
                if riot:
                    service_detail += " (known CDN/cloud/legitimate service)"
                return ThreatIntelResult(
                    is_malicious=False,
                    confidence=0.90,
                    source="greynoise",
                    tags=["greynoise_benign"],
                    details=service_detail,
                )
            elif noise:
                # Known scanner — not targeted, just noise
                return ThreatIntelResult(
                    is_malicious=False,
                    confidence=0.70,
                    source="greynoise",
                    tags=["greynoise_scanner"],
                    details=f"GreyNoise: IP {ip} is a known internet scanner",
                )

        except httpx.TimeoutException:
            _log.debug("GreyNoise timeout for %s", ip)
        except Exception:
            _log.debug("GreyNoise error for %s", ip, exc_info=True)

        return None

    def check_domain(self, domain: str) -> ThreatIntelResult | None:
        return None  # GreyNoise is IP-only

    def check_hash(self, file_hash: str) -> ThreatIntelResult | None:
        return None  # GreyNoise is IP-only
