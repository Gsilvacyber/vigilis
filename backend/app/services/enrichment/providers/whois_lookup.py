"""WHOIS Domain Age Lookup — identifies newly registered phishing domains.

A domain registered 2 days ago sending login links is almost certainly phishing.
A domain registered 10 years ago is probably legitimate. This is one of the
highest-signal enrichments for email-based alerts.

Uses RDAP (Registration Data Access Protocol) — the modern replacement for WHOIS.
FREE, no API key, standardized JSON responses.

Endpoint: https://rdap.org/domain/{domain}
Rate limit: Varies by registry (typically 100-1000/day)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.app.services.enrichment.threat_intel import ThreatIntelResult

_log = logging.getLogger(__name__)
_RDAP_URL = "https://rdap.org/domain/{domain}"
_TIMEOUT = 8


class WHOISProvider:
    """RDAP-based domain age and registration lookup."""

    def check_ip(self, ip: str) -> ThreatIntelResult | None:
        return None  # WHOIS is domain-only

    def check_hash(self, file_hash: str) -> ThreatIntelResult | None:
        return None  # WHOIS is domain-only

    def check_domain(self, domain: str) -> ThreatIntelResult | None:
        """Look up domain registration date via RDAP.

        Returns:
          - ThreatIntelResult with confidence based on domain age
          - Fires if domain is < 30 days old (likely phishing infrastructure)
        """
        if not domain or "." not in domain:
            return None

        # Skip well-known legitimate domains
        _SKIP = {"google.com", "microsoft.com", "amazon.com", "cloudflare.com",
                 "github.com", "dropbox.com", "apple.com", "facebook.com",
                 "twitter.com", "linkedin.com", "office.com", "live.com",
                 "outlook.com", "yahoo.com", "gmail.com"}
        if domain.lower() in _SKIP:
            return None

        try:
            with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
                resp = client.get(_RDAP_URL.format(domain=domain))

            if resp.status_code != 200:
                _log.debug("RDAP returned %d for %s", resp.status_code, domain)
                return None

            data = resp.json()

            # Extract registration date from RDAP events
            reg_date = None
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    date_str = event.get("eventDate", "")
                    if date_str:
                        try:
                            reg_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                        except (ValueError, TypeError):
                            pass
                    break

            if reg_date is None:
                return None

            # Calculate domain age
            now = datetime.now(timezone.utc)
            age_days = (now - reg_date).days

            # Extract registrar
            registrar = ""
            for entity in data.get("entities", []):
                if "registrar" in entity.get("roles", []):
                    vcard = entity.get("vcardArray", [])
                    if len(vcard) >= 2:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                registrar = item[3]
                                break

            tags = []
            confidence = 0.3
            is_malicious = False

            if age_days < 7:
                # Less than 1 week — very likely phishing/malicious
                tags.append("domain_age_critical")
                confidence = 0.95
                is_malicious = True
            elif age_days < 30:
                # Less than 1 month — suspicious
                tags.append("domain_age_suspicious")
                confidence = 0.75
                is_malicious = True
            elif age_days < 90:
                # Less than 3 months — worth noting
                tags.append("domain_age_young")
                confidence = 0.40
            else:
                # Established domain — probably legitimate
                return None  # No signal needed for old domains

            details = f"WHOIS: Domain {domain} registered {age_days} days ago"
            if registrar:
                details += f" (registrar: {registrar})"

            return ThreatIntelResult(
                is_malicious=is_malicious,
                confidence=confidence,
                source="whois_rdap",
                tags=tags,
                details=details,
            )

        except httpx.TimeoutException:
            _log.debug("RDAP timeout for %s", domain)
        except Exception:
            _log.debug("RDAP error for %s", domain, exc_info=True)

        return None
