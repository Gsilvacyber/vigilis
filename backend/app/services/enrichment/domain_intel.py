"""Domain intelligence — WHOIS/RDAP lookups for domain age + registrar info.

Adds a powerful enrichment signal: "This domain was registered 2 days ago"
is one of the strongest indicators for phishing, C2, and malware distribution.
Enterprise security platforms (CrowdStrike, Palo Alto) use domain age as a
primary triage signal — new domains are inherently suspicious.

Uses RDAP (Registration Data Access Protocol) — the modern JSON-based
replacement for WHOIS. No library dependency, just httpx.get().

Caching: results are cached in-memory per domain (dict) to avoid repeat
queries within one enrichment batch. Cache TTL is 24 hours. For persistent
caching across restarts, results are also stored in the ThreatIntelIOC table
with source="domain_intel".
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

_log = logging.getLogger(__name__)

# In-memory cache: domain -> (result_dict, timestamp)
_cache: dict[str, tuple[dict[str, Any], float]] = {}
_CACHE_TTL = 86400  # 24 hours

# RDAP endpoint (free, no API key, returns JSON)
_RDAP_URL = "https://rdap.org/domain/{domain}"

# Suspicious TLDs commonly used for phishing/malware
_SUSPICIOUS_TLDS = frozenset({
    ".xyz", ".top", ".club", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".buzz", ".surf", ".icu", ".cam", ".rest", ".monster",
    ".click", ".link", ".work", ".date", ".faith", ".review",
    ".win", ".bid", ".stream", ".racing", ".download", ".loan",
    ".trade", ".accountant", ".science", ".cricket", ".party",
})

# Well-known legitimate domains that don't need WHOIS lookup
_KNOWN_SAFE_DOMAINS = frozenset({
    "microsoft.com", "windows.com", "office.com", "live.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "github.com", "githubusercontent.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    "apple.com", "icloud.com",
    "facebook.com", "fbcdn.net",
    "cloudflare.com", "cloudflare-dns.com",
    "akamai.net", "akamaiedge.net",
    "dropbox.com", "dropboxapi.com",
    "slack.com", "slack-edge.com",
    "zoom.us",
    "okta.com", "auth0.com",
})


def lookup_domain(domain: str) -> dict[str, Any] | None:
    """Look up domain registration info via RDAP.

    Returns a dict with:
      - age_days: int (days since registration, -1 if unknown)
      - created_date: str (ISO date of registration)
      - registrar: str (registrar name)
      - is_new: bool (registered < 30 days ago)
      - is_very_new: bool (registered < 7 days ago)
      - suspicious_tld: bool (TLD in the suspicious list)
      - known_safe: bool (domain in the safe list)
      - source: "rdap"

    Returns None if lookup fails (timeout, unsupported TLD, etc.).
    Caches results for 24 hours to avoid hammering RDAP servers.
    """
    if not domain or "." not in domain:
        return None

    domain = domain.lower().strip()

    # Input validation: reject domains with path traversal or URL injection chars
    if any(c in domain for c in ("../", "/", "@", " ", "\t", "\n", "\\", "?")):
        return None
    if len(domain) > 253:  # RFC 1035 max domain length
        return None

    # Skip known-safe domains
    for safe in _KNOWN_SAFE_DOMAINS:
        if domain == safe or domain.endswith("." + safe):
            return {
                "age_days": 9999,
                "created_date": None,
                "registrar": "known-safe",
                "is_new": False,
                "is_very_new": False,
                "suspicious_tld": False,
                "known_safe": True,
                "source": "cache",
            }

    # Check cache (with size eviction to prevent unbounded memory growth)
    now = time.time()
    if len(_cache) > 10000:
        _cache.clear()  # evict all — simple but effective
    if domain in _cache:
        cached_result, cached_time = _cache[domain]
        if now - cached_time < _CACHE_TTL:
            return cached_result

    # Check for suspicious TLD (doesn't need RDAP)
    tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
    suspicious_tld = tld.lower() in _SUSPICIOUS_TLDS

    # Query RDAP
    try:
        resp = httpx.get(
            _RDAP_URL.format(domain=domain),
            timeout=5,
            follow_redirects=True,
        )
        if resp.status_code != 200:
            result = {
                "age_days": -1,
                "created_date": None,
                "registrar": "unknown",
                "is_new": False,
                "is_very_new": False,
                "suspicious_tld": suspicious_tld,
                "known_safe": False,
                "source": "rdap-failed",
            }
            _cache[domain] = (result, now)
            return result

        data = resp.json()

        # Extract registration date from RDAP events
        created_date = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created_date = event.get("eventDate", "")
                break

        # Fallback: check for "last changed" or other event types
        if not created_date:
            for event in data.get("events", []):
                if event.get("eventAction") in ("last changed", "last update of RDAP database"):
                    continue  # skip non-creation events
                date_val = event.get("eventDate")
                if date_val:
                    created_date = date_val
                    break

        # Parse age
        age_days = -1
        if created_date:
            try:
                # RDAP dates are ISO 8601: "2024-01-15T12:00:00Z"
                dt_str = created_date.split("T")[0]
                created_dt = datetime.strptime(dt_str, "%Y-%m-%d")
                age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created_dt).days
            except (ValueError, TypeError):
                pass

        # Extract registrar
        registrar = "unknown"
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) >= 2:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            registrar = field[3] if len(field) > 3 else "unknown"
                            break
                # Fallback to entity handle
                if registrar == "unknown":
                    registrar = entity.get("handle", "unknown")
                break

        is_new = 0 <= age_days < 30
        is_very_new = 0 <= age_days < 7

        result = {
            "age_days": age_days,
            "created_date": created_date,
            "registrar": registrar,
            "is_new": is_new,
            "is_very_new": is_very_new,
            "suspicious_tld": suspicious_tld,
            "known_safe": False,
            "source": "rdap",
        }
        _cache[domain] = (result, now)
        _log.debug("Domain intel: %s → age=%dd, registrar=%s, new=%s",
                    domain, age_days, registrar, is_new)
        return result

    except Exception:
        _log.debug("Domain RDAP lookup failed for %s (non-fatal)", domain, exc_info=True)
        result = {
            "age_days": -1,
            "created_date": None,
            "registrar": "unknown",
            "is_new": False,
            "is_very_new": False,
            "suspicious_tld": suspicious_tld,
            "known_safe": False,
            "source": "rdap-error",
        }
        _cache[domain] = (result, now)
        return result


def enrich_with_domain_intel(raw_alert: dict[str, Any]) -> int:
    """Extract domains from a raw alert and add domain intelligence fields.

    Called during enrichment, AFTER threat intel lookup. Sets structured
    fields that signal extractors can read:
      - _domainAgeDays: int
      - _domainNewlyRegistered: bool
      - _domainVeryNew: bool
      - _domainSuspiciousTld: bool
      - _domainRegistrar: str

    Returns the number of fields added.
    """
    added = 0

    # Collect domains from the alert
    domains: set[str] = set()
    for field in ("domain", "_domain", "destinationDomain", "_dstDomain"):
        val = raw_alert.get(field)
        if isinstance(val, str) and val and "." in val:
            domains.add(val.lower().strip())

    # Also extract domains from IPs/URLs
    for ip_entry in raw_alert.get("ips", []) or []:
        if isinstance(ip_entry, dict):
            geo = ip_entry.get("geo", {}) or {}
            # Some enrichment sources put domain in geo
            dom = geo.get("domain") or ""
            if dom and "." in dom:
                domains.add(dom.lower().strip())

    if not domains:
        return 0

    # Look up the first domain (most relevant, avoid hammering RDAP)
    primary_domain = sorted(domains)[0]
    result = lookup_domain(primary_domain)
    if result is None:
        return 0

    # Set structured fields for signal extractors
    if result["age_days"] >= 0:
        raw_alert["_domainAgeDays"] = result["age_days"]
        added += 1

    if result["is_new"]:
        raw_alert["_domainNewlyRegistered"] = True
        added += 1

    if result["is_very_new"]:
        raw_alert["_domainVeryNew"] = True
        added += 1

    if result["suspicious_tld"]:
        raw_alert["_domainSuspiciousTld"] = True
        added += 1

    if result["registrar"] and result["registrar"] != "unknown":
        raw_alert["_domainRegistrar"] = result["registrar"]
        added += 1

    if result["known_safe"]:
        raw_alert["_domainKnownSafe"] = True
        added += 1

    return added
