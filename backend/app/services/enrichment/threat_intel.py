"""Pluggable threat intelligence enrichment for the Vigilis engine.

WHY THIS EXISTS: Vigilis can't answer "Is this IP known malicious?" or "Was
this domain registered yesterday?" without threat intel. This module provides
a pluggable interface: default is static lists (ships with curated known-bad
IPs, TOR exit nodes, suspicious domain patterns), but customers can swap in
VirusTotal, AbuseIPDB, GreyNoise, or any provider that implements the protocol.

ARCHITECTURE:
  - ThreatIntelProvider: Python Protocol defining check_ip/check_domain/check_hash
  - StaticListProvider: Default provider with curated threat data
  - ThreatIntelEnricher: Orchestrates providers, merges results, generates Signal objects
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

from backend.app.services.enrichment.base import Signal, _is_private_ip
from backend.app.services.enrichment.cache import (
    DOMAIN_TTL,
    HASH_TTL,
    IP_TTL,
    get_cache,
)
from backend.app.services.enrichment.weights import get_weight


@dataclass
class ThreatIntelResult:
    is_malicious: bool
    confidence: float  # 0.0 - 1.0
    source: str
    tags: list[str] = field(default_factory=list)
    details: str = ""
    adversaries: list[str] = field(default_factory=list)
    campaign_names: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@runtime_checkable
class ThreatIntelProvider(Protocol):
    def check_ip(self, ip: str) -> ThreatIntelResult | None: ...
    def check_domain(self, domain: str) -> ThreatIntelResult | None: ...
    def check_hash(self, file_hash: str) -> ThreatIntelResult | None: ...


# ── Static List Provider (default) ───────────────────────────────────

_KNOWN_MALICIOUS_RANGES = [
    ipaddress.ip_network("185.220.100.0/23"),
    ipaddress.ip_network("185.220.101.0/24"),
    ipaddress.ip_network("23.129.64.0/24"),
    ipaddress.ip_network("91.219.236.0/24"),
    ipaddress.ip_network("185.100.87.0/24"),
]

_TOR_EXIT_RANGES = [
    ipaddress.ip_network("185.220.100.0/22"),   # Tor relay authority (covers .100-.103)
    ipaddress.ip_network("162.247.74.0/24"),
    ipaddress.ip_network("104.244.76.0/24"),
    ipaddress.ip_network("199.249.230.0/24"),
    ipaddress.ip_network("23.129.64.0/24"),
    ipaddress.ip_network("51.75.144.0/24"),
    ipaddress.ip_network("185.56.80.0/24"),
    ipaddress.ip_network("209.141.58.0/24"),
    ipaddress.ip_network("178.20.55.0/24"),
    ipaddress.ip_network("45.33.32.0/24"),      # Tor directory authority
    ipaddress.ip_network("171.25.193.0/24"),     # Tor exit relay
]

_KNOWN_MALICIOUS_DOMAINS: set[str] = {
    "evil-phishing.com",
    "malware-download.xyz",
    "credential-steal.tk",
    "c2-server.ml",
    "data-exfil.ga",
}

_SUSPICIOUS_TLD_PATTERNS = [
    re.compile(r".*\.(tk|ml|ga|cf|gq|xyz|top|buzz|club|work|click|loan|download)$", re.IGNORECASE),
    re.compile(r"^[a-z0-9]{30,}\.", re.IGNORECASE),
    re.compile(r".*\d{4,}.*\.(com|net|org)$"),
]

_KNOWN_MALICIOUS_HASHES: set[str] = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
}


def _ip_in_ranges(ip_str: str, ranges: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in ranges)


_KNOWN_BENIGN_IPS: dict[str, str] = {
    # Public DNS
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS", "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    # Microsoft infrastructure
    "13.107.4.50": "Microsoft", "204.79.197.200": "Microsoft",
    # Common CDNs (not exhaustive — ip-api.com handles the rest)
    "151.101.1.69": "Fastly CDN", "104.16.0.1": "Cloudflare CDN",
}


class StaticListProvider:
    """Ships with curated known-bad IPs, TOR exit nodes, domain lists, and hash lists."""

    def check_ip(self, ip: str) -> ThreatIntelResult | None:
        if _ip_in_ranges(ip, _TOR_EXIT_RANGES):
            return ThreatIntelResult(
                is_malicious=True, confidence=0.95,
                source="static_tor_list", tags=["tor_exit_node"],
                details=f"IP {ip} is a known TOR exit node",
            )
        if _ip_in_ranges(ip, _KNOWN_MALICIOUS_RANGES):
            return ThreatIntelResult(
                is_malicious=True, confidence=0.9,
                source="static_threat_list", tags=["known_malicious_ip"],
                details=f"IP {ip} is in known malicious infrastructure",
            )
        # Known benign IPs — noise reduction
        if ip in _KNOWN_BENIGN_IPS:
            service = _KNOWN_BENIGN_IPS[ip]
            return ThreatIntelResult(
                is_malicious=False, confidence=0.95,
                source="static_benign_list", tags=["known_benign_service"],
                details=f"IP {ip} is {service} — known legitimate infrastructure",
            )
        return None

    def check_domain(self, domain: str) -> ThreatIntelResult | None:
        domain_lower = domain.lower().strip()
        if domain_lower in _KNOWN_MALICIOUS_DOMAINS:
            return ThreatIntelResult(
                is_malicious=True, confidence=0.9,
                source="static_domain_list", tags=["known_malicious_domain"],
                details=f"Domain {domain} is in the known malicious domain list",
            )
        for pattern in _SUSPICIOUS_TLD_PATTERNS:
            if pattern.match(domain_lower):
                return ThreatIntelResult(
                    is_malicious=True, confidence=0.7,
                    source="static_domain_heuristic", tags=["suspicious_domain"],
                    details=f"Domain {domain} matches suspicious TLD pattern",
                )
        return None

    def check_hash(self, file_hash: str) -> ThreatIntelResult | None:
        normalized = file_hash.lower().strip()
        if normalized in _KNOWN_MALICIOUS_HASHES:
            return ThreatIntelResult(
                is_malicious=True, confidence=0.85,
                source="static_hash_list", tags=["known_bad_hash"],
                details=f"Hash {normalized[:16]}... is in the known malicious hash list",
            )
        return None


# ── Dynamic weight scaling from API confidence ──────────────────────


def _dynamic_weight(signal_name: str, confidence: float) -> int:
    """Scale signal weight by API confidence. Floor at 50% so even low-confidence hits contribute."""
    base = get_weight(signal_name) or 15
    scale = max(confidence, 0.5)
    return max(1, int(base * scale))


# ── Signal mapping from threat intel tags to enrichment signals ──────

_TAG_TO_SIGNAL: dict[str, str] = {
    "known_malicious_ip": "known_malicious_ip",
    "tor_exit_node": "tor_exit_node",
    "suspicious_domain": "recently_registered_domain",
    "known_malicious_domain": "known_malicious_domain",
    "known_bad_hash": "known_bad_hash",
    # VirusTotal tags
    "vt_malicious_ip": "known_malicious_ip",
    "vt_malicious_domain": "known_malicious_domain",
    "vt_malicious_hash": "known_bad_hash",
    "vt_suspicious_ip": "anomalous_ip",
    "vt_suspicious_domain": "anomalous_ip",
    "vt_suspicious_hash": "anomalous_ip",
    "vt_bad_reputation": "source_high_risk",
    # AbuseIPDB tags
    "abuseipdb_malicious": "known_malicious_ip",
    "abuseipdb_suspicious": "anomalous_ip",
    "abuseipdb_tor": "tor_exit_node",
    "abuseipdb_datacenter": "server_execution",       # Datacenter IP = hosting infra
    "abuseipdb_vpn_proxy": "known_proxy_vpn",         # VPN/proxy flag
    # OTX (AlienVault) tags
    "otx_c2_ip": "known_malicious_ip",
    "otx_c2_domain": "known_malicious_domain",
    "otx_apt_ip": "known_malicious_ip",
    "otx_apt_domain": "known_malicious_domain",
    "otx_malware_ip": "known_malicious_ip",
    "otx_malware_domain": "known_malicious_domain",
    "otx_malware_hash": "known_bad_hash",
    "otx_phishing_ip": "anomalous_ip",
    "otx_phishing_domain": "anomalous_ip",
    "otx_suspicious_ip": "anomalous_ip",
    "otx_suspicious_domain": "anomalous_ip",
    "otx_suspicious_hash": "anomalous_ip",
    # GreyNoise tags
    "greynoise_malicious": "known_malicious_ip",
    "greynoise_benign": "service_account_noise",     # Benign = NOISE REDUCTION
    "greynoise_scanner": "service_account_noise",     # Known scanner = noise
    # Known benign tags (noise reduction)
    "known_benign_service": "service_account_noise",
    # Local threat intel DB tags (from abuse.ch feeds)
    "localdb_feodo_tracker": "known_malicious_ip",
    "localdb_urlhaus": "known_malicious_domain",
    "localdb_threatfox": "known_malicious_ip",
    "localdb_malwarebazaar": "known_bad_hash",        # Phase 4.1
    "localdb_urlhaus_hashes": "known_bad_hash",        # Phase 4.1
    # WHOIS/RDAP tags
    "domain_age_critical": "recently_registered_domain",   # < 7 days old
    "domain_age_suspicious": "recently_registered_domain", # < 30 days old
    "domain_age_young": "new_domain",                      # < 90 days old
}


# ── Enricher (orchestrates providers) ────────────────────────────────

def _extract_ips(raw_alert: dict[str, Any]) -> list[str]:
    ips = []
    # Check structured IP arrays
    for ip_obj in raw_alert.get("ips") or raw_alert.get("ipAddresses") or []:
        if isinstance(ip_obj, dict):
            addr = ip_obj.get("ipAddress", "")
            if addr and not _is_private_ip(addr):
                ips.append(addr)
        elif isinstance(ip_obj, str) and not _is_private_ip(ip_obj):
            ips.append(ip_obj)
    # Fallback: check flat IP fields common in raw alerts
    for field in ("ip", "src_ip", "source_ip", "dest_ip", "destination_ip", "remote_ip",
                  "srcip", "dstip", "client_ip", "attacker_ip"):
        val = raw_alert.get(field, "")
        if isinstance(val, str) and val and not _is_private_ip(val) and val not in ips:
            ips.append(val)
    # Check nested principal.ip
    principal = raw_alert.get("principal", {})
    if isinstance(principal, dict):
        p_ip = principal.get("ip", "")
        if isinstance(p_ip, str) and p_ip and not _is_private_ip(p_ip) and p_ip not in ips:
            ips.append(p_ip)
    # Extract destination IPs (important for insider exfil cases)
    for field in ("dst_ip", "destination_ip", "dest_ip", "remote_ip"):
        val = raw_alert.get(field, "")
        if isinstance(val, str) and val and not _is_private_ip(val) and val not in ips:
            ips.append(val)
    # Check nested additional.dst_ip
    additional = raw_alert.get("additional", {})
    if isinstance(additional, dict):
        for field in ("dst_ip", "destination_ip", "dest_ip"):
            val = additional.get(field, "")
            if isinstance(val, str) and val and not _is_private_ip(val) and val not in ips:
                ips.append(val)
    return list(dict.fromkeys(ips))


def _extract_domains(raw_alert: dict[str, Any]) -> list[str]:
    domains = []
    ctx = raw_alert.get("_additionalContext") or ""
    alert_name = raw_alert.get("_sourceAlertName") or ""
    combined = f"{ctx} {alert_name}"

    for ip_obj in raw_alert.get("ips") or raw_alert.get("ipAddresses") or []:
        if isinstance(ip_obj, dict):
            domain = ip_obj.get("domain") or ip_obj.get("hostname") or ""
            if domain and "." in domain:
                domains.append(domain.lower())

    domain_pattern = re.compile(r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z]{2,})+)")
    for match in domain_pattern.finditer(combined):
        d = match.group(1).lower()
        if d not in domains:
            domains.append(d)

    mailbox = raw_alert.get("mailbox") or {}
    fwd = mailbox.get("forwardingAddress") or ""
    if "@" in fwd:
        domain_part = fwd.split("@")[1]
        if domain_part and domain_part not in domains:
            domains.append(domain_part)

    # Extract sender domain from email fields (BEC/phishing alerts)
    for _email_field in ("sender", "_mailFrom", "mailfrom", "mail_from", "from"):
        _sender = raw_alert.get(_email_field) or ""
        if "@" in _sender:
            _sender_domain = _sender.split("@")[1].lower()
            if _sender_domain and _sender_domain not in domains:
                domains.append(_sender_domain)

    # Also check description for domain-like patterns
    desc = raw_alert.get("description") or raw_alert.get("_description") or ""
    if desc:
        for match in domain_pattern.finditer(desc):
            d = match.group(1).lower()
            if d not in domains:
                domains.append(d)

    return domains


def _extract_hashes(raw_alert: dict[str, Any]) -> list[str]:
    hashes = []
    file_data = raw_alert.get("file") or {}
    for key in ("sha256", "sha1", "md5"):
        val = file_data.get(key) or ""
        if val:
            hashes.append(val.lower())
    return hashes


class ThreatIntelEnricher:
    """Runs all providers against a raw alert and produces Signal objects."""

    def __init__(self, providers: list[Any] | None = None):
        self._providers: list[Any] = providers or [StaticListProvider()]
        self._last_ti_notes: list[str] = []
        self._provider_status: dict[str, dict] = {
            type(p).__name__: {
                "name": type(p).__name__,
                "status": "unknown",
                "last_check": None,
                "error": None,
            }
            for p in self._providers
        }

    @property
    def last_ti_notes(self) -> list[str]:
        """Extra enrichment notes from the last enrich() call (adversaries, campaigns, refs)."""
        return self._last_ti_notes

    def _mark_provider_ok(self, provider_name: str) -> None:
        self._provider_status[provider_name] = {
            "name": provider_name,
            "status": "ok",
            "last_check": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }

    def _mark_provider_error(self, provider_name: str, error: str) -> None:
        self._provider_status[provider_name] = {
            "name": provider_name,
            "status": "error",
            "last_check": datetime.now(timezone.utc).isoformat(),
            "error": error,
        }

    def get_provider_health(self) -> dict[str, dict]:
        """Return a copy of provider health status."""
        import copy
        return copy.deepcopy(self._provider_status)

    def enrich(self, raw_alert: dict[str, Any]) -> list[Signal]:
        signals: list[Signal] = []
        seen: set[str] = set()
        ti_notes: list[str] = []
        all_adversaries: set[str] = set()
        all_campaigns: set[str] = set()
        all_references: list[str] = []

        cache = get_cache()

        for ip in _extract_ips(raw_alert):
            for provider in self._providers:
                provider_name = type(provider).__name__
                found, cached_result = cache.get(provider_name, "ip", ip)
                if found:
                    result = cached_result
                else:
                    try:
                        result = provider.check_ip(ip)
                        cache.put(provider_name, "ip", ip, result, IP_TTL)
                        self._mark_provider_ok(provider_name)
                    except Exception as exc:
                        self._mark_provider_error(provider_name, str(exc))
                        result = None
                if result and result.is_malicious:
                    all_adversaries.update(getattr(result, "adversaries", []) or [])
                    all_campaigns.update(getattr(result, "campaign_names", []) or [])
                    for ref in getattr(result, "references", []) or []:
                        if ref not in all_references:
                            all_references.append(ref)
                    for tag in result.tags:
                        signal_name = _TAG_TO_SIGNAL.get(tag, tag)
                        if signal_name not in seen:
                            seen.add(signal_name)
                            conf_pct = int(result.confidence * 100)
                            label = f"{result.source}: {result.details} ({conf_pct}% confidence)" if result.details else f"Threat intel: {tag} ({ip}, {conf_pct}% confidence)"
                            signals.append(Signal(
                                name=signal_name,
                                weight=_dynamic_weight(signal_name, result.confidence),
                                fired=True,
                                label=label,
                            ))

        for domain in _extract_domains(raw_alert):
            for provider in self._providers:
                provider_name = type(provider).__name__
                found, cached_result = cache.get(provider_name, "domain", domain)
                if found:
                    result = cached_result
                else:
                    try:
                        result = provider.check_domain(domain)
                        cache.put(provider_name, "domain", domain, result, DOMAIN_TTL)
                        self._mark_provider_ok(provider_name)
                    except Exception as exc:
                        self._mark_provider_error(provider_name, str(exc))
                        result = None
                if result and result.is_malicious:
                    all_adversaries.update(getattr(result, "adversaries", []) or [])
                    all_campaigns.update(getattr(result, "campaign_names", []) or [])
                    for ref in getattr(result, "references", []) or []:
                        if ref not in all_references:
                            all_references.append(ref)
                    for tag in result.tags:
                        signal_name = _TAG_TO_SIGNAL.get(tag, tag)
                        if signal_name not in seen:
                            seen.add(signal_name)
                            conf_pct = int(result.confidence * 100)
                            label = f"{result.source}: {result.details} ({conf_pct}% confidence)" if result.details else f"Threat intel: {tag} ({domain}, {conf_pct}% confidence)"
                            signals.append(Signal(
                                name=signal_name,
                                weight=_dynamic_weight(signal_name, result.confidence),
                                fired=True,
                                label=label,
                            ))

        # DNS resolution check for extracted domains
        # If domain doesn't resolve, it's suspicious (may be disposable phishing infra)
        for domain in _extract_domains(raw_alert):
            try:
                import socket
                socket.getaddrinfo(domain, 80, socket.AF_INET)
            except socket.gaierror:
                # Domain doesn't resolve — suspicious for sender domains
                if "unresolvable_domain" not in seen:
                    seen.add("unresolvable_domain")
                    signals.append(Signal(
                        name="unresolvable_domain",
                        weight=15,
                        fired=True,
                        label=f"Domain {domain} does not resolve in DNS — possible disposable phishing infrastructure",
                    ))
            except Exception:
                pass

        for file_hash in _extract_hashes(raw_alert):
            for provider in self._providers:
                provider_name = type(provider).__name__
                found, cached_result = cache.get(provider_name, "hash", file_hash)
                if found:
                    result = cached_result
                else:
                    try:
                        result = provider.check_hash(file_hash)
                        cache.put(provider_name, "hash", file_hash, result, HASH_TTL)
                        self._mark_provider_ok(provider_name)
                    except Exception as exc:
                        self._mark_provider_error(provider_name, str(exc))
                        result = None
                if result and result.is_malicious:
                    all_adversaries.update(getattr(result, "adversaries", []) or [])
                    all_campaigns.update(getattr(result, "campaign_names", []) or [])
                    for ref in getattr(result, "references", []) or []:
                        if ref not in all_references:
                            all_references.append(ref)
                    for tag in result.tags:
                        signal_name = _TAG_TO_SIGNAL.get(tag, tag)
                        if signal_name not in seen:
                            seen.add(signal_name)
                            conf_pct = int(result.confidence * 100)
                            label = f"{result.source}: {result.details} ({conf_pct}% confidence)" if result.details else f"Threat intel: {tag} ({file_hash[:16]}..., {conf_pct}% confidence)"
                            signals.append(Signal(
                                name=signal_name,
                                weight=_dynamic_weight(signal_name, result.confidence),
                                fired=True,
                                label=label,
                            ))

        # Build structured TI notes for enrichment output
        if all_adversaries:
            ti_notes.append(f"Threat actors: {', '.join(sorted(all_adversaries)[:5])}")
        if all_campaigns:
            ti_notes.append(f"Campaigns: {', '.join(list(all_campaigns)[:5])}")
        if all_references:
            ti_notes.append(f"Threat reports: {'; '.join(all_references[:5])}")
        self._last_ti_notes = ti_notes

        return signals


# Module-level singleton
_enricher = ThreatIntelEnricher()


def get_threat_intel_enricher() -> ThreatIntelEnricher:
    return _enricher


def set_threat_intel_providers(providers: list[Any]) -> ThreatIntelEnricher:
    """Replace the global enricher's providers (for customer configuration)."""
    global _enricher
    _enricher = ThreatIntelEnricher(providers)
    return _enricher


def reset_threat_intel() -> ThreatIntelEnricher:
    """Reset to default providers (used in tests)."""
    global _enricher
    _enricher = ThreatIntelEnricher()
    return _enricher


def get_provider_health() -> dict:
    """Get health status of all registered threat intel providers."""
    return _enricher.get_provider_health()
