"""AlienVault OTX (Open Threat Exchange) threat intelligence provider.

Free, commercial-use allowed. Provides community-sourced threat data
including pulse reports, reputation scoring, and indicator context.

Sign up: https://otx.alienvault.com
"""
import logging
from typing import Any, Optional

import httpx

from backend.app.services.enrichment.threat_intel import ThreatIntelResult

_log = logging.getLogger(__name__)


class OTXProvider:
    """AlienVault OTX threat intelligence provider."""

    def __init__(self, api_key: str):
        self._client = httpx.Client(
            base_url="https://otx.alienvault.com",
            headers={"X-OTX-API-KEY": api_key},
            timeout=10.0,
        )

    def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        return self._check(f"/api/v1/indicators/IPv4/{ip}/general", ip, "ip")

    def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        return self._check(f"/api/v1/indicators/domain/{domain}/general", domain, "domain")

    def check_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        return self._check(f"/api/v1/indicators/file/{file_hash}/general", file_hash, "hash")

    def _check(self, path: str, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        try:
            resp = self._client.get(path)
            if resp.status_code == 404:
                return None
            if resp.status_code == 429:
                _log.warning("OTX rate limited for %s", indicator)
                return None
            resp.raise_for_status()
            data = resp.json()
            return self._parse(data, indicator, indicator_type)
        except httpx.HTTPError as e:
            _log.warning("OTX API error for %s: %s", indicator, e)
            return None

    def _parse(self, data: dict[str, Any], indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])
        reputation = data.get("reputation", 0)
        validation = data.get("validation", [])
        country = data.get("country_code", "")

        # No pulses and clean reputation = not malicious
        if pulse_count == 0 and (reputation is None or reputation >= 0) and not validation:
            return None

        # Build tags from pulse data
        tags: set[str] = set()
        adversaries: set[str] = set()
        campaign_names: list[str] = []
        references: set[str] = set()
        mitre_ids: set[str] = set()
        for pulse in pulses[:10]:
            for tag in pulse.get("tags", []):
                tag_lower = tag.lower()
                if any(kw in tag_lower for kw in ["c2", "command", "control", "botnet"]):
                    tags.add(f"otx_c2_{indicator_type}")
                if any(kw in tag_lower for kw in ["apt", "threat", "actor"]):
                    tags.add(f"otx_apt_{indicator_type}")
                if any(kw in tag_lower for kw in ["malware", "trojan", "ransomware"]):
                    tags.add(f"otx_malware_{indicator_type}")
                if any(kw in tag_lower for kw in ["phishing", "spam"]):
                    tags.add(f"otx_phishing_{indicator_type}")
                if "tor" in tag_lower:
                    tags.add("tor_exit_node")
            adversary = pulse.get("adversary")
            if adversary:
                adversaries.add(adversary)

            # Extract campaign/pulse names
            pulse_name = pulse.get("name", "")
            if pulse_name and pulse_name not in campaign_names:
                campaign_names.append(pulse_name)

            # Extract references (URLs to threat reports)
            for ref in pulse.get("references", []) or []:
                if isinstance(ref, str) and ref.startswith("http"):
                    references.add(ref)

            # Extract MITRE ATT&CK technique IDs from attack_ids
            for attack_id in pulse.get("attack_ids", []) or []:
                if isinstance(attack_id, dict):
                    tid = attack_id.get("id", "")
                    if tid:
                        mitre_ids.add(tid)
                elif isinstance(attack_id, str):
                    mitre_ids.add(attack_id)

        if pulse_count > 0 and not tags:
            tags.add(f"otx_suspicious_{indicator_type}")

        if validation:
            tags.add(f"otx_malware_{indicator_type}")

        # Confidence based on pulse count
        if pulse_count >= 10:
            confidence = 0.9
            is_malicious = True
        elif pulse_count >= 5:
            confidence = 0.75
            is_malicious = True
        elif pulse_count >= 2:
            confidence = 0.5
            is_malicious = False
        else:
            confidence = 0.3
            is_malicious = False

        if reputation is not None and reputation < 0:
            is_malicious = True
            confidence = max(confidence, 0.8)

        # Build details
        details_parts = [f"OTX: {pulse_count} threat pulses reference {indicator_type} {indicator}"]
        if adversaries:
            details_parts.append(f"adversaries: {', '.join(list(adversaries)[:3])}")
        if campaign_names:
            details_parts.append(f"campaigns: {', '.join(campaign_names[:3])}")
        if mitre_ids:
            details_parts.append(f"MITRE: {', '.join(sorted(mitre_ids)[:5])}")
        if country:
            details_parts.append(f"country: {country}")
        if references:
            details_parts.append(f"refs: {len(references)}")

        return ThreatIntelResult(
            is_malicious=is_malicious,
            confidence=confidence,
            source="otx",
            tags=list(tags),
            details="; ".join(details_parts),
            adversaries=list(adversaries)[:5],
            campaign_names=campaign_names[:5],
            references=list(references)[:10],
        )
