"""Local Threat Intel Database Provider.

Queries the threat_intel_iocs Postgres table for IOC matches.
Zero API calls, zero rate limits, sub-millisecond lookups.

Fed by free public feeds (abuse.ch) via the feed_ingestion module.
"""
from __future__ import annotations

import logging
from typing import Optional

from backend.app.services.enrichment.threat_intel import ThreatIntelResult

_log = logging.getLogger(__name__)


class LocalDBProvider:
    """Queries local Postgres for threat intel IOCs."""

    def check_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        return self._lookup("ip", ip)

    def check_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        return self._lookup("domain", domain.lower().strip())

    def check_hash(self, file_hash: str) -> Optional[ThreatIntelResult]:
        return self._lookup("hash", file_hash.lower().strip())

    def _lookup(self, ioc_type: str, ioc_value: str) -> Optional[ThreatIntelResult]:
        if not ioc_value:
            return None
        try:
            from backend.app.core.db import get_session
            from backend.app.db.models import ThreatIntelIOC
            from sqlmodel import select

            with get_session() as session:
                ioc = session.exec(
                    select(ThreatIntelIOC).where(
                        ThreatIntelIOC.ioc_type == ioc_type,
                        ThreatIntelIOC.ioc_value == ioc_value,
                    )
                ).first()

                if ioc is None:
                    return None

                # Build tag from source name
                tag = f"localdb_{ioc.source}"

                # Build details string
                parts = [f"Local threat DB: {ioc_type} {ioc_value}"]
                if ioc.malware:
                    parts.append(f"malware: {ioc.malware}")
                if ioc.threat_type:
                    parts.append(f"type: {ioc.threat_type}")
                parts.append(f"source: {ioc.source}")

                return ThreatIntelResult(
                    is_malicious=True,
                    confidence=ioc.confidence,
                    source=f"local_feed:{ioc.source}",
                    tags=[tag],
                    details=", ".join(parts),
                )

        except Exception:
            _log.debug("Local DB lookup failed for %s:%s", ioc_type, ioc_value, exc_info=True)
            return None
