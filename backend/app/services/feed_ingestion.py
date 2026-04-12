"""Threat Intel Feed Ingestion — downloads free IOC feeds into Postgres.

Downloads curated threat feeds from abuse.ch on startup and every 24 hours.
All feeds are FREE and explicitly allow commercial use.

Feeds:
  - Feodo Tracker: Botnet C2 server IPs (~300 IPs)
  - URLhaus: Malicious URLs/domains (~1000 URLs)
  - ThreatFox: Mixed IOCs — IPs, domains, hashes (~2000 IOCs)
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import time
from datetime import datetime, timezone

import httpx

from backend.app.core.metrics import feed_age_seconds, feed_ingestion_total

_log = logging.getLogger(__name__)

# Track last successful fetch time per feed so `feed_age_seconds` can be
# computed on demand (the gauge is a snapshot — we poll it fresh each time).
_last_fetch: dict[str, float] = {}


def _mark_fetch_success(feed_name: str) -> None:
    _last_fetch[feed_name] = time.time()
    feed_ingestion_total.labels(feed=feed_name, status="success").inc()
    feed_age_seconds.labels(feed=feed_name).set(0)


def _mark_fetch_failure(feed_name: str) -> None:
    feed_ingestion_total.labels(feed=feed_name, status="failure").inc()


def update_feed_age_gauges() -> None:
    """Recompute feed age gauges from last-fetch timestamps.

    Called before returning from /metrics so the gauge reflects the
    current wall-clock age rather than stale values.
    """
    now = time.time()
    for feed_name, ts in _last_fetch.items():
        feed_age_seconds.labels(feed=feed_name).set(now - ts)

# Feed URLs (all abuse.ch — free, commercial-use allowed)
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
_URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
_THREATFOX_URL = "https://threatfox.abuse.ch/export/csv/recent/"
# Phase 4.1: MalwareBazaar recent SHA256 hash dump (CSV, plain text)
_MALWAREBAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
# Phase 4.1: URLhaus SHA256 hash feed (plain text, one hash per line)
_URLHAUS_HASHES_URL = "https://urlhaus.abuse.ch/downloads/sha256/"


async def update_feeds_loop(interval_hours: int = 24):
    """Background task: download IOC feeds on startup and every 24h."""
    _log.info("Feed ingestion task started (interval=%dh)", interval_hours)
    # Run immediately on startup
    _run_feed_update()
    while True:
        await asyncio.sleep(interval_hours * 3600)
        try:
            _run_feed_update()
        except Exception:
            _log.exception("Feed update failed")


def _run_feed_update():
    """Download all configured feeds and upsert into DB."""
    total = 0
    total += _download_feodo_tracker()
    total += _download_urlhaus()
    total += _download_threatfox()
    total += _download_malwarebazaar()     # Phase 4.1
    total += _download_urlhaus_hashes()    # Phase 4.1
    _log.info("Feed update complete: %d IOCs ingested", total)


def _upsert_ioc(session, ioc_type: str, ioc_value: str, source: str,
                threat_type: str = "", malware: str = "", confidence: float = 0.85):
    """Insert or update a single IOC in the database."""
    from backend.app.db.models import ThreatIntelIOC
    from sqlmodel import select

    existing = session.exec(
        select(ThreatIntelIOC).where(
            ThreatIntelIOC.ioc_type == ioc_type,
            ThreatIntelIOC.ioc_value == ioc_value,
            ThreatIntelIOC.source == source,
        )
    ).first()

    if existing:
        existing.last_seen = datetime.now(timezone.utc)
        existing.confidence = confidence
        if malware:
            existing.malware = malware
        session.add(existing)
    else:
        session.add(ThreatIntelIOC(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            source=source,
            threat_type=threat_type,
            malware=malware,
            confidence=confidence,
            details=f"{source}: {threat_type}" if threat_type else source,
        ))


def _download_feodo_tracker() -> int:
    """Download Feodo Tracker botnet C2 IP blocklist."""
    try:
        resp = httpx.get(_FEODO_URL, timeout=30, follow_redirects=True)
        if resp.status_code != 200:
            _log.warning("Feodo Tracker returned %d", resp.status_code)
            _mark_fetch_failure("feodo_tracker")
            return 0

        from backend.app.core.db import get_session

        count = 0
        with get_session() as session:
            reader = csv.reader(io.StringIO(resp.text))
            for row in reader:
                if not row or row[0].startswith("#") or row[0].startswith('"first'):
                    continue
                # Feodo CSV: first_seen, dst_ip, dst_port, c2_status, last_online, malware
                if len(row) < 2:
                    continue
                ip = row[1].strip().strip('"')
                malware = row[5].strip().strip('"') if len(row) > 5 else ""
                if ip and "." in ip and not ip[0].isalpha():
                    _upsert_ioc(session, "ip", ip, "feodo_tracker",
                                threat_type="botnet_cc", malware=malware,
                                confidence=0.90)
                    count += 1
            session.commit()

        _log.info("Feodo Tracker: %d botnet C2 IPs ingested", count)
        _mark_fetch_success("feodo_tracker")
        return count

    except Exception:
        _log.exception("Feodo Tracker download failed")
        _mark_fetch_failure("feodo_tracker")
        return 0


def _download_urlhaus() -> int:
    """Download URLhaus malicious URL list — extract domains."""
    try:
        resp = httpx.get(_URLHAUS_URL, timeout=30, follow_redirects=True)
        if resp.status_code != 200:
            _log.warning("URLhaus returned %d", resp.status_code)
            _mark_fetch_failure("urlhaus")
            return 0

        from backend.app.core.db import get_session
        from urllib.parse import urlparse

        count = 0
        with get_session() as session:
            reader = csv.reader(io.StringIO(resp.text))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                try:
                    # CSV: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                    if len(row) < 6:
                        continue
                    url = row[2].strip().strip('"')
                    threat = row[5].strip().strip('"') if len(row) > 5 else ""
                    tags = row[6].strip().strip('"') if len(row) > 6 else ""

                    # Extract domain from URL
                    parsed = urlparse(url)
                    domain = parsed.hostname
                    if domain and "." in domain:
                        malware_name = tags.split(",")[0].strip() if tags else ""
                        _upsert_ioc(session, "domain", domain, "urlhaus",
                                    threat_type=threat or "malware_distribution",
                                    malware=malware_name, confidence=0.85)
                        count += 1
                except (IndexError, ValueError):
                    continue

            session.commit()

        _log.info("URLhaus: %d malicious domains ingested", count)
        _mark_fetch_success("urlhaus")
        return count

    except Exception:
        _log.exception("URLhaus download failed")
        _mark_fetch_failure("urlhaus")
        return 0


def _download_threatfox() -> int:
    """Download ThreatFox IOC export — mixed IPs, domains, hashes."""
    try:
        resp = httpx.get(_THREATFOX_URL, timeout=30, follow_redirects=True)
        if resp.status_code != 200:
            _log.warning("ThreatFox returned %d", resp.status_code)
            _mark_fetch_failure("threatfox")
            return 0

        from backend.app.core.db import get_session

        count = 0
        with get_session() as session:
            reader = csv.reader(io.StringIO(resp.text))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                try:
                    # ThreatFox CSV: date, ioc_id, ioc_value, ioc_type, threat_type, malware, ...
                    if len(row) < 6:
                        continue

                    ioc_value = row[2].strip().strip('"')
                    ioc_type_raw = row[3].strip().strip('"').lower()
                    threat_type = row[4].strip().strip('"')
                    malware = row[5].strip().strip('"')
                    conf_raw = row[6].strip().strip('"') if len(row) > 6 else "75"

                    # Map ThreatFox ioc_type to our types
                    if "ip" in ioc_type_raw:
                        ioc_type = "ip"
                        # ThreatFox IPs may include port: "1.2.3.4:443"
                        ioc_value = ioc_value.split(":")[0]
                    elif "domain" in ioc_type_raw or "url" in ioc_type_raw:
                        ioc_type = "domain"
                        if "://" in ioc_value:
                            from urllib.parse import urlparse
                            ioc_value = urlparse(ioc_value).hostname or ioc_value
                    elif "hash" in ioc_type_raw or "sha256" in ioc_type_raw or "md5" in ioc_type_raw:
                        ioc_type = "hash"
                    else:
                        continue

                    if not ioc_value or len(ioc_value) < 3:
                        continue

                    # Parse confidence
                    try:
                        confidence = int(conf_raw) / 100 if conf_raw.isdigit() else 0.75
                    except (ValueError, TypeError):
                        confidence = 0.75

                    _upsert_ioc(session, ioc_type, ioc_value, "threatfox",
                                threat_type=threat_type, malware=malware,
                                confidence=min(confidence, 0.95))
                    count += 1

                except (IndexError, ValueError):
                    continue

            session.commit()

        _log.info("ThreatFox: %d IOCs ingested", count)
        _mark_fetch_success("threatfox")
        return count

    except Exception:
        _log.exception("ThreatFox download failed")
        _mark_fetch_failure("threatfox")
        return 0


def _download_malwarebazaar() -> int:
    """Phase 4.1: MalwareBazaar recent SHA256 malware hashes.

    MalwareBazaar exports a daily CSV of recently-submitted malware samples
    with SHA256 hashes, signatures, and tags. Commercial use is explicitly
    allowed on the abuse.ch free feeds. ~thousands of hashes per run.
    """
    try:
        resp = httpx.get(_MALWAREBAZAAR_URL, timeout=60, follow_redirects=True)
        if resp.status_code != 200:
            _log.warning("MalwareBazaar returned %d", resp.status_code)
            _mark_fetch_failure("malwarebazaar")
            return 0

        from backend.app.core.db import get_session

        count = 0
        with get_session() as session:
            reader = csv.reader(io.StringIO(resp.text))
            for row in reader:
                if not row or row[0].startswith("#") or row[0].startswith('"first'):
                    continue
                # MalwareBazaar CSV columns:
                # first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,
                # file_name, file_type_guess, mime_type, signature, clamav, ...
                try:
                    if len(row) < 9:
                        continue
                    sha256 = row[1].strip().strip('"').lower()
                    signature = row[8].strip().strip('"') if len(row) > 8 else ""
                    file_type = row[6].strip().strip('"') if len(row) > 6 else ""
                    # Validate SHA256 (64 hex chars)
                    if len(sha256) == 64 and all(c in "0123456789abcdef" for c in sha256):
                        _upsert_ioc(
                            session, "hash", sha256, "malwarebazaar",
                            threat_type=file_type or "malware",
                            malware=signature,
                            confidence=0.90,
                        )
                        count += 1
                except (IndexError, ValueError):
                    continue
                # Respect MaxEventsPerRun cap — MalwareBazaar feed is large
                if count >= 5000:
                    break
            session.commit()

        _log.info("MalwareBazaar: %d malware hashes ingested", count)
        _mark_fetch_success("malwarebazaar")
        return count

    except Exception:
        _log.exception("MalwareBazaar download failed")
        _mark_fetch_failure("malwarebazaar")
        return 0


def _download_urlhaus_hashes() -> int:
    """Phase 4.1: URLhaus SHA256 hashes of hosted malware.

    URLhaus publishes a plain-text list of SHA256 hashes of payloads hosted
    on its tracked URLs. Complements MalwareBazaar with different sampling.
    Format: one SHA256 per line, comments start with '#'.
    """
    try:
        resp = httpx.get(_URLHAUS_HASHES_URL, timeout=60, follow_redirects=True)
        if resp.status_code != 200:
            _log.warning("URLhaus hashes returned %d", resp.status_code)
            _mark_fetch_failure("urlhaus_hashes")
            return 0

        from backend.app.core.db import get_session

        count = 0
        with get_session() as session:
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                sha = line.lower()
                if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
                    _upsert_ioc(
                        session, "hash", sha, "urlhaus_hashes",
                        threat_type="malware_distribution",
                        confidence=0.85,
                    )
                    count += 1
                if count >= 5000:
                    break
            session.commit()

        _log.info("URLhaus hashes: %d malware hashes ingested", count)
        _mark_fetch_success("urlhaus_hashes")
        return count

    except Exception:
        _log.exception("URLhaus hashes download failed")
        _mark_fetch_failure("urlhaus_hashes")
        return 0


def get_feed_stats() -> dict:
    """Return IOC counts per source for health/status endpoints."""
    try:
        from backend.app.core.db import get_session
        from backend.app.db.models import ThreatIntelIOC
        from sqlmodel import select, func

        with get_session() as session:
            sources = session.exec(
                select(ThreatIntelIOC.source, func.count(ThreatIntelIOC.id))
                .group_by(ThreatIntelIOC.source)
            ).all()
            return {source: count for source, count in sources}
    except Exception:
        return {}
