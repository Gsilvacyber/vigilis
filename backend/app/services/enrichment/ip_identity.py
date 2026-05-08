"""ip-api.com identity lookup — cache-first single lookup plus batch pre-fetch.

WHY THIS EXISTS:
  Before this module, the per-alert enrichment path made a synchronous
  ``httpx.get`` to ``ip-api.com/json/<ip>`` for every external IP in every
  alert, bypassing the project's ``ThreatIntelCache``. With N alerts × ~1s
  per round-trip, uploads got slow fast.

This module gives the rest of the codebase two operations:

  * :func:`lookup_ip_identity` — cache-first single lookup. Used by the
    per-alert enrichment path.
  * :func:`batch_prefetch_identities` — collect all unique external IPs
    in an upload up front, hit ip-api's ``POST /batch`` endpoint once,
    and populate the cache. Subsequent per-alert calls become cache hits.

Both functions degrade gracefully — any HTTP / parsing / network failure
is logged at debug level and returns ``None`` (or 0 fetched). The caller
behaves the same as if ip-api were unreachable, which is the same baseline
behaviour the engine had before this module existed.
"""
from __future__ import annotations

import logging
from typing import Any, Iterable

import httpx

from backend.app.services.enrichment.cache import IP_TTL, get_cache

_log = logging.getLogger(__name__)

_PROVIDER = "IPApiIdentity"
_FIELDS = "status,org,isp,as,reverse,hosting,proxy"
_BATCH_URL = "http://ip-api.com/batch"
_SINGLE_URL_TPL = "http://ip-api.com/json/{ip}?fields=" + _FIELDS
_TIMEOUT = 5  # seconds, single lookup
_BATCH_TIMEOUT = 10  # seconds, batch lookup (server has more work to do)
_BATCH_MAX = 100  # ip-api hard limit per request


def lookup_ip_identity(ip: str) -> dict[str, Any] | None:
    """Cache-first ip-api.com identity lookup.

    Returns the parsed ip-api response dict (``{"org": ..., "isp": ...,
    "proxy": bool, ...}``) on success, or ``None`` for unknown / failed
    lookups. Both outcomes are cached so we don't hammer the API.
    """
    if not ip:
        return None
    cache = get_cache()
    found, cached = cache.get(_PROVIDER, "ip", ip)
    if found:
        return cached

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            resp = client.get(_SINGLE_URL_TPL.format(ip=ip))
        if resp.status_code != 200:
            cache.put(_PROVIDER, "ip", ip, None, IP_TTL)  # negative cache
            return None
        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "success":
            cache.put(_PROVIDER, "ip", ip, None, IP_TTL)
            return None
        cache.put(_PROVIDER, "ip", ip, data, IP_TTL)
        return data
    except Exception:
        _log.debug("ip-api single lookup failed for %s", ip, exc_info=True)
        return None


def batch_prefetch_identities(ips: Iterable[str]) -> int:
    """Batch-fetch identities for many IPs, populating the cache.

    Skips IPs already in cache. Splits the request into chunks of at most
    100 (ip-api's documented batch limit). Caches both successes (full
    response dict) and failures (``None``) so per-alert lookups become
    O(1) cache hits.

    Returns the number of IPs for which a successful response was cached.
    Network / HTTP failures are non-fatal — the function returns whatever
    succeeded so far and the per-alert path will fall back to single
    lookups (which themselves cache results).
    """
    cache = get_cache()
    to_fetch: list[str] = []
    for ip in dict.fromkeys(ips):  # de-dupe preserving order
        if not ip:
            continue
        found, _ = cache.get(_PROVIDER, "ip", ip)
        if not found:
            to_fetch.append(ip)
    if not to_fetch:
        return 0

    fetched = 0
    for chunk_start in range(0, len(to_fetch), _BATCH_MAX):
        chunk = to_fetch[chunk_start:chunk_start + _BATCH_MAX]
        try:
            with httpx.Client(timeout=_BATCH_TIMEOUT) as client:
                resp = client.post(
                    f"{_BATCH_URL}?fields={_FIELDS}",
                    json=chunk,
                )
            if resp.status_code != 200:
                _log.debug("ip-api batch returned HTTP %d", resp.status_code)
                continue
            results = resp.json()
            if not isinstance(results, list):
                _log.debug("ip-api batch returned non-list payload")
                continue
            for ip, result in zip(chunk, results):
                if isinstance(result, dict) and result.get("status") == "success":
                    cache.put(_PROVIDER, "ip", ip, result, IP_TTL)
                    fetched += 1
                else:
                    cache.put(_PROVIDER, "ip", ip, None, IP_TTL)
        except Exception:
            _log.debug("ip-api batch chunk failed", exc_info=True)
    return fetched
