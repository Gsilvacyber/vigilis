"""Regression tests for ip_identity (cache-first single lookup + batch).

Pins:
- A single lookup makes at most one HTTP call per IP, with subsequent
  lookups served from cache.
- Failed/unsuccessful lookups are negatively cached (no retry storm).
- batch_prefetch_identities POSTs to /batch, populates the cache for
  every successful entry, and degrades gracefully on transport failure.
- After a batch prefetch, lookup_ip_identity for the same IP issues no
  HTTP call.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from backend.app.services.enrichment import ip_identity
from backend.app.services.enrichment.cache import get_cache


# ─── Fixtures ─────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_cache():
    """Clear the ThreatIntelCache singleton between tests."""
    cache = get_cache()
    cache._store.clear()
    cache.hits = 0
    cache.misses = 0
    yield
    cache._store.clear()


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeClient:
    """Drop-in for httpx.Client that records calls made through it."""

    def __init__(self, *, get_responses: list[_FakeResponse] | None = None,
                 post_responses: list[_FakeResponse] | None = None,
                 raise_on_get: Exception | None = None,
                 raise_on_post: Exception | None = None):
        self._get_responses = list(get_responses or [])
        self._post_responses = list(post_responses or [])
        self._raise_on_get = raise_on_get
        self._raise_on_post = raise_on_post
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, Any]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, url: str, **_kwargs):
        self.get_calls.append(url)
        if self._raise_on_get:
            raise self._raise_on_get
        if not self._get_responses:
            raise AssertionError(f"unexpected GET {url}")
        return self._get_responses.pop(0)

    def post(self, url: str, *, json=None, **_kwargs):
        self.post_calls.append((url, json))
        if self._raise_on_post:
            raise self._raise_on_post
        if not self._post_responses:
            raise AssertionError(f"unexpected POST {url}")
        return self._post_responses.pop(0)


def _patch_httpx_client(monkeypatch, fake: _FakeClient) -> None:
    """Make ip_identity.httpx.Client(...) return our fake."""
    fake_module = MagicMock()
    fake_module.Client = lambda *a, **kw: fake
    monkeypatch.setattr(ip_identity, "httpx", fake_module)


# ─── lookup_ip_identity ───────────────────────────────────────────────────

def test_single_lookup_returns_parsed_dict_and_caches(monkeypatch):
    payload = {"status": "success", "org": "Cloudflare", "isp": "Cloudflare",
               "proxy": False, "hosting": True, "reverse": "one.one.one.one"}
    fake = _FakeClient(get_responses=[_FakeResponse(200, payload)])
    _patch_httpx_client(monkeypatch, fake)

    result = ip_identity.lookup_ip_identity("1.1.1.1")
    assert result is not None
    assert result["org"] == "Cloudflare"

    cache = get_cache()
    found, cached = cache.get("IPApiIdentity", "ip", "1.1.1.1")
    assert found is True
    assert cached["org"] == "Cloudflare"


def test_second_lookup_hits_cache_no_extra_http(monkeypatch):
    payload = {"status": "success", "org": "Cloudflare", "proxy": False}
    fake = _FakeClient(get_responses=[_FakeResponse(200, payload)])
    _patch_httpx_client(monkeypatch, fake)

    ip_identity.lookup_ip_identity("1.1.1.1")
    ip_identity.lookup_ip_identity("1.1.1.1")
    ip_identity.lookup_ip_identity("1.1.1.1")

    assert len(fake.get_calls) == 1, "second/third call should be served from cache"


def test_failed_lookup_negative_caches(monkeypatch):
    fake = _FakeClient(get_responses=[_FakeResponse(429, {})])
    _patch_httpx_client(monkeypatch, fake)

    result = ip_identity.lookup_ip_identity("8.8.8.8")
    assert result is None

    # Second call must not re-hit HTTP — negative cache
    ip_identity.lookup_ip_identity("8.8.8.8")
    assert len(fake.get_calls) == 1, "negative cache should suppress retries"


def test_status_fail_payload_negative_caches(monkeypatch):
    payload = {"status": "fail", "message": "private range"}
    fake = _FakeClient(get_responses=[_FakeResponse(200, payload)])
    _patch_httpx_client(monkeypatch, fake)

    assert ip_identity.lookup_ip_identity("10.0.0.1") is None
    ip_identity.lookup_ip_identity("10.0.0.1")
    assert len(fake.get_calls) == 1


def test_network_exception_returns_none_no_raise(monkeypatch):
    fake = _FakeClient(raise_on_get=RuntimeError("network down"))
    _patch_httpx_client(monkeypatch, fake)

    result = ip_identity.lookup_ip_identity("1.1.1.1")
    assert result is None  # graceful degradation, no exception escapes


def test_empty_ip_returns_none_without_http(monkeypatch):
    fake = _FakeClient()
    _patch_httpx_client(monkeypatch, fake)

    assert ip_identity.lookup_ip_identity("") is None
    assert fake.get_calls == [], "empty ip must short-circuit before HTTP"


# ─── batch_prefetch_identities ────────────────────────────────────────────

def test_batch_prefetch_populates_cache_for_each_success(monkeypatch):
    batch_payload = [
        {"status": "success", "query": "1.1.1.1", "org": "Cloudflare", "proxy": False},
        {"status": "success", "query": "8.8.8.8", "org": "Google LLC", "proxy": False},
        {"status": "fail", "message": "private range", "query": "10.0.0.1"},
    ]
    fake = _FakeClient(post_responses=[_FakeResponse(200, batch_payload)])
    _patch_httpx_client(monkeypatch, fake)

    fetched = ip_identity.batch_prefetch_identities(["1.1.1.1", "8.8.8.8", "10.0.0.1"])
    assert fetched == 2

    assert len(fake.post_calls) == 1
    url, body = fake.post_calls[0]
    assert "ip-api.com/batch" in url
    assert body == ["1.1.1.1", "8.8.8.8", "10.0.0.1"]

    cache = get_cache()
    found_one, cached_one = cache.get("IPApiIdentity", "ip", "1.1.1.1")
    found_two, cached_two = cache.get("IPApiIdentity", "ip", "8.8.8.8")
    found_three, cached_three = cache.get("IPApiIdentity", "ip", "10.0.0.1")
    assert found_one and cached_one["org"] == "Cloudflare"
    assert found_two and cached_two["org"] == "Google LLC"
    assert found_three and cached_three is None  # negative cache for fail


def test_batch_prefetch_dedupes_and_skips_already_cached(monkeypatch):
    # Pre-seed cache with one IP
    cache = get_cache()
    cache.put("IPApiIdentity", "ip", "1.1.1.1", {"org": "Cloudflare"}, 3600)

    batch_payload = [{"status": "success", "query": "8.8.8.8", "org": "Google"}]
    fake = _FakeClient(post_responses=[_FakeResponse(200, batch_payload)])
    _patch_httpx_client(monkeypatch, fake)

    # Pass duplicate IPs and one already-cached
    fetched = ip_identity.batch_prefetch_identities(
        ["1.1.1.1", "8.8.8.8", "8.8.8.8", "1.1.1.1"]
    )

    assert fetched == 1
    assert len(fake.post_calls) == 1
    _url, body = fake.post_calls[0]
    assert body == ["8.8.8.8"], "1.1.1.1 was cached, dupes should be removed"


def test_batch_prefetch_failure_returns_zero_no_raise(monkeypatch):
    fake = _FakeClient(raise_on_post=RuntimeError("connection refused"))
    _patch_httpx_client(monkeypatch, fake)

    fetched = ip_identity.batch_prefetch_identities(["1.1.1.1", "8.8.8.8"])
    assert fetched == 0  # graceful — no exception escapes


def test_batch_prefetch_then_lookup_hits_cache(monkeypatch):
    # First, prefetch
    batch_payload = [
        {"status": "success", "query": "1.1.1.1", "org": "Cloudflare", "proxy": False},
    ]
    fake = _FakeClient(post_responses=[_FakeResponse(200, batch_payload)])
    _patch_httpx_client(monkeypatch, fake)

    ip_identity.batch_prefetch_identities(["1.1.1.1"])

    # Now lookup_ip_identity should see the cached entry — no GET should fire
    fake.get_calls.clear()
    result = ip_identity.lookup_ip_identity("1.1.1.1")

    assert result is not None
    assert result["org"] == "Cloudflare"
    assert fake.get_calls == [], "lookup after batch must hit cache, not HTTP"


def test_batch_prefetch_chunks_over_100(monkeypatch):
    # ip-api caps at 100 per request — we should split larger lists
    ips = [f"1.1.1.{i}" for i in range(120)]  # need 2 chunks
    chunk1 = [{"status": "success", "query": ip, "org": "T"} for ip in ips[:100]]
    chunk2 = [{"status": "success", "query": ip, "org": "T"} for ip in ips[100:]]
    fake = _FakeClient(post_responses=[
        _FakeResponse(200, chunk1),
        _FakeResponse(200, chunk2),
    ])
    _patch_httpx_client(monkeypatch, fake)

    fetched = ip_identity.batch_prefetch_identities(ips)
    assert fetched == 120
    assert len(fake.post_calls) == 2, "should split into 2 chunks of 100"
    assert len(fake.post_calls[0][1]) == 100
    assert len(fake.post_calls[1][1]) == 20
