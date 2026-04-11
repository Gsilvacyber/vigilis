"""API key authentication, tenant resolution, and rate limiting.

Rate limiting uses in-process memory by default. For multi-worker
deployments, set ``REDIS_URL`` to enable distributed rate limiting
backed by Redis INCR with TTL.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

import bcrypt
from fastapi import Header, HTTPException
from sqlmodel import select

from backend.app.core.config import settings
from backend.app.core.db import get_session

_log = logging.getLogger(__name__)

DEMO_API_KEY = settings.demo_api_key

_RATE_LIMIT = 100  # requests per minute per key
_rate_counts: dict[str, tuple[int, int]] = {}  # key -> (count, minute_bucket)

# ── Optional Redis-backed rate limiting ─────────────────────────────────

_redis_client = None


def _init_redis() -> None:
    """Connect to Redis if REDIS_URL is set. Falls back to in-memory."""
    global _redis_client
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return
    try:
        import redis  # optional dependency
        _redis_client = redis.from_url(redis_url)
        _redis_client.ping()
        _log.info("Redis rate limiter connected: %s", redis_url)
    except Exception as e:
        _log.warning("Redis rate limiter failed, falling back to in-memory: %s", e)
        _redis_client = None


_init_redis()

if settings.app_env == "prod" and _redis_client is None:
    _max_workers = int(os.getenv("MAX_WORKERS", "1"))
    if _max_workers > 1:
        raise RuntimeError(
            f"FATAL: Rate limiting uses in-process memory but MAX_WORKERS={_max_workers}. "
            "Each worker maintains independent rate counters, allowing "
            f"{_max_workers}x the intended rate limit. "
            "Set REDIS_URL for distributed rate limiting, or set MAX_WORKERS=1."
        )
    _log.warning(
        "SECURITY: Rate limiting uses in-process memory (single worker). "
        "For multi-worker deployments, set REDIS_URL and MAX_WORKERS."
    )


def _check_rate_limit_redis(key: str) -> None:
    """Redis-backed rate limit using INCR + EXPIRE."""
    bucket_key = f"rate:{key}:{int(time.time() // 60)}"
    count = _redis_client.incr(bucket_key)  # type: ignore[union-attr]
    if count == 1:
        _redis_client.expire(bucket_key, 120)  # type: ignore[union-attr]  # 2-minute TTL
    if count > _RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({_RATE_LIMIT} requests/minute)",
        )


def _hash_key(raw_key: str) -> str:
    return bcrypt.hashpw(raw_key.encode(), bcrypt.gensalt()).decode()


def _verify_key(raw_key: str, key_hash: str) -> bool:
    try:
        return bcrypt.checkpw(raw_key.encode(), key_hash.encode())
    except Exception:
        return False


def _check_rate_limit(api_key: str) -> None:
    if _redis_client:
        return _check_rate_limit_redis(api_key)

    minute = int(time.time() // 60)
    entry = _rate_counts.get(api_key)
    if entry is None or entry[1] != minute:
        _rate_counts[api_key] = (1, minute)
        return
    count, _ = entry
    if count >= _RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded ({_RATE_LIMIT} requests/minute)",
        )
    _rate_counts[api_key] = (count + 1, minute)

    # Prune stale entries older than 2 minutes
    stale = [k for k, (_, m) in _rate_counts.items() if m < minute - 1]
    for k in stale:
        del _rate_counts[k]


def _resolve_key(raw_key: Optional[str]) -> tuple[Optional[str], Optional[str], str]:
    """Return (key, tenant_id, role).  tenant_id is None when key is invalid."""
    if not raw_key:
        return None, None, "analyst"
    from backend.app.db.models import ApiKey  # deferred to avoid circular import

    prefix = raw_key[:8]
    with get_session() as session:
        candidates = session.exec(
            select(ApiKey).where(ApiKey.key_prefix == prefix, ApiKey.is_active == True)  # noqa: E712
        ).all()
        for candidate in candidates:
            if _verify_key(raw_key, candidate.key_hash):
                _check_rate_limit(raw_key)
                return raw_key, candidate.tenant_id, candidate.role
    return raw_key, None, "analyst"


def require_tenant(x_api_key: Optional[str] = Header(None)) -> str:
    """Dependency - require a valid API key.  Returns the key's tenant_id."""
    key, tenant_id, _role = _resolve_key(x_api_key)
    if key is None:
        raise HTTPException(status_code=401, detail="Missing API key (X-API-Key header required)")
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return tenant_id


def require_admin(x_api_key: Optional[str] = Header(None)) -> str:
    """Dependency - require a valid API key with admin role. Returns tenant_id."""
    key, tenant_id, role = _resolve_key(x_api_key)
    if key is None:
        raise HTTPException(status_code=401, detail="Missing API key (X-API-Key header required)")
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return tenant_id


def optional_tenant(x_api_key: Optional[str] = Header(None)) -> str:
    """Dependency - use API key if provided, else fall back to demo-tenant."""
    if settings.app_env == "prod":
        return require_tenant(x_api_key)
    key, tenant_id, _role = _resolve_key(x_api_key)
    if key is not None and tenant_id is None:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return tenant_id or "demo-tenant"


def _resolve_key_prefix(raw_key: Optional[str]) -> str:
    """Extract the prefix from a raw key for audit logging."""
    if not raw_key:
        return "system"
    return raw_key[:8]


def seed_demo_key() -> None:
    """Ensure the well-known demo API key exists in the DB."""
    from backend.app.db.models import ApiKey

    prefix = DEMO_API_KEY[:8]
    with get_session() as session:
        existing = session.exec(
            select(ApiKey).where(ApiKey.key_prefix == prefix)
        ).first()
        if existing is None:
            session.add(
                ApiKey(
                    key_hash=_hash_key(DEMO_API_KEY),
                    key_prefix=prefix,
                    tenant_id="demo-tenant",
                    name="Demo Key (development only)",
                    role="admin",
                )
            )
            session.commit()
