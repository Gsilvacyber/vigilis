"""Thread-safe TTL cache for threat intelligence lookups."""
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


@dataclass
class CacheEntry:
    value: Any
    expires_at: float  # monotonic time


class ThreatIntelCache:
    def __init__(self, max_size: int = 10_000):
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size
        self.hits = 0
        self.misses = 0

    def _make_key(self, provider: str, indicator_type: str, value: str) -> str:
        return f"{provider}:{indicator_type}:{value.lower().strip()}"

    def get(self, provider: str, indicator_type: str, value: str) -> tuple[bool, Any]:
        """Returns (found: bool, result: Any). Result may be None (clean sentinel)."""
        key = self._make_key(provider, indicator_type, value)
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self.misses += 1
                return False, None
            if time.monotonic() > entry.expires_at:
                del self._store[key]
                self.misses += 1
                return False, None
            self._store.move_to_end(key)
            self.hits += 1
            return True, entry.value

    def put(
        self,
        provider: str,
        indicator_type: str,
        value: str,
        result: Any,
        ttl_seconds: int,
    ) -> None:
        key = self._make_key(provider, indicator_type, value)
        with self._lock:
            self._store[key] = CacheEntry(
                value=result, expires_at=time.monotonic() + ttl_seconds
            )
            self._store.move_to_end(key)
            while len(self._store) > self._max_size:
                self._store.popitem(last=False)

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": round(self.hits / total, 3) if total else 0,
            "size": len(self._store),
        }


# Module-level singleton
_cache = ThreatIntelCache()

# TTL config (seconds)
IP_TTL = 3600  # 1 hour
DOMAIN_TTL = 86400  # 24 hours
HASH_TTL = 86400  # 24 hours


def get_cache() -> ThreatIntelCache:
    return _cache
