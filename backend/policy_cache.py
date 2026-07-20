"""
Adaptive Privacy Observatory — Policy Cache

In-memory origin-keyed cache for script classification decisions. Each entry
records the intent classification (fingerprint / legitimate / unknown), the
confidence level, and the noise multiplier that the extension should apply.

Thread safety is provided via asyncio.Lock (appropriate for the single-process
async FastAPI server). Entries expire after a configurable TTL (default: 1 hour)
so stale classifications don't persist across browsing sessions.

Includes LRU eviction when the cache exceeds ``max_size`` to bound memory usage.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger("apo.cache")


# ---------------------------------------------------------------------------
# Policy Entry — a single classification decision
# ---------------------------------------------------------------------------


@dataclass
class PolicyEntry:
    """A cached classification decision for a single script origin."""

    origin: str
    intent: Literal["fingerprint", "legitimate", "unknown"]
    confidence: float
    reason: str  # Human-readable explanation
    signals: list[str]  # Detected fingerprinting signals
    source: Literal["heuristic", "ai", "user"]  # Who made this classification
    noise_multiplier: float  # 1.0 for trackers, 0.0 for legitimate
    timestamp: float  # When the classification was made

    def to_dict(self) -> dict:
        """Serialize to a plain dict for JSON responses."""
        return {
            "origin": self.origin,
            "intent": self.intent,
            "confidence": self.confidence,
            "reason": self.reason,
            "signals": self.signals,
            "source": self.source,
            "noise_multiplier": self.noise_multiplier,
            "timestamp": self.timestamp,
        }

    def is_expired(self, ttl_seconds: float) -> bool:
        """Check whether this entry has exceeded the TTL."""
        return (time.time() - self.timestamp) > ttl_seconds


# ---------------------------------------------------------------------------
# Cache Statistics
# ---------------------------------------------------------------------------


@dataclass
class CacheStats:
    """Runtime statistics for the policy cache."""

    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expired: int = 0

    def to_dict(self) -> dict:
        total = self.hits + self.misses
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expired": self.expired,
            "hit_rate": round(self.hits / total, 4) if total > 0 else 0.0,
        }


# ---------------------------------------------------------------------------
# Policy Cache — origin-keyed store with TTL + LRU eviction
# ---------------------------------------------------------------------------

DEFAULT_TTL_SECONDS: float = 3600.0  # 1 hour
DEFAULT_MAX_SIZE: int = 10_000


class PolicyCache:
    """
    Async-safe in-memory cache mapping script origins to classification entries.

    Designed for a single-process FastAPI server. The asyncio.Lock prevents
    concurrent coroutines from corrupting shared state during read-modify-write
    sequences. Entries older than ``ttl_seconds`` are silently evicted on access.

    When the cache exceeds ``max_size``, the least-recently-used entry is
    evicted to bound memory usage.
    """

    def __init__(
        self,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_size: int = DEFAULT_MAX_SIZE,
    ) -> None:
        self._store: OrderedDict[str, PolicyEntry] = OrderedDict()
        self._lock = asyncio.Lock()
        self._ttl = ttl_seconds
        self._max_size = max_size
        self._stats = CacheStats()

    @property
    def stats(self) -> CacheStats:
        """Return a reference to the cache statistics."""
        return self._stats

    async def get(self, origin: str) -> PolicyEntry | None:
        """
        Retrieve a cached policy entry, or None if missing / expired.

        Expired entries are evicted lazily on read so the cache doesn't
        retain stale decisions. Successful lookups promote the entry to
        the most-recently-used position.
        """
        async with self._lock:
            entry = self._store.get(origin)
            if entry is None:
                self._stats.misses += 1
                return None
            if entry.is_expired(self._ttl):
                del self._store[origin]
                self._stats.expired += 1
                self._stats.misses += 1
                logger.debug("Cache entry expired: %s", origin)
                return None
            # Promote to most-recently-used.
            self._store.move_to_end(origin)
            self._stats.hits += 1
            return entry

    async def set(self, origin: str, entry: PolicyEntry) -> None:
        """Insert or overwrite a classification for the given origin."""
        async with self._lock:
            if origin in self._store:
                # Update existing — move to end (most recent).
                self._store[origin] = entry
                self._store.move_to_end(origin)
            else:
                self._store[origin] = entry
                # Evict least-recently-used entries if over capacity.
                while len(self._store) > self._max_size:
                    evicted_key, _ = self._store.popitem(last=False)
                    self._stats.evictions += 1
                    logger.debug("LRU eviction: %s", evicted_key)

    async def delete(self, origin: str) -> bool:
        """
        Remove a single entry by origin.

        Returns True if the entry existed and was removed.
        """
        async with self._lock:
            if origin in self._store:
                del self._store[origin]
                return True
            return False

    async def get_all(self) -> dict[str, PolicyEntry]:
        """
        Return all non-expired entries. Used by the dashboard endpoint.

        Also performs a sweep of expired entries to keep memory bounded.
        """
        async with self._lock:
            now = time.time()
            expired_keys = [
                k for k, v in self._store.items()
                if (now - v.timestamp) > self._ttl
            ]
            for k in expired_keys:
                del self._store[k]
                self._stats.expired += 1
            return dict(self._store)

    async def clear(self) -> None:
        """Drop all cached entries."""
        async with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        """Approximate number of entries (may include recently-expired ones)."""
        return len(self._store)
