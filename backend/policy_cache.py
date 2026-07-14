"""
Adaptive Privacy Observatory — Policy Cache

In-memory origin-keyed cache for script classification decisions. Each entry
records the intent classification (fingerprint / legitimate / unknown), the
confidence level, and the noise multiplier that the extension should apply.

Thread safety is provided via asyncio.Lock (appropriate for the single-process
async FastAPI server). Entries expire after a configurable TTL (default: 1 hour)
so stale classifications don't persist across browsing sessions.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Literal


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
# Policy Cache — origin-keyed store with TTL
# ---------------------------------------------------------------------------

DEFAULT_TTL_SECONDS: float = 3600.0  # 1 hour


class PolicyCache:
    """
    Async-safe in-memory cache mapping script origins to classification entries.

    Designed for a single-process FastAPI server. The asyncio.Lock prevents
    concurrent coroutines from corrupting shared state during read-modify-write
    sequences. Entries older than ``ttl_seconds`` are silently evicted on access.
    """

    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        self._store: dict[str, PolicyEntry] = {}
        self._lock = asyncio.Lock()
        self._ttl = ttl_seconds

    async def get(self, origin: str) -> PolicyEntry | None:
        """
        Retrieve a cached policy entry, or None if missing / expired.

        Expired entries are evicted lazily on read so the cache doesn't
        retain stale decisions.
        """
        async with self._lock:
            entry = self._store.get(origin)
            if entry is None:
                return None
            if entry.is_expired(self._ttl):
                del self._store[origin]
                return None
            return entry

    async def set(self, origin: str, entry: PolicyEntry) -> None:
        """Insert or overwrite a classification for the given origin."""
        async with self._lock:
            self._store[origin] = entry

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
            return dict(self._store)

    async def clear(self) -> None:
        """Drop all cached entries."""
        async with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        """Approximate number of entries (may include recently-expired ones)."""
        return len(self._store)
