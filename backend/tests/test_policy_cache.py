"""
Tests for the async policy cache.
"""

from __future__ import annotations

import time

import pytest
import pytest_asyncio

from policy_cache import PolicyCache, PolicyEntry


def _make_entry(origin: str, **kwargs) -> PolicyEntry:
    """Helper to create a PolicyEntry with sensible defaults."""
    defaults = {
        "origin": origin,
        "intent": "unknown",
        "confidence": 0.5,
        "reason": "test",
        "signals": [],
        "source": "heuristic",
        "noise_multiplier": 0.5,
        "timestamp": time.time(),
    }
    defaults.update(kwargs)
    return PolicyEntry(**defaults)


@pytest.mark.asyncio
class TestPolicyCacheBasic:
    """Basic CRUD operations."""

    async def test_set_and_get(self, cache):
        """Set then get should return the same entry."""
        entry = _make_entry("https://example.com")
        await cache.set("https://example.com", entry)
        result = await cache.get("https://example.com")
        assert result is not None
        assert result.origin == "https://example.com"

    async def test_get_missing_returns_none(self, cache):
        """Getting a non-existent key should return None."""
        result = await cache.get("https://nonexistent.com")
        assert result is None

    async def test_overwrite(self, cache):
        """Setting the same key twice should overwrite."""
        entry1 = _make_entry("https://example.com", confidence=0.3)
        entry2 = _make_entry("https://example.com", confidence=0.9)
        await cache.set("https://example.com", entry1)
        await cache.set("https://example.com", entry2)
        result = await cache.get("https://example.com")
        assert result.confidence == 0.9

    async def test_delete_existing(self, cache):
        """Deleting an existing entry should return True."""
        entry = _make_entry("https://example.com")
        await cache.set("https://example.com", entry)
        assert await cache.delete("https://example.com") is True
        assert await cache.get("https://example.com") is None

    async def test_delete_missing(self, cache):
        """Deleting a non-existent entry should return False."""
        assert await cache.delete("https://nonexistent.com") is False

    async def test_clear(self, cache):
        """Clear should remove all entries."""
        for i in range(10):
            await cache.set(f"https://site-{i}.com", _make_entry(f"https://site-{i}.com"))
        assert cache.size == 10
        await cache.clear()
        assert cache.size == 0

    async def test_size_property(self, cache):
        """Size should reflect the number of entries."""
        assert cache.size == 0
        await cache.set("https://a.com", _make_entry("https://a.com"))
        assert cache.size == 1
        await cache.set("https://b.com", _make_entry("https://b.com"))
        assert cache.size == 2


@pytest.mark.asyncio
class TestTTLExpiry:
    """TTL-based expiration tests."""

    async def test_expired_entry_returns_none(self):
        """Entries older than TTL should be evicted on access."""
        cache = PolicyCache(ttl_seconds=0.1, max_size=100)
        entry = _make_entry("https://example.com", timestamp=time.time() - 1.0)
        await cache.set("https://example.com", entry)
        result = await cache.get("https://example.com")
        assert result is None

    async def test_fresh_entry_not_expired(self):
        """Entries within TTL should be returned normally."""
        cache = PolicyCache(ttl_seconds=3600.0, max_size=100)
        entry = _make_entry("https://example.com")
        await cache.set("https://example.com", entry)
        result = await cache.get("https://example.com")
        assert result is not None

    async def test_get_all_sweeps_expired(self):
        """get_all() should sweep expired entries."""
        cache = PolicyCache(ttl_seconds=0.1, max_size=100)
        old_entry = _make_entry("https://old.com", timestamp=time.time() - 1.0)
        new_entry = _make_entry("https://new.com")
        await cache.set("https://old.com", old_entry)
        await cache.set("https://new.com", new_entry)

        all_entries = await cache.get_all()
        assert "https://old.com" not in all_entries
        assert "https://new.com" in all_entries


@pytest.mark.asyncio
class TestLRUEviction:
    """LRU eviction when cache exceeds max_size."""

    async def test_eviction_at_max_size(self):
        """Cache should evict LRU entry when max_size is exceeded."""
        cache = PolicyCache(ttl_seconds=3600.0, max_size=3)
        for i in range(5):
            await cache.set(f"https://site-{i}.com", _make_entry(f"https://site-{i}.com"))

        assert cache.size == 3
        # Oldest entries (0, 1) should be evicted.
        assert await cache.get("https://site-0.com") is None
        assert await cache.get("https://site-1.com") is None
        # Newest entries should remain.
        assert await cache.get("https://site-4.com") is not None

    async def test_access_promotes_entry(self):
        """Accessing an entry should promote it to most-recently-used."""
        cache = PolicyCache(ttl_seconds=3600.0, max_size=3)
        await cache.set("https://a.com", _make_entry("https://a.com"))
        await cache.set("https://b.com", _make_entry("https://b.com"))
        await cache.set("https://c.com", _make_entry("https://c.com"))

        # Access 'a' to promote it.
        await cache.get("https://a.com")

        # Add a new entry — 'b' (least recently used) should be evicted.
        await cache.set("https://d.com", _make_entry("https://d.com"))

        assert await cache.get("https://a.com") is not None  # promoted
        assert await cache.get("https://b.com") is None  # evicted
        assert await cache.get("https://c.com") is not None
        assert await cache.get("https://d.com") is not None


@pytest.mark.asyncio
class TestCacheStats:
    """Cache statistics tracking."""

    async def test_hit_count(self, cache):
        """Successful gets should increment hits."""
        entry = _make_entry("https://example.com")
        await cache.set("https://example.com", entry)
        await cache.get("https://example.com")
        await cache.get("https://example.com")
        assert cache.stats.hits == 2

    async def test_miss_count(self, cache):
        """Failed gets should increment misses."""
        await cache.get("https://nonexistent.com")
        assert cache.stats.misses == 1

    async def test_stats_to_dict(self, cache):
        """stats.to_dict() should contain expected keys."""
        stats = cache.stats.to_dict()
        assert "hits" in stats
        assert "misses" in stats
        assert "evictions" in stats
        assert "expired" in stats
        assert "hit_rate" in stats


@pytest.mark.asyncio
class TestPolicyEntryMethods:
    """Tests for the PolicyEntry dataclass methods."""

    def test_to_dict(self, sample_entry):
        """to_dict() should return a complete dict."""
        d = sample_entry.to_dict()
        assert d["origin"] == sample_entry.origin
        assert d["intent"] == sample_entry.intent
        assert d["confidence"] == sample_entry.confidence
        assert "signals" in d

    def test_is_expired_true(self):
        """Entry older than TTL should report as expired."""
        entry = _make_entry("test", timestamp=time.time() - 100.0)
        assert entry.is_expired(60.0) is True

    def test_is_expired_false(self):
        """Fresh entry should not report as expired."""
        entry = _make_entry("test")
        assert entry.is_expired(3600.0) is False
