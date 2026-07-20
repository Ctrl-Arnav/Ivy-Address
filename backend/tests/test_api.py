"""
Tests for the FastAPI REST and WebSocket endpoints.
"""

from __future__ import annotations

import pytest
import pytest_asyncio


@pytest.mark.asyncio
class TestHealthEndpoint:
    """GET /api/health"""

    async def test_health_ok(self, client):
        """Health endpoint should return 200 with status ok."""
        resp = await client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data


@pytest.mark.asyncio
class TestStatusEndpoint:
    """GET /api/status"""

    async def test_status_running(self, client):
        """Status endpoint should return running state."""
        resp = await client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "running"
        assert "uptime_seconds" in data
        assert "total_intercepts" in data
        assert "cache_size" in data
        assert "version" in data

    async def test_status_has_cache_stats(self, client):
        """Status should include cache statistics."""
        resp = await client.get("/api/status")
        data = resp.json()
        assert "cache_stats" in data
        stats = data["cache_stats"]
        assert "hits" in stats
        assert "misses" in stats


@pytest.mark.asyncio
class TestPoliciesEndpoint:
    """GET /api/policies"""

    async def test_policies_empty(self, client):
        """Fresh server should return empty policies."""
        resp = await client.get("/api/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert "count" in data
        assert "policies" in data
        assert isinstance(data["policies"], dict)


@pytest.mark.asyncio
class TestEntropySummaryEndpoint:
    """GET /api/entropy-summary"""

    async def test_entropy_summary_structure(self, client):
        """Entropy summary should return per-API breakdown."""
        resp = await client.get("/api/entropy-summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "per_api" in data
        assert "total_before" in data
        assert "total_after" in data
        assert "reduction_pct" in data
        assert data["total_before"] > 0
        assert data["reduction_pct"] > 0

    async def test_entropy_summary_has_entries(self, client):
        """Should have entries for all known APIs."""
        resp = await client.get("/api/entropy-summary")
        data = resp.json()
        assert len(data["per_api"]) > 0
        for entry in data["per_api"]:
            assert "api" in entry
            assert "entropy_before" in entry
            assert "entropy_after" in entry
            assert "reduction_bits" in entry


@pytest.mark.asyncio
class TestDeletePolicy:
    """DELETE /api/policies/{origin}"""

    async def test_delete_nonexistent(self, client):
        """Deleting a non-existent policy should return not_found."""
        resp = await client.delete("/api/policies/https://nonexistent.com")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_found"
