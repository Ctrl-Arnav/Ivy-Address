"""
Shared test fixtures for the Adaptive Privacy Observatory backend.
"""

from __future__ import annotations

import asyncio
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from heuristic_classifier import HeuristicClassifier
from policy_cache import PolicyCache, PolicyEntry


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Policy cache
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def cache():
    """Provide a fresh PolicyCache for each test."""
    return PolicyCache(ttl_seconds=60.0, max_size=100)


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


@pytest.fixture
def classifier():
    """Provide a fresh HeuristicClassifier for each test."""
    return HeuristicClassifier()


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_entry() -> PolicyEntry:
    """A representative PolicyEntry for testing."""
    return PolicyEntry(
        origin="https://tracker.example.com",
        intent="fingerprint",
        confidence=0.85,
        reason="Test entry",
        signals=["known_fp_domain_origin"],
        source="heuristic",
        noise_multiplier=1.0,
        timestamp=time.time(),
    )


@pytest.fixture
def sample_telemetry() -> dict:
    """A representative telemetry event dict."""
    return {
        "api": "canvas.toDataURL",
        "origin": "https://example.com",
        "timestamp": time.time(),
        "width": 8,
        "height": 8,
    }


# ---------------------------------------------------------------------------
# FastAPI test client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def client():
    """Provide an async HTTP client for testing FastAPI endpoints."""
    from main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
