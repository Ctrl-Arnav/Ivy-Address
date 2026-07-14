"""
Adaptive Privacy Observatory — Backend Server

FastAPI application providing:
  WebSocket /ws/telemetry  — receives browser extension events, classifies,
                             responds with noise instructions
  WebSocket /ws/dashboard  — broadcasts real-time updates to the dashboard
  GET       /api/status    — server health + aggregate stats
  GET       /api/policies  — current policy cache as JSON

Run directly:  python main.py
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from entropy_engine import (
    calculate_api_entropy,
    calculate_protected_entropy,
)
from heuristic_classifier import HeuristicClassifier
from policy_cache import PolicyCache, PolicyEntry
from prng import create_prng


# ---------------------------------------------------------------------------
# Shared application state (no database)
# ---------------------------------------------------------------------------


class AppState:
    """Mutable singleton holding all server-wide state."""

    def __init__(self) -> None:
        self.policy_cache = PolicyCache()
        self.classifier = HeuristicClassifier()
        self.total_intercepts: int = 0
        self.start_time: float = time.time()
        self.recent_events: list[dict] = []  # Rolling window, last 100
        self.dashboard_clients: list[WebSocket] = []

    def record_event(self, event: dict) -> None:
        """Append to the rolling recent-events buffer."""
        self.recent_events.append(event)
        if len(self.recent_events) > 100:
            self.recent_events = self.recent_events[-100:]


state = AppState()


# ---------------------------------------------------------------------------
# Lifespan — startup / shutdown hooks
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Print startup banner, yield, then clean up."""
    _print_banner()
    yield
    print("\n[APO] Shutting down...")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Adaptive Privacy Observatory",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# WebSocket — /ws/telemetry
# ---------------------------------------------------------------------------


@app.websocket("/ws/telemetry")
async def telemetry_ws(ws: WebSocket) -> None:
    """
    Receive telemetry events from the browser extension.

    Each incoming message is a JSON object with at minimum:
      { "api": str, "origin": str, "timestamp": float }

    The server classifies the event, updates the policy cache, and responds
    with a JSON object the extension uses to decide noise application:
      { "action": str, "noise_multiplier": float,
        "entropy_before": float, "entropy_after": float,
        "classification": dict }
    """
    await ws.accept()
    print(f"[Telemetry] Client connected ({ws.client})")

    try:
        while True:
            raw = await ws.receive_text()
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"error": "invalid JSON"})
                continue

            # The extension's injector.js wraps payloads in an envelope:
            #   { "type": "telemetry" | "script_source", "payload": {...} }
            msg_type = message.get("type", "telemetry")
            payload = message.get("payload", message)

            if msg_type == "telemetry":
                response = await _process_telemetry(payload)
                await ws.send_json(response)

                # Broadcast to dashboard clients (fire-and-forget).
                await _broadcast_to_dashboard({
                    "type": "telemetry_event",
                    "event": payload,
                    "classification": response,
                })

            elif msg_type == "script_source":
                # Phase 3: forward to the AI analyzer for intent classification.
                # For now, log and acknowledge.
                src_url = payload.get("url", "unknown")
                src_len = payload.get("source_length", 0)
                print(f"[Telemetry] Script source received: {src_url} ({src_len} bytes)")
                await ws.send_json({
                    "type": "script_source_ack",
                    "url": src_url,
                    "status": "queued",
                })

    except WebSocketDisconnect:
        print(f"[Telemetry] Client disconnected ({ws.client})")


async def _process_telemetry(telemetry: dict) -> dict:
    """Classify a telemetry event and return the response payload."""
    state.total_intercepts += 1

    # Run heuristic classifier (synchronous, sub-ms).
    entry: PolicyEntry = state.classifier.classify(telemetry)

    # Check if we already have a higher-confidence decision cached.
    cached = await state.policy_cache.get(entry.origin)
    if cached and cached.confidence > entry.confidence:
        entry = cached
    else:
        await state.policy_cache.set(entry.origin, entry)

    # Calculate entropy metrics.
    api_name = telemetry.get("api", "")
    raw_value = telemetry.get("raw_value")
    entropy_before = calculate_api_entropy(api_name, raw_value)

    # Simulate protected entropy (perturbation would have been applied).
    perturbed_value = _simulate_perturbation(
        api_name, entry.origin, entry.noise_multiplier,
    )
    entropy_after = calculate_protected_entropy(
        api_name, raw_value, perturbed_value,
    )

    event_record = {
        "api": api_name,
        "origin": entry.origin,
        "intent": entry.intent,
        "confidence": entry.confidence,
        "entropy_before": round(entropy_before, 2),
        "entropy_after": round(entropy_after, 2),
        "timestamp": time.time(),
    }
    state.record_event(event_record)

    return {
        "action": "perturb" if entry.noise_multiplier > 0 else "allow",
        "noise_multiplier": entry.noise_multiplier,
        "entropy_before": round(entropy_before, 2),
        "entropy_after": round(entropy_after, 2),
        "classification": entry.to_dict(),
    }


def _simulate_perturbation(
    api_name: str, origin: str, noise_multiplier: float,
) -> Any:
    """
    Generate a dummy perturbed value via the PRNG to model entropy reduction.

    Returns None when noise_multiplier is 0 (no perturbation), otherwise
    returns a sentinel to indicate perturbation was applied.
    """
    if noise_multiplier <= 0:
        return None

    # Use today's date as the salt (mirrors the extension's daily rotation).
    daily_salt = time.strftime("%Y-%m-%d")
    prng = create_prng(origin, daily_salt)

    # Advance the PRNG a few steps (mimics the extension's per-API offset).
    for _ in range(3):
        prng.next()

    # Return a float as a stand-in for "perturbed value exists".
    return prng.next_float()


# ---------------------------------------------------------------------------
# WebSocket — /ws/dashboard
# ---------------------------------------------------------------------------


@app.websocket("/ws/dashboard")
async def dashboard_ws(ws: WebSocket) -> None:
    """
    Stream real-time updates to the dashboard UI (read-only).

    On connect, sends the current full state. Subsequently, updates are
    pushed whenever new telemetry arrives (via _broadcast_to_dashboard).
    """
    await ws.accept()
    state.dashboard_clients.append(ws)
    print(f"[Dashboard] Client connected ({ws.client}), "
          f"total: {len(state.dashboard_clients)}")

    try:
        # Send initial state snapshot.
        await ws.send_json(await _build_dashboard_snapshot())

        # Keep the connection alive; the dashboard is read-only so we just
        # listen for pings or a disconnect.
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        state.dashboard_clients.remove(ws)
        print(f"[Dashboard] Client disconnected, "
              f"remaining: {len(state.dashboard_clients)}")


async def _broadcast_to_dashboard(message: dict) -> None:
    """Send a message to all connected dashboard clients."""
    dead: list[WebSocket] = []
    for client in state.dashboard_clients:
        try:
            await client.send_json(message)
        except Exception:
            dead.append(client)
    for client in dead:
        state.dashboard_clients.remove(client)


async def _build_dashboard_snapshot() -> dict:
    """Assemble the full dashboard state snapshot."""
    policies = await state.policy_cache.get_all()
    return {
        "type": "snapshot",
        "status": _build_status(),
        "policies": {k: v.to_dict() for k, v in policies.items()},
        "recent_events": state.recent_events[-20:],
    }


# ---------------------------------------------------------------------------
# REST — /api/status
# ---------------------------------------------------------------------------


@app.get("/api/status")
async def get_status() -> dict:
    """Return server health, uptime, and aggregate statistics."""
    return _build_status()


def _build_status() -> dict:
    """Shared status builder used by both REST and dashboard."""
    uptime = time.time() - state.start_time
    return {
        "status": "running",
        "version": "0.2.0",
        "uptime_seconds": round(uptime, 1),
        "total_intercepts": state.total_intercepts,
        "cache_size": state.policy_cache.size,
        "dashboard_clients": len(state.dashboard_clients),
    }


# ---------------------------------------------------------------------------
# REST — /api/policies
# ---------------------------------------------------------------------------


@app.get("/api/policies")
async def get_policies() -> dict:
    """Return the full policy cache as JSON."""
    policies = await state.policy_cache.get_all()
    return {
        "count": len(policies),
        "policies": {k: v.to_dict() for k, v in policies.items()},
    }


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    """Display a startup banner in the console."""
    banner = """
    +==================================================+
    |   Adaptive Privacy Observatory  --  Backend v0.2 |
    |--------------------------------------------------|
    |  WebSocket  /ws/telemetry   (extension events)   |
    |  WebSocket  /ws/dashboard   (live dashboard)     |
    |  REST       /api/status     (server health)      |
    |  REST       /api/policies   (policy cache)       |
    +==================================================+
    """
    print(banner)


# ---------------------------------------------------------------------------
# Direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info",
    )
