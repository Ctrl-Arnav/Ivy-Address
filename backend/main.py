"""
Adaptive Privacy Observatory — Backend Server

FastAPI application providing:
  WebSocket /ws/telemetry  — receives browser extension events, classifies,
                             responds with noise instructions
  WebSocket /ws/dashboard  — broadcasts real-time updates to the dashboard
  GET       /api/health    — lightweight health probe
  GET       /api/status    — server health + aggregate stats
  GET       /api/policies  — current policy cache as JSON
  GET       /api/entropy-summary — entropy reduction summary
  DELETE    /api/policies/{origin} — invalidate a cached policy

Static files from ``dashboard/`` are served at ``/dashboard``.

Run directly:  python main.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from config import settings
from entropy_engine import (
    API_ENTROPY_BITS,
    calculate_api_entropy,
    calculate_protected_entropy,
    entropy_reduction_summary,
)
from heuristic_classifier import HeuristicClassifier
from script_analyzer import ScriptAnalyzer
from models import (
    ClassificationResponse,
    EntropySummaryResponse,
    HealthResponse,
    PolicyResponse,
    StatusResponse,
    TelemetryEvent,
    WebSocketEnvelope,
)
from policy_cache import PolicyCache, PolicyEntry
from prng import create_prng


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG_FORMAT = (
    "%(asctime)s | %(levelname)-7s | %(name)-18s | %(message)s"
)


def _configure_logging() -> None:
    """Set up structured logging for the entire application."""
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format=_LOG_FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    # Quieten noisy third-party loggers.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


logger = logging.getLogger("apo.server")


# ---------------------------------------------------------------------------
# Application version
# ---------------------------------------------------------------------------

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Shared application state (no database)
# ---------------------------------------------------------------------------


class AppState:
    """Mutable singleton holding all server-wide state."""

    def __init__(self) -> None:
        self.policy_cache = PolicyCache(
            ttl_seconds=settings.cache_ttl_seconds,
            max_size=settings.cache_max_size,
        )
        self.classifier = HeuristicClassifier(
            burst_call_count=settings.classifier_burst_call_count,
            burst_window_ms=settings.classifier_burst_window_ms,
            max_origins=settings.classifier_history_max_origins,
        )
        self.script_analyzer = ScriptAnalyzer()
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
    """Configure logging, print startup banner, yield, then clean up."""
    _configure_logging()
    _print_banner()
    logger.info("Server started on %s:%d", settings.host, settings.port)
    yield
    # Graceful shutdown: close all dashboard WebSocket connections.
    for client in list(state.dashboard_clients):
        try:
            await client.close(1001, "Server shutting down")
        except Exception:
            pass
    state.dashboard_clients.clear()
    logger.info("Server shut down gracefully")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Adaptive Privacy Observatory",
    version=__version__,
    description="Anti-fingerprinting backend with real-time telemetry classification",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount dashboard static files if the directory exists.
_dashboard_path = Path(settings.dashboard_dir)
if _dashboard_path.is_dir():
    app.mount(
        "/dashboard",
        StaticFiles(directory=str(_dashboard_path), html=True),
        name="dashboard",
    )
    logger.info("Dashboard mounted from %s", _dashboard_path)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------


@app.exception_handler(Exception)
async def _global_exception_handler(request, exc):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
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
    client_info = f"{ws.client}" if ws.client else "unknown"
    logger.info("Telemetry client connected (%s)", client_info)

    try:
        while True:
            raw = await ws.receive_text()

            # --- Parse JSON ---
            try:
                message = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Invalid JSON from telemetry client: %.100s", raw)
                await ws.send_json({"error": "invalid JSON"})
                continue

            # --- Validate envelope ---
            try:
                envelope = WebSocketEnvelope(**message)
            except Exception:
                # Fallback: treat the entire message as a telemetry payload.
                envelope = WebSocketEnvelope(type="telemetry", payload=message)

            # --- Route by type ---
            if envelope.type == "telemetry":
                try:
                    response = await _process_telemetry(envelope.payload)
                    await ws.send_json(response)

                    # Broadcast to dashboard clients (fire-and-forget).
                    await _broadcast_to_dashboard({
                        "type": "telemetry_event",
                        "event": envelope.payload,
                        "classification": response,
                    })
                except Exception:
                    logger.exception("Error processing telemetry event")
                    await ws.send_json({"error": "processing failed"})

            elif envelope.type == "script_source":
                src_url = envelope.payload.get("url", "unknown")
                src_origin = envelope.payload.get("origin") or envelope.payload.get("page_origin") or "unknown"
                source_text = envelope.payload.get("source_text", "")
                src_len = envelope.payload.get("source_length", len(source_text))

                logger.info(
                    "Script source received: %s (%d bytes) from %s", src_url, src_len, src_origin,
                )

                # Run AI script analysis (hybrid AST + ML classifier).
                result = state.script_analyzer.analyze(
                    url=src_url,
                    origin=src_origin,
                    source_text=source_text,
                )

                # Convert to policy entry and update policy cache if confidence is higher or source is unknown.
                ai_policy = result.to_policy_entry()
                cached = await state.policy_cache.get(src_origin)
                if not cached or ai_policy.confidence >= cached.confidence or cached.source == "heuristic":
                    await state.policy_cache.set(src_origin, ai_policy)

                response_payload = {
                    "type": "script_source_ack",
                    "url": src_url,
                    "status": "analyzed",
                    "intent": result.intent,
                    "confidence": result.confidence,
                    "probabilities": result.probabilities,
                    "signals": result.detected_signals,
                    "action": "perturb" if result.noise_multiplier > 0 else "allow",
                    "noise_multiplier": result.noise_multiplier,
                }

                await ws.send_json(response_payload)

                # Broadcast AI classification update to dashboard.
                await _broadcast_to_dashboard({
                    "type": "script_ai_classification",
                    "url": src_url,
                    "origin": src_origin,
                    "classification": response_payload,
                })

    except WebSocketDisconnect:
        logger.info("Telemetry client disconnected (%s)", client_info)
    except Exception:
        logger.exception("Unexpected error in telemetry WebSocket")


async def _process_telemetry(telemetry: dict) -> dict:
    """Classify a telemetry event and return the response payload."""
    state.total_intercepts += 1

    # Validate input.
    try:
        event = TelemetryEvent(**telemetry)
        telemetry_clean = event.model_dump()
    except Exception:
        telemetry_clean = telemetry

    # Run heuristic classifier (synchronous, sub-ms).
    entry: PolicyEntry = state.classifier.classify(telemetry_clean)

    # Check if we already have a higher-confidence decision cached.
    cached = await state.policy_cache.get(entry.origin)
    if cached and cached.confidence > entry.confidence:
        entry = cached
    else:
        await state.policy_cache.set(entry.origin, entry)

    # Calculate entropy metrics.
    api_name = telemetry_clean.get("api", "")
    raw_value = telemetry_clean.get("raw_value")
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
    logger.info(
        "Dashboard client connected, total: %d", len(state.dashboard_clients),
    )

    try:
        # Send initial state snapshot.
        await ws.send_json(await _build_dashboard_snapshot())

        # Keep the connection alive; the dashboard is read-only so we just
        # listen for pings or a disconnect.
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        if ws in state.dashboard_clients:
            state.dashboard_clients.remove(ws)
        logger.info(
            "Dashboard client disconnected, remaining: %d",
            len(state.dashboard_clients),
        )
    except Exception:
        if ws in state.dashboard_clients:
            state.dashboard_clients.remove(ws)
        logger.exception("Dashboard WebSocket error")


async def _broadcast_to_dashboard(message: dict) -> None:
    """Send a message to all connected dashboard clients."""
    dead: list[WebSocket] = []
    for client in state.dashboard_clients:
        try:
            await client.send_json(message)
        except Exception:
            dead.append(client)
    for client in dead:
        if client in state.dashboard_clients:
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
# REST — /api/health
# ---------------------------------------------------------------------------


@app.get("/api/health", response_model=HealthResponse)
async def get_health() -> dict:
    """Lightweight health probe for monitoring."""
    return {"status": "ok", "version": __version__}


# ---------------------------------------------------------------------------
# REST — /api/status
# ---------------------------------------------------------------------------


@app.get("/api/status", response_model=StatusResponse)
async def get_status() -> dict:
    """Return server health, uptime, and aggregate statistics."""
    return _build_status()


def _build_status() -> dict:
    """Shared status builder used by both REST and dashboard."""
    uptime = time.time() - state.start_time
    return {
        "status": "running",
        "version": __version__,
        "uptime_seconds": round(uptime, 1),
        "total_intercepts": state.total_intercepts,
        "cache_size": state.policy_cache.size,
        "cache_stats": state.policy_cache.stats.to_dict(),
        "dashboard_clients": len(state.dashboard_clients),
    }


# ---------------------------------------------------------------------------
# REST — /api/policies
# ---------------------------------------------------------------------------


@app.get("/api/policies", response_model=PolicyResponse)
async def get_policies() -> dict:
    """Return the full policy cache as JSON."""
    policies = await state.policy_cache.get_all()
    return {
        "count": len(policies),
        "policies": {k: v.to_dict() for k, v in policies.items()},
    }


@app.delete("/api/policies/{origin:path}")
async def delete_policy(origin: str) -> dict:
    """Invalidate a cached policy for the given origin."""
    removed = await state.policy_cache.delete(origin)
    if removed:
        logger.info("Policy deleted: %s", origin)
        return {"status": "deleted", "origin": origin}
    return {"status": "not_found", "origin": origin}


# ---------------------------------------------------------------------------
# REST — /api/entropy-summary
# ---------------------------------------------------------------------------


@app.get("/api/entropy-summary", response_model=EntropySummaryResponse)
async def get_entropy_summary() -> dict:
    """Return entropy reduction summary across all known APIs."""
    # Build a synthetic response set from known API entropy values.
    api_responses = {api: None for api in API_ENTROPY_BITS}
    return entropy_reduction_summary(api_responses)


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    """Display a startup banner in the console."""
    banner = f"""
    +====================================================+
    |   Adaptive Privacy Observatory  --  Backend v{__version__}  |
    |----------------------------------------------------|
    |  WebSocket  /ws/telemetry   (extension events)     |
    |  WebSocket  /ws/dashboard   (live dashboard)       |
    |  REST       /api/health     (health probe)         |
    |  REST       /api/status     (server status)        |
    |  REST       /api/policies   (policy cache)         |
    |  REST       /api/entropy-summary                   |
    |  Dashboard  /dashboard      (real-time UI)         |
    +====================================================+
    """
    print(banner)


# ---------------------------------------------------------------------------
# Direct execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level=settings.log_level,
    )
