"""
Adaptive Privacy Observatory — Data Models

Pydantic models for request validation and response serialization across
REST endpoints and WebSocket messages.
"""

from __future__ import annotations

import time
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Inbound — telemetry from the browser extension
# ---------------------------------------------------------------------------


class TelemetryEvent(BaseModel):
    """A single API interception event sent by the browser extension."""

    api: str = Field(..., min_length=1, description="Intercepted API name")
    origin: str = Field(..., min_length=1, description="Page origin")
    timestamp: float = Field(
        default_factory=time.time,
        description="Event timestamp (epoch seconds or millis)",
    )
    width: Optional[int] = Field(None, ge=0, description="Canvas width in px")
    height: Optional[int] = Field(None, ge=0, description="Canvas height in px")
    call_stack: Optional[str] = Field(None, description="Truncated call stack")
    script_origin: Optional[str] = Field(None, description="Origin of calling script")
    raw_value: Optional[Any] = Field(None, description="Raw API response value")
    intercept_id: Optional[int] = Field(None, description="Extension-local counter")

    model_config = ConfigDict(extra="allow")


class ScriptSourceEvent(BaseModel):
    """Third-party script source captured by the injector."""

    url: str
    origin: Optional[str] = None
    page_origin: Optional[str] = None
    source_length: int = 0
    source_text: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)


class WebSocketEnvelope(BaseModel):
    """Envelope wrapping messages from the browser extension."""

    type: Literal["telemetry", "script_source"] = "telemetry"
    payload: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Outbound — classification responses
# ---------------------------------------------------------------------------


class ClassificationResponse(BaseModel):
    """Response sent back to the extension after classifying a telemetry event."""

    action: Literal["perturb", "allow"]
    noise_multiplier: float = Field(ge=0.0, le=1.0)
    entropy_before: float
    entropy_after: float
    classification: dict


class ScriptSourceAck(BaseModel):
    """Acknowledgment for a received script source."""

    type: str = "script_source_ack"
    url: str
    status: str = "queued"


# ---------------------------------------------------------------------------
# REST responses
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    """Minimal health-check response."""

    status: Literal["ok"] = "ok"
    version: str


class StatusResponse(BaseModel):
    """Detailed server status and aggregate statistics."""

    status: str = "running"
    version: str
    uptime_seconds: float
    total_intercepts: int
    cache_size: int
    cache_stats: dict = {}
    dashboard_clients: int


class PolicyResponse(BaseModel):
    """Full policy cache dump."""

    count: int
    policies: dict[str, dict]


class EntropySummaryResponse(BaseModel):
    """Entropy reduction summary across known APIs."""

    per_api: list[dict]
    total_before: float
    total_after: float
    reduction_pct: float
