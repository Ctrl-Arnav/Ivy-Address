"""
Adaptive Privacy Observatory — Configuration

Centralized settings management using Pydantic BaseSettings.
All values can be overridden via environment variables or a .env file.

Environment variable names are auto-derived from field names with
the ``APO_`` prefix.  For example::

    APO_HOST=0.0.0.0
    APO_PORT=8080
    APO_LOG_LEVEL=debug
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _BACKEND_DIR.parent
_DASHBOARD_DIR = _PROJECT_DIR / "dashboard"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class Settings(BaseSettings):
    """Application-wide configuration with environment variable overrides."""

    model_config = SettingsConfigDict(
        env_prefix="APO_",
        env_file=str(_BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- Server ---------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000
    reload: bool = False
    log_level: Literal["debug", "info", "warning", "error", "critical"] = "info"

    # -- CORS -----------------------------------------------------------------
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
    ]

    # -- Policy cache ---------------------------------------------------------
    cache_ttl_seconds: float = 3600.0       # 1 hour
    cache_max_size: int = 10_000            # LRU eviction threshold

    # -- WebSocket ------------------------------------------------------------
    ws_message_queue_size: int = 100        # Max buffered messages per client
    ws_max_message_bytes: int = 1_048_576   # 1 MB

    # -- Dashboard ------------------------------------------------------------
    dashboard_dir: str = str(_DASHBOARD_DIR)

    # -- Classifier -----------------------------------------------------------
    classifier_burst_call_count: int = 3
    classifier_burst_window_ms: float = 100.0
    classifier_history_max_origins: int = 5_000


# Module-level singleton — import ``settings`` everywhere.
settings = Settings()
