"""
Adaptive Privacy Observatory — Heuristic Classifier

Fast rule-based intent classifier that provides instant fingerprinting
decisions before the (slower) AI analyzer completes. Runs synchronously
and is designed for sub-millisecond latency on every telemetry event.

Each rule inspects a single facet of the telemetry and appends a weighted
signal. Signals are then aggregated into a final classification:
  - fingerprint  (confidence ≥ 0.7)
  - unknown      (0.3 ≤ confidence < 0.7)
  - legitimate   (confidence < 0.3)
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

from policy_cache import PolicyEntry


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Origins known to serve fingerprinting scripts.
KNOWN_FINGERPRINT_DOMAINS: frozenset[str] = frozenset({
    "fingerprintjs.com",
    "cdn.fingerprintjs.com",
    "fpjs.io",
    "api.fpjs.io",
    "openfpcdn.io",
    "cdn.jsdelivr.net",  # Common CDN host for fp libraries
})

# Canvas sizes below this threshold are almost certainly fingerprint probes
# (real rendering needs at least a visible area).
SMALL_CANVAS_THRESHOLD: int = 16

# Canvas sizes above this are likely legitimate drawing operations.
LARGE_CANVAS_THRESHOLD: int = 256

# Burst detection: more than this many calls within the window → fingerprint.
BURST_CALL_COUNT: int = 3
BURST_WINDOW_MS: float = 100.0

# APIs that are commonly abused for fingerprinting.
FINGERPRINT_APIS: frozenset[str] = frozenset({
    "canvas.toDataURL",
    "canvas.getImageData",
    "canvas.toBlob",
    "OffscreenCanvas.toDataURL",
    "AudioContext.createOscillator",
    "AudioContext.createDynamicsCompressor",
    "AudioContext.destination",
    "WebGLRenderingContext.getParameter",
    "WebGL2RenderingContext.getParameter",
    "navigator.hardwareConcurrency",
    "screen.colorDepth",
})

# WebGL parameters that leak GPU identity.
WEBGL_IDENTITY_PARAMS: frozenset[str] = frozenset({
    "RENDERER",
    "VENDOR",
    "UNMASKED_RENDERER_WEBGL",
    "UNMASKED_VENDOR_WEBGL",
})


# ---------------------------------------------------------------------------
# Internal signal accumulator
# ---------------------------------------------------------------------------


@dataclass
class _Signal:
    """A single heuristic signal with a name and a weight (0–1)."""
    name: str
    weight: float


# ---------------------------------------------------------------------------
# Heuristic Classifier
# ---------------------------------------------------------------------------


class HeuristicClassifier:
    """
    Evaluate telemetry events against a set of hand-written rules and produce
    an instant classification. Maintains a short history of recent calls per
    origin so it can detect rapid-fire burst patterns.
    """

    def __init__(self) -> None:
        # Recent call timestamps per origin, used for burst detection.
        # Maps origin → list of timestamps (seconds).
        self._call_history: dict[str, list[float]] = defaultdict(list)

    # ----- public interface ------------------------------------------------

    def classify(self, telemetry: dict) -> PolicyEntry:
        """
        Classify a single telemetry event.

        Args:
            telemetry: Dict with keys:
                api (str):             API that was intercepted
                origin (str):          Page origin
                width (int, optional): Canvas width in px
                height (int, optional): Canvas height in px
                timestamp (float):     Event timestamp (epoch seconds)
                call_stack (str, optional): Truncated call stack
                script_origin (str, optional): Origin of the calling script

        Returns:
            A PolicyEntry with the classification result.
        """
        api: str = telemetry.get("api", "")
        origin: str = telemetry.get("origin", "unknown")
        width: int | None = telemetry.get("width")
        height: int | None = telemetry.get("height")
        ts: float = telemetry.get("timestamp", time.time())
        script_origin: str | None = telemetry.get("script_origin")

        signals: list[_Signal] = []

        # --- Rule 1: Known fingerprinting domains -------------------------
        signals.extend(self._check_known_domains(origin, script_origin))

        # --- Rule 2: Small canvas reads (< 16×16) -------------------------
        signals.extend(self._check_small_canvas(api, width, height))

        # --- Rule 3: Rapid sequential calls (burst detection) --------------
        signals.extend(self._check_burst(origin, ts))

        # --- Rule 4: Third-party script doing sensitive reads --------------
        signals.extend(self._check_third_party(api, origin, script_origin))

        # --- Rule 5: WebGL identity queries --------------------------------
        signals.extend(self._check_webgl_identity(api, telemetry))

        # --- Rule 6: Large canvas with no other signals → legitimate -------
        legitimacy_boost = self._check_large_canvas(api, width, height, signals)

        # Aggregate signals into a confidence score.
        if not signals:
            confidence = 0.0
        else:
            # Weighted average, clamped to [0, 1].
            total_weight = sum(s.weight for s in signals)
            confidence = min(total_weight / max(len(signals), 1), 1.0)

        # Apply legitimacy boost (pulls confidence toward 0).
        if legitimacy_boost:
            confidence *= 0.3

        intent = self._intent_from_confidence(confidence)
        noise_multiplier = self._noise_for_intent(intent, confidence)
        signal_names = [s.name for s in signals]
        if legitimacy_boost:
            signal_names.append("large_canvas_legitimate")

        reason = self._build_reason(intent, signal_names)

        return PolicyEntry(
            origin=origin,
            intent=intent,
            confidence=round(confidence, 4),
            reason=reason,
            signals=signal_names,
            source="heuristic",
            noise_multiplier=round(noise_multiplier, 4),
            timestamp=time.time(),
        )

    # ----- individual rule checkers ----------------------------------------

    def _check_known_domains(
        self, origin: str, script_origin: str | None,
    ) -> list[_Signal]:
        """Flag origins or script sources matching known fingerprinting domains."""
        signals: list[_Signal] = []
        for domain in KNOWN_FINGERPRINT_DOMAINS:
            if domain in origin:
                signals.append(_Signal("known_fp_domain_origin", 0.95))
            if script_origin and domain in script_origin:
                signals.append(_Signal("known_fp_domain_script", 0.95))
        return signals

    def _check_small_canvas(
        self, api: str, width: int | None, height: int | None,
    ) -> list[_Signal]:
        """Small canvas reads are almost always fingerprint probes."""
        if width is None or height is None:
            return []
        is_canvas_api = any(
            kw in api for kw in ("canvas", "Canvas", "toDataURL", "getImageData")
        )
        if is_canvas_api and width < SMALL_CANVAS_THRESHOLD and height < SMALL_CANVAS_THRESHOLD:
            return [_Signal("small_canvas_read", 0.90)]
        return []

    def _check_burst(self, origin: str, ts: float) -> list[_Signal]:
        """Detect rapid-fire API calls from the same origin."""
        history = self._call_history[origin]
        history.append(ts)

        # Trim old entries (keep only the last second for memory).
        cutoff = ts - 1.0
        self._call_history[origin] = [t for t in history if t >= cutoff]
        history = self._call_history[origin]

        # Count calls within the burst window.
        window_start = ts - (BURST_WINDOW_MS / 1000.0)
        recent = [t for t in history if t >= window_start]

        if len(recent) > BURST_CALL_COUNT:
            return [_Signal("rapid_burst_calls", 0.80)]
        return []

    def _check_third_party(
        self, api: str, origin: str, script_origin: str | None,
    ) -> list[_Signal]:
        """Third-party scripts performing sensitive API calls are suspicious."""
        if script_origin is None or script_origin == origin:
            return []
        is_sensitive = api in FINGERPRINT_APIS or any(
            kw in api for kw in ("canvas", "Canvas", "Audio", "WebGL")
        )
        if is_sensitive:
            return [_Signal("third_party_sensitive_api", 0.65)]
        return []

    def _check_webgl_identity(
        self, api: str, telemetry: dict,
    ) -> list[_Signal]:
        """WebGL renderer/vendor queries leak GPU identity."""
        if "WebGL" not in api and "webgl" not in api:
            return []
        # Check if the call stack or additional data mentions identity params.
        call_stack = telemetry.get("call_stack", "")
        raw = f"{api} {call_stack}"
        for param in WEBGL_IDENTITY_PARAMS:
            if param in raw:
                return [_Signal("webgl_identity_query", 0.55)]
        return []

    def _check_large_canvas(
        self,
        api: str,
        width: int | None,
        height: int | None,
        existing_signals: list[_Signal],
    ) -> bool:
        """
        Large canvas operations with no other fingerprint signals
        are most likely legitimate drawing (games, charts, etc.).
        Returns True if a legitimacy boost should be applied.
        """
        if width is None or height is None:
            return False
        is_canvas_api = any(
            kw in api for kw in ("canvas", "Canvas", "toDataURL", "getImageData")
        )
        if not is_canvas_api:
            return False
        if width > LARGE_CANVAS_THRESHOLD and height > LARGE_CANVAS_THRESHOLD:
            # Only boost if no strong fingerprint signals already exist.
            strong = [s for s in existing_signals if s.weight >= 0.7]
            return len(strong) == 0
        return False

    # ----- helpers ---------------------------------------------------------

    @staticmethod
    def _intent_from_confidence(confidence: float) -> str:
        """Map aggregate confidence to an intent label."""
        if confidence >= 0.7:
            return "fingerprint"
        if confidence >= 0.3:
            return "unknown"
        return "legitimate"

    @staticmethod
    def _noise_for_intent(intent: str, confidence: float) -> float:
        """
        Determine the noise multiplier.

        Fingerprint → full noise (1.0).
        Unknown → proportional noise based on confidence.
        Legitimate → no noise (0.0).
        """
        if intent == "fingerprint":
            return 1.0
        if intent == "unknown":
            # Scale linearly between 0.3 and 0.7 confidence.
            return round(min(max((confidence - 0.3) / 0.4, 0.0), 1.0), 4)
        return 0.0

    @staticmethod
    def _build_reason(intent: str, signal_names: list[str]) -> str:
        """Compose a human-readable reason string."""
        if not signal_names:
            return "No fingerprinting signals detected."
        signal_str = ", ".join(signal_names)
        if intent == "fingerprint":
            return f"Classified as fingerprinting based on: {signal_str}."
        if intent == "unknown":
            return f"Suspicious activity detected ({signal_str}), monitoring."
        return f"Likely legitimate despite signals: {signal_str}."
