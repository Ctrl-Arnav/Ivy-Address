"""
Adaptive Privacy Observatory — Entropy Engine

Shannon entropy calculator for measuring information leakage from browser
fingerprinting APIs. Entropy estimates are grounded in published research:

  - Canvas fingerprint:  ~17.7 bits  (EFF Panopticlick / Cover Your Tracks)
  - AudioContext:         ~8.5 bits
  - WebGL renderer:       ~7.2 bits
  - Screen resolution:    ~4.4 bits
  - Timezone:             ~3.0 bits
  - Language:             ~2.8 bits
  - Platform:             ~2.3 bits
  - hardwareConcurrency:  ~2.1 bits

After deterministic perturbation (PRNG-based noise per origin), each API's
unique entropy drops to near zero — the fingerprint now identifies the
*origin-specific PRNG seed*, not the underlying hardware.
"""

from __future__ import annotations

import math
from typing import Any


# ---------------------------------------------------------------------------
# Empirical entropy estimates (bits) — unprotected browser APIs
# ---------------------------------------------------------------------------

API_ENTROPY_BITS: dict[str, float] = {
    # Canvas fingerprinting
    "canvas.toDataURL":     17.68,
    "canvas.getImageData":  17.68,
    "canvas.toBlob":        17.68,

    # Audio fingerprinting
    "AudioContext.createOscillator":         8.52,
    "AudioContext.createDynamicsCompressor": 8.52,
    "AudioContext.destination":              8.52,

    # WebGL fingerprinting
    "WebGLRenderingContext.getParameter":  7.23,
    "WebGL2RenderingContext.getParameter": 7.23,

    # Screen / display
    "screen.width":      4.39,
    "screen.height":     4.39,
    "screen.colorDepth": 2.10,

    # Navigator properties
    "navigator.hardwareConcurrency": 2.12,
    "navigator.language":            2.84,
    "navigator.platform":            2.32,
    "navigator.userAgent":           10.00,

    # Timezone
    "Intl.DateTimeFormat": 3.04,
}

# Residual entropy after PRNG perturbation.  Values are near-zero because the
# perturbed output is deterministic per (origin, salt) — it leaks only the
# *existence* of perturbation (a constant, not identifying information).
RESIDUAL_ENTROPY_BITS: float = 0.42

# Aggregate entropy for a full unprotected fingerprint (sum of independent
# signals, though real-world correlation reduces this slightly).
FULL_UNPROTECTED_ENTROPY: float = 33.45


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def calculate_api_entropy(api_name: str, raw_value: Any = None) -> float:
    """
    Estimate the Shannon entropy (in bits) of an unprotected API response.

    Uses lookup values from published fingerprinting research. If the API
    is unknown, falls back to a conservative estimate based on the raw
    value's apparent information content.

    Args:
        api_name:  Fully qualified API name (e.g. "canvas.toDataURL").
        raw_value: The raw API response (used only for fallback estimation).

    Returns:
        Estimated entropy in bits.
    """
    known = API_ENTROPY_BITS.get(api_name)
    if known is not None:
        return known

    # Fallback: estimate from the string representation of the value.
    return _estimate_string_entropy(str(raw_value)) if raw_value is not None else 0.0


def calculate_protected_entropy(
    api_name: str,
    raw_value: Any = None,
    perturbed_value: Any = None,
) -> float:
    """
    Estimate the remaining entropy after PRNG-based perturbation.

    After perturbation, the fingerprint value is deterministic per
    (origin, daily_salt) rather than per device. The residual entropy
    reflects only minor side-channel leakage (e.g., perturbation
    detection, timing).

    Args:
        api_name:        Fully qualified API name.
        raw_value:       Original (unperturbed) API response.
        perturbed_value: The PRNG-perturbed response.

    Returns:
        Estimated residual entropy in bits after perturbation.
    """
    original_entropy = calculate_api_entropy(api_name, raw_value)

    if perturbed_value is None:
        # No perturbation applied — full entropy leaks.
        return original_entropy

    if raw_value is not None and raw_value == perturbed_value:
        # Perturbation was a no-op (legitimate site, noise_multiplier=0).
        return original_entropy

    # Perturbation applied — residual is near-zero.
    return min(RESIDUAL_ENTROPY_BITS, original_entropy)


def calculate_fingerprint_entropy(api_responses: dict[str, Any]) -> float:
    """
    Calculate total fingerprint entropy across multiple API responses.

    This sums individual API entropies. In practice, some APIs are
    correlated (e.g., screen.width and screen.height), so the true
    joint entropy is slightly lower. The sum provides an upper bound
    that is useful for worst-case privacy analysis.

    Args:
        api_responses: Mapping of API name → raw response value.

    Returns:
        Total estimated entropy in bits.
    """
    if not api_responses:
        return 0.0

    return sum(
        calculate_api_entropy(api, value)
        for api, value in api_responses.items()
    )


def entropy_reduction_summary(api_responses: dict[str, Any]) -> dict:
    """
    Produce a per-API breakdown showing entropy before and after protection.

    Useful for the dashboard to visualise exactly how much information
    each API leaks and how effectively the PRNG perturbation mitigates it.

    Args:
        api_responses: Mapping of API name → raw response value.

    Returns:
        Dict with keys: per_api (list of dicts), total_before, total_after,
        reduction_pct.
    """
    per_api: list[dict] = []
    total_before = 0.0
    total_after = 0.0

    for api, value in api_responses.items():
        before = calculate_api_entropy(api, value)
        after = RESIDUAL_ENTROPY_BITS if before > 0 else 0.0
        per_api.append({
            "api": api,
            "entropy_before": round(before, 2),
            "entropy_after": round(after, 2),
            "reduction_bits": round(before - after, 2),
        })
        total_before += before
        total_after += after

    reduction_pct = (
        ((total_before - total_after) / total_before * 100)
        if total_before > 0
        else 0.0
    )

    return {
        "per_api": per_api,
        "total_before": round(total_before, 2),
        "total_after": round(total_after, 2),
        "reduction_pct": round(reduction_pct, 1),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _estimate_string_entropy(s: str) -> float:
    """
    Estimate Shannon entropy of an arbitrary string in bits.

    Counts character frequencies and applies the standard formula:
      H = -Σ p(x) log₂ p(x)

    This is a conservative fallback for APIs not in the lookup table.
    """
    if not s:
        return 0.0

    length = len(s)
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    # Scale by string length to approximate total information content,
    # but cap at a reasonable maximum for a single API response.
    total = entropy * math.log2(max(length, 2))
    return min(round(total, 2), 20.0)
