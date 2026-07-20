"""
Tests for the entropy engine module.
"""

from __future__ import annotations

import pytest

from entropy_engine import (
    API_ENTROPY_BITS,
    RESIDUAL_ENTROPY_BITS,
    calculate_api_entropy,
    calculate_fingerprint_entropy,
    calculate_protected_entropy,
    entropy_reduction_summary,
)


class TestCalculateApiEntropy:
    """Tests for the unprotected entropy estimator."""

    def test_known_api_returns_lookup_value(self):
        """Known APIs should return their empirical entropy values."""
        assert calculate_api_entropy("canvas.toDataURL") == 17.68
        assert calculate_api_entropy("navigator.hardwareConcurrency") == 2.12

    def test_unknown_api_with_value_falls_back(self):
        """Unknown APIs with a raw value should use string entropy estimation."""
        result = calculate_api_entropy("custom.api", "some raw data value")
        assert result > 0.0

    def test_unknown_api_without_value_returns_zero(self):
        """Unknown APIs with no value should return 0."""
        assert calculate_api_entropy("unknown.api") == 0.0

    def test_all_known_apis_positive(self):
        """Every API in the lookup should have positive entropy."""
        for api, bits in API_ENTROPY_BITS.items():
            assert bits > 0.0, f"{api} has non-positive entropy"


class TestCalculateProtectedEntropy:
    """Tests for the post-perturbation entropy estimator."""

    def test_no_perturbation_leaks_full_entropy(self):
        """If perturbed_value is None, full entropy should leak."""
        result = calculate_protected_entropy("canvas.toDataURL", "raw_data", None)
        assert result == 17.68

    def test_noop_perturbation_leaks_full_entropy(self):
        """If raw == perturbed, no protection was applied."""
        result = calculate_protected_entropy("canvas.toDataURL", "same", "same")
        assert result == 17.68

    def test_successful_perturbation_reduces_entropy(self):
        """After perturbation, residual entropy should be near zero."""
        result = calculate_protected_entropy("canvas.toDataURL", "raw", "perturbed")
        assert result == RESIDUAL_ENTROPY_BITS
        assert result < 1.0

    def test_unknown_api_perturbation(self):
        """Unknown APIs that get perturbed should also show reduction."""
        result = calculate_protected_entropy("custom.api", "raw", "perturbed")
        # For unknown API with no lookup, entropy_before is 0, so residual is 0.
        assert result >= 0.0


class TestCalculateFingerprintEntropy:
    """Tests for the aggregate fingerprint entropy calculator."""

    def test_empty_responses(self):
        """Empty dict should return 0."""
        assert calculate_fingerprint_entropy({}) == 0.0

    def test_single_api(self):
        """Single API should return its individual entropy."""
        result = calculate_fingerprint_entropy({"canvas.toDataURL": "data"})
        assert result == 17.68

    def test_multiple_apis_sum(self):
        """Multiple APIs should sum their entropies."""
        responses = {
            "canvas.toDataURL": "data",
            "navigator.hardwareConcurrency": 8,
        }
        result = calculate_fingerprint_entropy(responses)
        assert result == pytest.approx(17.68 + 2.12, abs=0.01)


class TestEntropyReductionSummary:
    """Tests for the per-API reduction summary."""

    def test_structure(self):
        """Summary should have the expected keys."""
        responses = {"canvas.toDataURL": "data"}
        summary = entropy_reduction_summary(responses)

        assert "per_api" in summary
        assert "total_before" in summary
        assert "total_after" in summary
        assert "reduction_pct" in summary

    def test_per_api_entries(self):
        """Each per-API entry should have before/after/reduction fields."""
        responses = {"canvas.toDataURL": "data"}
        summary = entropy_reduction_summary(responses)

        assert len(summary["per_api"]) == 1
        entry = summary["per_api"][0]
        assert entry["api"] == "canvas.toDataURL"
        assert entry["entropy_before"] == 17.68
        assert entry["entropy_after"] == RESIDUAL_ENTROPY_BITS
        assert entry["reduction_bits"] == pytest.approx(17.68 - RESIDUAL_ENTROPY_BITS, abs=0.01)

    def test_reduction_percentage(self):
        """Reduction percentage should be high for known APIs."""
        responses = {"canvas.toDataURL": "data"}
        summary = entropy_reduction_summary(responses)
        assert summary["reduction_pct"] > 90.0

    def test_empty_responses(self):
        """Empty responses should produce zero totals."""
        summary = entropy_reduction_summary({})
        assert summary["total_before"] == 0.0
        assert summary["total_after"] == 0.0
        assert summary["reduction_pct"] == 0.0
