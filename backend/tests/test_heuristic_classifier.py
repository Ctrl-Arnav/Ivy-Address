"""
Tests for the heuristic classifier.
"""

from __future__ import annotations

import time

import pytest

from heuristic_classifier import HeuristicClassifier
from policy_cache import PolicyEntry


class TestKnownDomains:
    """Rule 1: Known fingerprinting domain detection."""

    def test_known_origin_high_confidence(self, classifier):
        """Origins matching known FP domains → fingerprint classification."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://fingerprintjs.com",
            "timestamp": time.time(),
        })
        assert result.intent == "fingerprint"
        assert result.confidence >= 0.7
        assert "known_fp_domain_origin" in result.signals

    def test_known_script_origin(self, classifier):
        """Third-party script from known FP domain → fingerprint."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://example.com",
            "script_origin": "https://cdn.fingerprintjs.com/agent.js",
            "timestamp": time.time(),
        })
        assert "known_fp_domain_script" in result.signals

    def test_unknown_origin_no_signal(self, classifier):
        """Clean origins should not trigger domain signals."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://clean-site.com",
            "timestamp": time.time(),
        })
        assert "known_fp_domain_origin" not in result.signals


class TestSmallCanvas:
    """Rule 2: Small canvas fingerprint detection."""

    def test_tiny_canvas_read(self, classifier):
        """Very small canvas reads are almost always FP probes."""
        result = classifier.classify({
            "api": "canvas.getImageData",
            "origin": "https://example.com",
            "width": 4,
            "height": 4,
            "timestamp": time.time(),
        })
        assert "small_canvas_read" in result.signals

    def test_normal_canvas_no_signal(self, classifier):
        """Normal-sized canvas should not trigger small canvas signal."""
        result = classifier.classify({
            "api": "canvas.getImageData",
            "origin": "https://example.com",
            "width": 100,
            "height": 100,
            "timestamp": time.time(),
        })
        assert "small_canvas_read" not in result.signals

    def test_no_dimensions_no_signal(self, classifier):
        """Missing dimensions should not trigger small canvas signal."""
        result = classifier.classify({
            "api": "canvas.getImageData",
            "origin": "https://example.com",
            "timestamp": time.time(),
        })
        assert "small_canvas_read" not in result.signals


class TestBurstDetection:
    """Rule 3: Rapid-fire API call detection."""

    def test_burst_triggers_signal(self, classifier):
        """Multiple rapid calls from same origin → burst signal."""
        now = time.time()
        for i in range(5):
            result = classifier.classify({
                "api": "canvas.toDataURL",
                "origin": "https://example.com",
                "timestamp": now + i * 0.01,  # 10ms apart
            })
        assert "rapid_burst_calls" in result.signals

    def test_no_burst_spaced_calls(self, classifier):
        """Slow calls should not trigger burst detection."""
        now = time.time()
        for i in range(3):
            result = classifier.classify({
                "api": "canvas.toDataURL",
                "origin": "https://example.com",
                "timestamp": now + i * 1.0,  # 1s apart
            })
        assert "rapid_burst_calls" not in result.signals


class TestThirdParty:
    """Rule 4: Third-party sensitive API calls."""

    def test_third_party_canvas_suspicious(self, classifier):
        """Third-party script reading canvas → suspicious."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://example.com",
            "script_origin": "https://tracker.ad-network.com",
            "timestamp": time.time(),
        })
        assert "third_party_sensitive_api" in result.signals

    def test_first_party_no_signal(self, classifier):
        """First-party scripts should not trigger third-party signal."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://example.com",
            "script_origin": "https://example.com",
            "timestamp": time.time(),
        })
        assert "third_party_sensitive_api" not in result.signals


class TestWebGLIdentity:
    """Rule 5: WebGL identity parameter queries."""

    def test_renderer_query_detected(self, classifier):
        """WebGL RENDERER queries should be flagged."""
        result = classifier.classify({
            "api": "WebGLRenderingContext.getParameter",
            "origin": "https://example.com",
            "call_stack": "UNMASKED_RENDERER_WEBGL",
            "timestamp": time.time(),
        })
        assert "webgl_identity_query" in result.signals

    def test_non_identity_webgl_no_signal(self, classifier):
        """Non-identity WebGL queries should not be flagged."""
        result = classifier.classify({
            "api": "WebGLRenderingContext.getParameter",
            "origin": "https://example.com",
            "call_stack": "MAX_TEXTURE_SIZE",
            "timestamp": time.time(),
        })
        assert "webgl_identity_query" not in result.signals


class TestLargeCanvasLegitimacy:
    """Rule 6: Large canvas legitimacy boost."""

    def test_large_canvas_boosts_legitimacy(self, classifier):
        """Large canvas with no other signals → legitimate."""
        result = classifier.classify({
            "api": "canvas.getImageData",
            "origin": "https://clean-site.com",
            "width": 1920,
            "height": 1080,
            "timestamp": time.time(),
        })
        assert result.intent == "legitimate"
        assert "large_canvas_legitimate" in result.signals


class TestConfidenceAggregation:
    """Tests for signal aggregation and noise multiplier."""

    def test_no_signals_is_legitimate(self, classifier):
        """No signals → legitimate, no noise."""
        result = classifier.classify({
            "api": "custom.api",
            "origin": "https://clean.com",
            "timestamp": time.time(),
        })
        assert result.intent == "legitimate"
        assert result.noise_multiplier == 0.0

    def test_fingerprint_full_noise(self, classifier):
        """High-confidence fingerprint → noise_multiplier = 1.0."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://fingerprintjs.com",
            "timestamp": time.time(),
        })
        assert result.intent == "fingerprint"
        assert result.noise_multiplier == 1.0

    def test_result_is_policy_entry(self, classifier):
        """classify() should return a PolicyEntry instance."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://example.com",
            "timestamp": time.time(),
        })
        assert isinstance(result, PolicyEntry)
        assert result.source == "heuristic"

    def test_reason_populated(self, classifier):
        """The reason field should always be a non-empty string."""
        result = classifier.classify({
            "api": "canvas.toDataURL",
            "origin": "https://fingerprintjs.com",
            "timestamp": time.time(),
        })
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0


class TestBoundedHistory:
    """Verify that call history is bounded to prevent memory leaks."""

    def test_max_origins_enforced(self):
        """History should not exceed max_origins."""
        classifier = HeuristicClassifier(max_origins=10)
        now = time.time()
        for i in range(50):
            classifier.classify({
                "api": "canvas.toDataURL",
                "origin": f"https://site-{i}.com",
                "timestamp": now + i,
            })
        assert len(classifier._call_history) <= 10
