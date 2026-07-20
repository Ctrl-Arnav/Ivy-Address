"""
Tests for the AI Script Intent Analyzer module (hybrid AST + ML classifier).
"""

from __future__ import annotations

import pytest

from script_analyzer import ScriptAnalyzer, ScriptAnalysisResult


@pytest.fixture
def analyzer():
    """Provide a fresh ScriptAnalyzer instance."""
    return ScriptAnalyzer()


class TestScriptAnalyzer:
    """Unit tests for ScriptAnalyzer."""

    def test_empty_script_classified_as_legitimate(self, analyzer):
        """Empty script text should return legitimate with 0 confidence."""
        res = analyzer.analyze("https://test.com/empty.js", "https://test.com", "")
        assert res.intent == "legitimate"
        assert res.probabilities["legitimate"] == 1.0
        assert res.noise_multiplier == 0.0

    def test_fingerprint_script_classification(self, analyzer):
        """FingerprintJS-like script should be classified as fingerprint."""
        code = """
        function getFP() {
            var canvas = document.createElement('canvas');
            canvas.width = 200; canvas.height = 50;
            var ctx = canvas.getContext('2d');
            ctx.fillText('fingerprint test', 2, 2);
            var canvasFP = canvas.toDataURL();
            var gl = canvas.getContext('webgl');
            var ext = gl.getExtension('WEBGL_debug_renderer_info');
            var vendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
            var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
            return canvasFP + vendor + renderer;
        }
        """
        res = analyzer.analyze("https://tracker.com/fp.js", "https://tracker.com", code)
        assert res.intent == "fingerprint"
        assert res.probabilities["fingerprint"] > 0.5
        assert res.noise_multiplier == 1.0
        assert "ast_canvas_toDataURL" in res.detected_signals
        assert "ast_webgl_identity" in res.detected_signals

    def test_analytics_script_classification(self, analyzer):
        """Standard Google Analytics-like script should be classified as analytics."""
        code = """
        (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
        (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
        m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
        })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
        ga('create', 'UA-123456-1', 'auto');
        ga('send', 'pageview');
        """
        res = analyzer.analyze("https://google-analytics.com/analytics.js", "https://google-analytics.com", code)
        assert res.intent in ("analytics", "legitimate", "unknown")
        assert res.noise_multiplier < 1.0

    def test_legitimate_chart_script(self, analyzer):
        """Clean UI rendering code should be classified as legitimate."""
        code = """
        function renderGraph(data, container) {
            var width = container.clientWidth;
            var height = container.clientHeight;
            var canvas = document.createElement('canvas');
            canvas.width = width; canvas.height = height;
            var ctx = canvas.getContext('2d');
            ctx.fillRect(0, 0, width, height);
            ctx.beginPath();
            for (var i = 0; i < data.length; i++) {
                ctx.lineTo(i * 10, data[i]);
            }
            ctx.stroke();
        }
        """
        res = analyzer.analyze("https://app.com/chart.js", "https://app.com", code)
        assert res.intent in ("legitimate", "unknown")
        assert res.noise_multiplier <= 0.5

    def test_result_to_policy_entry(self, analyzer):
        """to_policy_entry() should produce a PolicyEntry with source='ai'."""
        code = "var x = 1;"
        res = analyzer.analyze("https://app.com/app.js", "https://app.com", code)
        policy = res.to_policy_entry()
        assert policy.origin == "https://app.com"
        assert policy.source == "ai"
        assert isinstance(policy.noise_multiplier, float)
