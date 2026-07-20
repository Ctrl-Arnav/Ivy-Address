"""
Adaptive Privacy Observatory — AI Script Intent Analyzer

Hybrid AST Feature Extractor + Machine Learning Intent Classifier.
Analyzes JavaScript source code captured by the extension injector to detect
fingerprinting intent and estimate class probabilities:
  - fingerprint
  - analytics
  - legitimate

Combines static AST/token feature extraction with a TF-IDF + Logistic Regression
machine learning classifier trained on representative code patterns.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Literal

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from policy_cache import PolicyEntry

logger = logging.getLogger("apo.script_analyzer")


# ---------------------------------------------------------------------------
# AST & Token Feature Patterns
# ---------------------------------------------------------------------------

AST_PATTERNS: dict[str, re.Pattern] = {
    # Canvas fingerprinting code structures
    "ast_canvas_toDataURL": re.compile(r"\b(toDataURL|toBlob)\b"),
    "ast_canvas_getImageData": re.compile(r"\b(getImageData)\b"),
    "ast_canvas_rendering": re.compile(r"\b(fillText|strokeText|fillRect|createLinearGradient)\b"),

    # WebGL GPU & parameter probing
    "ast_webgl_getParameter": re.compile(r"\b(getParameter|getSupportedExtensions)\b"),
    "ast_webgl_identity": re.compile(
        r"\b(UNMASKED_VENDOR_WEBGL|UNMASKED_RENDERER_WEBGL|WEBGL_debug_renderer_info)\b"
    ),

    # AudioContext fingerprinting
    "ast_audio_oscillator": re.compile(r"\b(createOscillator|createDynamicsCompressor)\b"),
    "ast_audio_frequency": re.compile(r"\b(getFloatFrequencyData|getByteFrequencyData|getChannelData)\b"),

    # Font enumeration & DOM measurement loops
    "ast_font_enumeration": re.compile(r"\b(offsetWidth|offsetHeight|getClientRects|getBoundingClientRect)\b"),
    "ast_font_families": re.compile(r"\b(monospace|sans-serif|serif|Courier|Arial|Times New Roman)\b"),

    # Hardware & Navigator property queries
    "ast_navigator_hardware": re.compile(r"\b(hardwareConcurrency|deviceMemory|maxTouchPoints|platform|cpuClass)\b"),
    "ast_screen_depth": re.compile(r"\b(colorDepth|pixelDepth|availWidth|availHeight)\b"),

    # Obfuscation & anti-analysis signals
    "ast_obfuscation_hex": re.compile(r"(_0x[a-f0-9]{4,}|\\x[0-9a-f]{2}){3,}", re.IGNORECASE),
    "ast_dynamic_eval": re.compile(r"\b(eval|Function\s*\()\b"),
}


# ---------------------------------------------------------------------------
# Training Dataset (Representative Code Snippets)
# ---------------------------------------------------------------------------

# Fingerprinting code training examples
_FP_SAMPLES = [
    """
    function getCanvasFingerprint() {
        var canvas = document.createElement('canvas');
        canvas.width = 200; canvas.height = 50;
        var ctx = canvas.getContext('2d');
        ctx.textBaseline = "top";
        ctx.font = "14px 'Arial'";
        ctx.fillText("Hello, world!", 2, 2);
        return canvas.toDataURL();
    }
    function getWebGL() {
        var gl = canvas.getContext('webgl');
        var debug = gl.getExtension('WEBGL_debug_renderer_info');
        var vendor = gl.getParameter(debug.UNMASKED_VENDOR_WEBGL);
        var renderer = gl.getParameter(debug.UNMASKED_RENDERER_WEBGL);
        return vendor + '~' + renderer;
    }
    """,
    """
    function getAudioFP() {
        var ctx = new (window.AudioContext || window.webkitAudioContext)();
        var osc = ctx.createOscillator();
        var comp = ctx.createDynamicsCompressor();
        osc.type = 'triangle';
        osc.connect(comp);
        comp.connect(ctx.destination);
        var analyser = ctx.createAnalyser();
        var data = new Float32Array(analyser.frequencyBinCount);
        analyser.getFloatFrequencyData(data);
        return data.slice(0, 10).join(',');
    }
    """,
    """
    function getFonts() {
        var fonts = ['monospace', 'sans-serif', 'Courier', 'Arial'];
        var results = [];
        for (var i = 0; i < fonts.length; i++) {
            var span = document.createElement('span');
            span.style.fontFamily = fonts[i];
            span.innerText = "mmmmmmmmmmlli";
            document.body.appendChild(span);
            results.push(span.offsetWidth + 'x' + span.offsetHeight);
            document.body.removeChild(span);
        }
        return results.join(';');
    }
    """,
    """
    function getHardware() {
        return [
            navigator.hardwareConcurrency,
            navigator.deviceMemory,
            navigator.maxTouchPoints,
            screen.colorDepth,
            screen.availWidth,
            screen.availHeight
        ].join('|');
    }
    """,
    """
    var _0x4f12=['canvas','toDataURL','getParameter','UNMASKED_RENDERER_WEBGL'];
    (function(_0x2d8f,_0x4f12){var _0x3b1c=function(_0x1a2b){while(--_0x1a2b){_0x2d8f['push'](_0x2d8f['shift']());}};_0x3b1c(++_0x4f12);}(_0x4f12,0x1f4));
    """,
]

# Analytics code training examples
_ANALYTICS_SAMPLES = [
    """
    (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
    (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
    m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
    })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');
    ga('create', 'UA-XXXXX-Y', 'auto');
    ga('send', 'pageview');
    """,
    """
    window.mixpanel = window.mixpanel || [];
    mixpanel.init("YOUR_TOKEN");
    mixpanel.track("Page View", {"url": window.location.href, "referrer": document.referrer});
    """,
    """
    !function(f,b,e,v,n,t,s){if(f.fbq)return;n=f.fbq=function(){n.callMethod?
    n.callMethod.apply(n,arguments):n.queue.push(arguments)};if(!f._fbq)f._fbq=n;
    n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;
    t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}(window,
    document,'script','https://connect.facebook.net/en_US/fbevents.js');
    fbq('init', '123456789');
    fbq('track', 'PageView');
    """,
]

# Legitimate UI & application code training examples
_LEGIT_SAMPLES = [
    """
    function renderChart(data, container) {
        var width = container.clientWidth;
        var height = container.clientHeight;
        var canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, width, height);
        ctx.beginPath();
        for (var i = 0; i < data.length; i++) {
            var x = (i / data.length) * width;
            var y = height - (data[i] * height);
            ctx.lineTo(x, y);
        }
        ctx.strokeStyle = '#00e5ff';
        ctx.stroke();
    }
    """,
    """
    class UIComponent {
        constructor(element) {
            this.element = element;
            this.bindEvents();
        }
        bindEvents() {
            this.element.addEventListener('click', (e) => {
                this.handleClick(e);
            });
        }
        handleClick(e) {
            e.preventDefault();
            this.element.classList.toggle('active');
        }
    }
    """,
    """
    function debounce(func, wait) {
        var timeout;
        return function() {
            var context = this, args = arguments;
            clearTimeout(timeout);
            timeout = setTimeout(function() {
                func.apply(context, args);
            }, wait);
        };
    }
    """,
]


# ---------------------------------------------------------------------------
# Analysis Result Model
# ---------------------------------------------------------------------------


@dataclass
class ScriptAnalysisResult:
    """Output of the script analyzer."""

    url: str
    origin: str
    intent: Literal["fingerprint", "analytics", "legitimate", "unknown"]
    probabilities: dict[str, float]  # fingerprint, analytics, legitimate
    confidence: float
    detected_signals: list[str]
    noise_multiplier: float
    reason: str

    def to_policy_entry(self) -> PolicyEntry:
        return PolicyEntry(
            origin=self.origin,
            intent="fingerprint" if self.intent == "fingerprint" else ("unknown" if self.intent == "unknown" else "legitimate"),
            confidence=round(self.confidence, 4),
            reason=self.reason,
            signals=self.detected_signals,
            source="ai",
            noise_multiplier=round(self.noise_multiplier, 4),
            timestamp=time.time(),
        )


# ---------------------------------------------------------------------------
# Script Analyzer Engine
# ---------------------------------------------------------------------------


class ScriptAnalyzer:
    """
    Hybrid Machine Learning + AST Feature Extractor for JavaScript source code.
    """

    def __init__(self) -> None:
        self._vectorizer = TfidfVectorizer(
            token_pattern=r"\b[a-zA-Z_]\w*\b",
            ngram_range=(1, 2),
            max_features=500,
        )
        self._classifier = LogisticRegression(max_iter=500, random_state=42)
        self._is_trained = False
        self._train_model()

    def _train_model(self) -> None:
        """Train the TF-IDF + Logistic Regression model on initial dataset."""
        X_text = _FP_SAMPLES + _ANALYTICS_SAMPLES + _LEGIT_SAMPLES
        y_labels = (
            ["fingerprint"] * len(_FP_SAMPLES)
            + ["analytics"] * len(_ANALYTICS_SAMPLES)
            + ["legitimate"] * len(_LEGIT_SAMPLES)
        )

        X_vec = self._vectorizer.fit_transform(X_text)
        self._classifier.fit(X_vec, y_labels)
        self._is_trained = True
        logger.info("ScriptAnalyzer ML model trained on %d samples", len(X_text))

    def analyze(self, url: str, origin: str, source_text: str) -> ScriptAnalysisResult:
        """
        Analyze JavaScript source code text.

        Returns:
            ScriptAnalysisResult with probabilities, signals, and recommended policy.
        """
        if not source_text or len(source_text.strip()) == 0:
            return ScriptAnalysisResult(
                url=url,
                origin=origin,
                intent="legitimate",
                probabilities={"fingerprint": 0.0, "analytics": 0.0, "legitimate": 1.0},
                confidence=0.0,
                detected_signals=[],
                noise_multiplier=0.0,
                reason="Empty script source",
            )

        # Step 1: AST / Token Pattern Matching
        signals: list[str] = []
        for name, pattern in AST_PATTERNS.items():
            if pattern.search(source_text):
                signals.append(name)

        # Step 2: Machine Learning Prediction (TF-IDF + LR)
        vec = self._vectorizer.transform([source_text])
        classes = list(self._classifier.classes_)
        probas = self._classifier.predict_proba(vec)[0]

        prob_dict = {cls: float(np.round(p, 4)) for cls, p in zip(classes, probas)}

        # Ensure all classes are present in prob_dict
        for cls in ("fingerprint", "analytics", "legitimate"):
            if cls not in prob_dict:
                prob_dict[cls] = 0.0

        # Step 3: Hybrid Scoring (Combine ML Probabilities with AST Signal Weights)
        fp_prob = prob_dict.get("fingerprint", 0.0)
        analytics_prob = prob_dict.get("analytics", 0.0)
        legit_prob = prob_dict.get("legitimate", 0.0)

        # Boost FP probability if multiple strong AST signals are present
        strong_ast_count = sum(
            1 for s in signals if s in ("ast_canvas_toDataURL", "ast_webgl_identity", "ast_audio_frequency", "ast_font_enumeration")
        )
        if strong_ast_count >= 2:
            fp_prob = min(1.0, fp_prob + 0.35)
            legit_prob = max(0.0, legit_prob - 0.35)

        # Determine Intent Label
        if fp_prob >= 0.60 or (fp_prob >= 0.40 and strong_ast_count >= 1):
            intent: Literal["fingerprint", "analytics", "legitimate", "unknown"] = "fingerprint"
            confidence = round(fp_prob, 4)
            noise_multiplier = 1.0
        elif analytics_prob >= 0.40 and strong_ast_count == 0 and fp_prob < 0.40:
            intent = "analytics"
            confidence = round(analytics_prob, 4)
            noise_multiplier = 0.25  # Low noise for standard analytics
        elif fp_prob >= 0.35 or len(signals) >= 3:
            intent = "unknown"
            confidence = round(fp_prob, 4)
            noise_multiplier = round(min(max(fp_prob, 0.3), 0.7), 4)
        else:
            intent = "legitimate"
            confidence = round(legit_prob, 4)
            noise_multiplier = 0.0

        reason_signals = ", ".join(signals) if signals else "no strong FP patterns"
        reason = f"AI Classified as {intent} ({prob_dict}) based on AST signals: {reason_signals}."

        logger.info(
            "Analyzed script %s | origin=%s intent=%s probs=%s signals=%s",
            url, origin, intent, prob_dict, signals,
        )

        return ScriptAnalysisResult(
            url=url,
            origin=origin,
            intent=intent,
            probabilities=prob_dict,
            confidence=confidence,
            detected_signals=signals,
            noise_multiplier=noise_multiplier,
            reason=reason,
        )
