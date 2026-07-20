// ============================================================================
// Adaptive Privacy Observatory — Content Script (MAIN World)
// Runtime API Interceptor & Deterministic Perturbation Engine  v1.0.0
//
// This script runs in the page's JS context (world: "MAIN") at document_start,
// before any page scripts execute. It overrides high-entropy browser API
// prototypes to inject deterministic, domain-isolated noise into their return
// values, destroying fingerprint stability across sites while preserving
// intra-site consistency.
// ============================================================================

(function () {
  "use strict";

  const LOG_PREFIX = "[Observatory]";
  let ENABLED = true; // Dynamic — updated via settings from background worker

  // Per-origin noise multiplier (0.0–1.0). Updated by backend classifications.
  let noiseMultiplier = 1.0;

  // ========================================================================
  // 1. ORIGINAL API REFERENCES
  // Capture these BEFORE any other script can tamper with them.
  // ========================================================================

  const originals = Object.freeze({
    // Canvas 2D
    getImageData: CanvasRenderingContext2D.prototype.getImageData,
    toDataURL: HTMLCanvasElement.prototype.toDataURL,
    toBlob: HTMLCanvasElement.prototype.toBlob,

    // Audio
    getFloatFrequencyData: AnalyserNode.prototype.getFloatFrequencyData,
    getByteFrequencyData: AnalyserNode.prototype.getByteFrequencyData,
    getChannelData: AudioBuffer.prototype.getChannelData,

    // WebGL (both v1 and v2 share the same prototype chain for getParameter)
    getParameter: WebGLRenderingContext.prototype.getParameter,
    getParameter2: typeof WebGL2RenderingContext !== "undefined"
      ? WebGL2RenderingContext.prototype.getParameter
      : null,

    // Navigator — capture original descriptors for spoofing
    navigatorProto: Object.getOwnPropertyDescriptors(Navigator.prototype),

    // ClientRects
    getBoundingClientRect: Element.prototype.getBoundingClientRect,
    getClientRects: Element.prototype.getClientRects,

    // Utilities
    createElement: document.createElement.bind(document),
    getContext: HTMLCanvasElement.prototype.getContext,
  });

  // ========================================================================
  // 2. PRNG — Xoshiro128** (32-bit, fast, statistically excellent)
  // ========================================================================

  class Xoshiro128StarStar {
    /**
     * @param {number} s0 - First 32-bit state word
     * @param {number} s1 - Second 32-bit state word
     * @param {number} s2 - Third 32-bit state word
     * @param {number} s3 - Fourth 32-bit state word
     */
    constructor(s0, s1, s2, s3) {
      this.s = new Uint32Array([s0, s1, s2, s3]);
    }

    /** Rotate left (32-bit unsigned) */
    static rotl(x, k) {
      return ((x << k) | (x >>> (32 - k))) >>> 0;
    }

    /** Generate next 32-bit unsigned integer */
    next() {
      const s = this.s;
      const result = (Math.imul(Xoshiro128StarStar.rotl(Math.imul(s[1], 5), 7), 9)) >>> 0;

      const t = (s[1] << 9) >>> 0;

      s[2] = (s[2] ^ s[0]) >>> 0;
      s[3] = (s[3] ^ s[1]) >>> 0;
      s[1] = (s[1] ^ s[2]) >>> 0;
      s[0] = (s[0] ^ s[3]) >>> 0;

      s[2] = (s[2] ^ t) >>> 0;
      s[3] = Xoshiro128StarStar.rotl(s[3], 11);

      return result;
    }

    /** Generate float in [0, 1) */
    nextFloat() {
      return this.next() / 4294967296;
    }

    /** Create a fresh copy of this PRNG at its current state */
    clone() {
      return new Xoshiro128StarStar(this.s[0], this.s[1], this.s[2], this.s[3]);
    }
  }

  // ========================================================================
  // 3. SEED GENERATOR — Domain-isolated deterministic seeding
  //
  // Seed = SplitMix32-expand( hash(origin + "|" + dailySalt) )
  //
  // Synchronous so hooks work immediately at document_start.
  // ========================================================================

  /**
   * Fast 32-bit string hash (cyrb53-derived, single pass).
   * Not cryptographic — we only need good distribution for PRNG seeding.
   */
  function hashString(str) {
    let h1 = 0xdeadbeef >>> 0;
    let h2 = 0x41c6ce57 >>> 0;
    for (let i = 0; i < str.length; i++) {
      const ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 0x85ebca77);
      h2 = Math.imul(h2 ^ ch, 0xc2b2ae3d);
    }
    h1 ^= Math.imul(h1 ^ (h2 >>> 15), 0x735a2d97);
    h2 ^= Math.imul(h2 ^ (h1 >>> 15), 0xcaf649a9);
    h1 = (h1 ^ (h2 >>> 16)) >>> 0;
    return h1;
  }

  /**
   * SplitMix32 — expands a single 32-bit seed into a sequence of values.
   * Standard approach for seeding Xoshiro from a single integer.
   */
  function splitmix32(seed) {
    seed = seed >>> 0;
    const values = new Uint32Array(4);
    for (let i = 0; i < 4; i++) {
      seed = (seed + 0x9e3779b9) >>> 0;
      let t = seed ^ (seed >>> 16);
      t = Math.imul(t, 0x21f0aaad);
      t = (t ^ (t >>> 15)) >>> 0;
      t = Math.imul(t, 0x735a2d97);
      t = (t ^ (t >>> 15)) >>> 0;
      values[i] = t;
    }
    return values;
  }

  /**
   * Get today's date string for the daily salt rotation.
   * Fingerprints rotate every 24 hours — long enough to avoid anomaly detection
   * within a session, short enough to limit long-term tracking.
   */
  function getDailySalt() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  }

  /** Cache of PRNG instances keyed by origin, so we don't re-seed every call. */
  const prngCache = new Map();

  /**
   * Get (or create) a deterministic PRNG for the given origin.
   * Each origin gets a unique, reproducible random stream.
   */
  function getPRNG(origin) {
    if (prngCache.has(origin)) {
      return prngCache.get(origin);
    }
    const seedString = origin + "|" + getDailySalt();
    const seedHash = hashString(seedString);
    const expanded = splitmix32(seedHash);
    const prng = new Xoshiro128StarStar(expanded[0], expanded[1], expanded[2], expanded[3]);
    prngCache.set(origin, prng);
    return prng;
  }

  // Current page origin — computed once at startup
  const PAGE_ORIGIN = location.origin || location.hostname || "unknown";
  const pagePRNG = getPRNG(PAGE_ORIGIN);

  // ========================================================================
  // 4. PERTURBATION ENGINE
  // ========================================================================

  /**
   * Check if perturbation should be applied based on ENABLED state
   * and noise multiplier.
   */
  function shouldPerturb() {
    return ENABLED && noiseMultiplier > 0;
  }

  /**
   * Apply deterministic LSB perturbation to pixel data (Uint8ClampedArray).
   * Flips the least significant bit of each RGB channel based on the PRNG stream.
   * Alpha channel is left untouched to avoid transparency artifacts.
   *
   * Uses batched PRNG reads: one 32-bit PRNG output provides 32 bits of noise,
   * enough for 32 pixel components — roughly 10 pixels.
   *
   * @param {Uint8ClampedArray} data - The pixel data array (RGBA, 4 bytes/pixel)
   * @param {Xoshiro128StarStar} prng - A cloned PRNG instance
   */
  function perturbPixelData(data, prng) {
    const len = data.length;
    let bits = 0;
    let bitPos = 32; // Force initial fetch

    for (let i = 0; i < len; i++) {
      // Skip alpha channel (every 4th byte starting at index 3)
      if ((i & 3) === 3) continue;

      if (bitPos >= 32) {
        bits = prng.next();
        bitPos = 0;
      }

      // Apply noise based on multiplier — at full noise, always flip LSB.
      // At reduced noise, probabilistically skip some perturbations.
      if (noiseMultiplier >= 1.0 || prng.nextFloat() < noiseMultiplier) {
        data[i] = data[i] ^ ((bits >>> bitPos) & 1);
      }
      bitPos++;
    }
  }

  /**
   * Apply deterministic noise to audio frequency/sample data (Float32Array).
   * Adds tiny floating-point perturbations (< 1e-7 magnitude) that are
   * inaudible but change the resulting hash.
   *
   * @param {Float32Array} data - Audio sample or frequency data
   * @param {Xoshiro128StarStar} prng - A cloned PRNG instance
   */
  function perturbAudioData(data, prng) {
    const len = data.length;
    for (let i = 0; i < len; i++) {
      // Generate a tiny perturbation: [-5e-8, +5e-8]
      // This is well below audible threshold but breaks fingerprint hashes
      const noise = (prng.nextFloat() - 0.5) * 1e-7 * noiseMultiplier;
      data[i] += noise;
    }
  }

  /**
   * Apply deterministic noise to byte-valued audio data (Uint8Array).
   * Flips LSB similar to pixel perturbation.
   *
   * @param {Uint8Array} data - Byte frequency data
   * @param {Xoshiro128StarStar} prng - A cloned PRNG instance
   */
  function perturbByteAudioData(data, prng) {
    const len = data.length;
    let bits = 0;
    let bitPos = 32;

    for (let i = 0; i < len; i++) {
      if (bitPos >= 32) {
        bits = prng.next();
        bitPos = 0;
      }
      if (noiseMultiplier >= 1.0 || prng.nextFloat() < noiseMultiplier) {
        data[i] = data[i] ^ ((bits >>> bitPos) & 1);
      }
      bitPos++;
    }
  }

  /**
   * Perturb a DOMRect by adding tiny deterministic offsets.
   * This defeats ClientRects-based fingerprinting while keeping
   * the values visually identical.
   */
  function perturbDOMRect(rect, prng) {
    const noise = () => (prng.nextFloat() - 0.5) * 0.001 * noiseMultiplier;
    return new DOMRect(
      rect.x + noise(),
      rect.y + noise(),
      rect.width + noise(),
      rect.height + noise()
    );
  }

  // ========================================================================
  // 5. TELEMETRY BRIDGE — MAIN world → ISOLATED world (injector.js)
  //
  // Since MAIN world scripts can't use chrome.* APIs, we relay telemetry
  // to the injector.js (ISOLATED world) via window.postMessage. The
  // injector then forwards it over WebSocket to the backend.
  // ========================================================================

  const MESSAGE_CHANNEL = "observatory-telemetry";

  const telemetry = {
    interceptCount: 0,
    apiCalls: [],

    /** Record an API interception event and relay to the backend via injector */
    record(apiName, context) {
      this.interceptCount++;

      const event = {
        api: apiName,
        origin: PAGE_ORIGIN,
        timestamp: Date.now(),
        intercept_id: this.interceptCount,
        ...context,
      };

      this.apiCalls.push(event);

      // Keep only the last 200 events in local memory
      if (this.apiCalls.length > 200) {
        this.apiCalls.shift();
      }

      // Post to ISOLATED world for backend relay
      try {
        window.postMessage(
          {
            channel: MESSAGE_CHANNEL,
            type: "telemetry",
            payload: event,
          },
          "*"
        );
      } catch (e) {
        // postMessage can fail in rare edge cases (e.g., detached frames)
      }
    },
  };

  /**
   * Listen for classification responses from the backend (relayed via injector).
   * These update the local policy for whether to apply noise or not.
   */
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const msg = event.data;
    if (!msg || msg.channel !== MESSAGE_CHANNEL) return;

    if (msg.type === "classification") {
      const response = msg.payload;
      if (response && typeof response.noise_multiplier === "number") {
        noiseMultiplier = response.noise_multiplier;
        console.debug(
          `${LOG_PREFIX} Classification received: ${response.classification?.intent || "unknown"} ` +
          `(noise: ${noiseMultiplier.toFixed(2)}, entropy: ${response.entropy_before?.toFixed(1)}→${response.entropy_after?.toFixed(1)} bits)`
        );
      }
    }

    if (msg.type === "settings-update") {
      // Settings pushed from injector (originally from background worker).
      if (typeof msg.enabled === "boolean") {
        ENABLED = msg.enabled;
        console.debug(`${LOG_PREFIX} Protection ${ENABLED ? "enabled" : "disabled"}`);
      }
    }
  });

  // ========================================================================
  // 6. CANVAS HOOKS
  // ========================================================================

  // --- getImageData ---
  CanvasRenderingContext2D.prototype.getImageData = function (x, y, w, h, settings) {
    const imageData = originals.getImageData.call(this, x, y, w, h, settings);
    if (!shouldPerturb()) return imageData;

    // Clone the PRNG so repeated calls with the same origin produce the same
    // perturbation pattern (deterministic per-domain, not per-call)
    const prng = pagePRNG.clone();
    perturbPixelData(imageData.data, prng);

    telemetry.record("canvas.getImageData", { width: w, height: h });
    return imageData;
  };

  // --- toDataURL ---
  HTMLCanvasElement.prototype.toDataURL = function (type, quality) {
    if (!shouldPerturb()) return originals.toDataURL.call(this, type, quality);

    // Strategy: create an offscreen clone, perturb it, serialize the clone.
    // This avoids modifying the visible canvas.
    const clone = originals.createElement("canvas");
    clone.width = this.width;
    clone.height = this.height;
    const ctx = originals.getContext.call(clone, "2d");
    ctx.drawImage(this, 0, 0);

    const imageData = originals.getImageData.call(ctx, 0, 0, clone.width, clone.height);
    const prng = pagePRNG.clone();
    perturbPixelData(imageData.data, prng);
    ctx.putImageData(imageData, 0, 0);

    telemetry.record("canvas.toDataURL", { width: this.width, height: this.height });
    return originals.toDataURL.call(clone, type, quality);
  };

  // --- toBlob ---
  HTMLCanvasElement.prototype.toBlob = function (callback, type, quality) {
    if (!shouldPerturb()) return originals.toBlob.call(this, callback, type, quality);

    const clone = originals.createElement("canvas");
    clone.width = this.width;
    clone.height = this.height;
    const ctx = originals.getContext.call(clone, "2d");
    ctx.drawImage(this, 0, 0);

    const imageData = originals.getImageData.call(ctx, 0, 0, clone.width, clone.height);
    const prng = pagePRNG.clone();
    perturbPixelData(imageData.data, prng);
    ctx.putImageData(imageData, 0, 0);

    telemetry.record("canvas.toBlob", { width: this.width, height: this.height });
    return originals.toBlob.call(clone, callback, type, quality);
  };

  // ========================================================================
  // 7. AUDIO HOOKS
  // ========================================================================

  // --- getFloatFrequencyData ---
  AnalyserNode.prototype.getFloatFrequencyData = function (array) {
    originals.getFloatFrequencyData.call(this, array);
    if (!shouldPerturb()) return;

    const prng = pagePRNG.clone();
    perturbAudioData(array, prng);
    telemetry.record("audio.getFloatFrequencyData", { length: array.length });
  };

  // --- getByteFrequencyData ---
  AnalyserNode.prototype.getByteFrequencyData = function (array) {
    originals.getByteFrequencyData.call(this, array);
    if (!shouldPerturb()) return;

    const prng = pagePRNG.clone();
    perturbByteAudioData(array, prng);
    telemetry.record("audio.getByteFrequencyData", { length: array.length });
  };

  // --- getChannelData ---
  AudioBuffer.prototype.getChannelData = function (channel) {
    const data = originals.getChannelData.call(this, channel);
    if (!shouldPerturb()) return data;

    // Return a copy with perturbation so we don't corrupt the actual audio buffer
    const perturbed = new Float32Array(data);
    const prng = pagePRNG.clone();
    perturbAudioData(perturbed, prng);

    telemetry.record("audio.getChannelData", { channel, length: data.length });
    return perturbed;
  };

  // ========================================================================
  // 8. WEBGL HOOKS
  // ========================================================================

  // WebGL parameter constants used for fingerprinting
  const WEBGL_FP_PARAMS = Object.freeze({
    VENDOR: 0x1f00,
    RENDERER: 0x1f01,
    UNMASKED_VENDOR_WEBGL: 0x9245,
    UNMASKED_RENDERER_WEBGL: 0x9246,
  });

  // Pool of realistic GPU renderer strings.
  // The PRNG deterministically selects one per domain.
  const RENDERER_POOL = Object.freeze([
    "ANGLE (Intel, Intel(R) UHD Graphics 630 (0x00003E92), OpenGL 4.5)",
    "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 (0x00001F82), OpenGL 4.5)",
    "ANGLE (AMD, AMD Radeon RX 580 (0x000067DF), OpenGL 4.5)",
    "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics (0x00009A49), OpenGL 4.5)",
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002504), OpenGL 4.5)",
    "ANGLE (AMD, AMD Radeon RX 6600 XT (0x000073FF), OpenGL 4.5)",
    "ANGLE (Intel, Intel(R) UHD Graphics 770 (0x00004680), OpenGL 4.5)",
    "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 (0x00002786), OpenGL 4.5)",
  ]);

  const VENDOR_POOL = Object.freeze([
    "Google Inc. (Intel)",
    "Google Inc. (NVIDIA)",
    "Google Inc. (AMD)",
  ]);

  /**
   * Create a WebGL getParameter hook for a given prototype.
   * Only intercepts fingerprinting-relevant parameters; all other
   * getParameter calls pass through unmodified.
   */
  function createWebGLHook(originalFn) {
    return function (pname) {
      if (!shouldPerturb()) return originalFn.call(this, pname);

      const prng = pagePRNG.clone();

      switch (pname) {
        case WEBGL_FP_PARAMS.UNMASKED_RENDERER_WEBGL:
        case WEBGL_FP_PARAMS.RENDERER: {
          const idx = prng.next() % RENDERER_POOL.length;
          telemetry.record("webgl.getParameter", { param: "RENDERER" });
          return RENDERER_POOL[idx];
        }
        case WEBGL_FP_PARAMS.UNMASKED_VENDOR_WEBGL:
        case WEBGL_FP_PARAMS.VENDOR: {
          const idx = prng.next() % VENDOR_POOL.length;
          telemetry.record("webgl.getParameter", { param: "VENDOR" });
          return VENDOR_POOL[idx];
        }
        default:
          // All non-fingerprinting parameters pass through unmodified
          return originalFn.call(this, pname);
      }
    };
  }

  WebGLRenderingContext.prototype.getParameter = createWebGLHook(originals.getParameter);

  if (originals.getParameter2) {
    WebGL2RenderingContext.prototype.getParameter = createWebGLHook(originals.getParameter2);
  }

  // ========================================================================
  // 9. CLIENTRECTS HOOKS (new in v1.0.0)
  //
  // Element.getBoundingClientRect() and Element.getClientRects() are used
  // by sophisticated fingerprinters to detect font rendering differences.
  // ========================================================================

  Element.prototype.getBoundingClientRect = function () {
    const rect = originals.getBoundingClientRect.call(this);
    if (!shouldPerturb()) return rect;

    const prng = pagePRNG.clone();
    // Advance PRNG based on element tag for diversity.
    for (let i = 0; i < (this.tagName || "").length; i++) prng.next();

    telemetry.record("element.getBoundingClientRect", { tag: this.tagName });
    return perturbDOMRect(rect, prng);
  };

  Element.prototype.getClientRects = function () {
    const rects = originals.getClientRects.call(this);
    if (!shouldPerturb()) return rects;

    const prng = pagePRNG.clone();
    for (let i = 0; i < (this.tagName || "").length; i++) prng.next();

    const perturbed = [];
    for (let i = 0; i < rects.length; i++) {
      perturbed.push(perturbDOMRect(rects[i], prng));
    }

    telemetry.record("element.getClientRects", { tag: this.tagName, count: rects.length });

    // Return a DOMRectList-like object.
    perturbed.item = function (index) { return this[index] || null; };
    return perturbed;
  };

  // ========================================================================
  // 10. NAVIGATOR PROPERTY HOOKS (new in v1.0.0)
  //
  // Spoof navigator.hardwareConcurrency and navigator.deviceMemory to
  // prevent hardware-based fingerprinting.
  // ========================================================================

  try {
    const prng = pagePRNG.clone();

    // hardwareConcurrency: report a common value (4 or 8)
    const commonCores = [4, 8, 8, 12, 16];
    const spoofedCores = commonCores[prng.next() % commonCores.length];

    Object.defineProperty(Navigator.prototype, "hardwareConcurrency", {
      get() {
        if (!shouldPerturb()) {
          return originals.navigatorProto.hardwareConcurrency?.get?.call(this) ?? 4;
        }
        telemetry.record("navigator.hardwareConcurrency", { spoofed: spoofedCores });
        return spoofedCores;
      },
      configurable: true,
    });

    // deviceMemory: report a common value (4 or 8 GB)
    if ("deviceMemory" in navigator) {
      const commonMemory = [4, 8, 8, 16];
      const spoofedMemory = commonMemory[prng.next() % commonMemory.length];

      Object.defineProperty(Navigator.prototype, "deviceMemory", {
        get() {
          if (!shouldPerturb()) {
            return originals.navigatorProto.deviceMemory?.get?.call(this) ?? 8;
          }
          telemetry.record("navigator.deviceMemory", { spoofed: spoofedMemory });
          return spoofedMemory;
        },
        configurable: true,
      });
    }
  } catch (e) {
    // Some browsers may not support these — fail silently.
  }

  // ========================================================================
  // 11. INITIALIZATION
  // ========================================================================

  console.log(
    `%c${LOG_PREFIX} Adaptive Privacy Observatory v1.0.0 active`,
    "color: #00e5ff; font-weight: bold; font-size: 13px;"
  );
  console.log(
    `%c${LOG_PREFIX} Domain seed: ${PAGE_ORIGIN} | Salt: ${getDailySalt()}`,
    "color: #b0bec5;"
  );
  console.log(
    `%c${LOG_PREFIX} Hooks installed: Canvas, Audio, WebGL, ClientRects, Navigator`,
    "color: #b0bec5;"
  );

  // Expose a minimal global API for debugging and integration
  Object.defineProperty(window, "__PRIVACY_OBSERVATORY__", {
    value: Object.freeze({
      version: "1.0.0",
      get enabled() { return ENABLED; },
      origin: PAGE_ORIGIN,
      salt: getDailySalt(),
      get noiseMultiplier() { return noiseMultiplier; },
      telemetry: telemetry,
    }),
    writable: false,
    configurable: false,
  });
})();
