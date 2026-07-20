// ============================================================================
// Adaptive Privacy Observatory — Injector Script (ISOLATED World) v1.0.0
//
// Runs in the extension's isolated world alongside content.js (MAIN world).
// Responsibilities:
//   1. WebSocket connection to the local backend (configurable URL)
//   2. Relay telemetry from the MAIN world content script to the backend
//   3. Receive classification decisions from the backend and relay back
//   4. Capture third-party script source text for AI analysis (Phase 3)
//   5. Forward settings changes from background worker to MAIN world
//
// Communication:
//   MAIN world (content.js) <--window.postMessage--> ISOLATED world (injector.js)
//   ISOLATED world (injector.js) <--WebSocket--> Backend (main.py)
//   Background worker <--chrome.runtime.onMessage--> ISOLATED world (injector.js)
// ============================================================================

(function () {
  "use strict";

  const LOG_PREFIX = "[Observatory:Injector]";
  const DEFAULT_WS_URL = "ws://127.0.0.1:8000/ws/telemetry";
  const RECONNECT_BASE_DELAY_MS = 2000;
  const MAX_RECONNECT_ATTEMPTS = 15;
  const MESSAGE_CHANNEL = "observatory-telemetry";

  // ========================================================================
  // 1. WebSocket Connection Manager
  // ========================================================================

  class BackendConnection {
    constructor(url) {
      this.url = url;
      this.ws = null;
      this.connected = false;
      this.reconnectAttempts = 0;
      this.messageQueue = []; // Buffer messages while disconnected
      this.listeners = new Map(); // Event listeners
    }

    /** Update the WebSocket URL (e.g., from settings change). */
    updateUrl(newUrl) {
      if (newUrl && newUrl !== this.url) {
        this.url = newUrl;
        if (this.connected) {
          this.disconnect();
          this.connect();
        }
      }
    }

    /** Establish WebSocket connection with auto-reconnect */
    connect() {
      if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
        return;
      }

      try {
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          this.connected = true;
          this.reconnectAttempts = 0;
          console.log(`${LOG_PREFIX} Connected to backend at ${this.url}`);

          // Flush queued messages
          while (this.messageQueue.length > 0) {
            const msg = this.messageQueue.shift();
            this.ws.send(JSON.stringify(msg));
          }
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this._emit("response", data);
          } catch (e) {
            console.warn(`${LOG_PREFIX} Failed to parse backend message:`, e);
          }
        };

        this.ws.onclose = (event) => {
          this.connected = false;
          console.log(`${LOG_PREFIX} Disconnected from backend (code: ${event.code})`);
          this._scheduleReconnect();
        };

        this.ws.onerror = () => {
          // onerror is always followed by onclose, so reconnect is handled there
          console.warn(`${LOG_PREFIX} WebSocket error — is the backend running?`);
        };
      } catch (e) {
        console.warn(`${LOG_PREFIX} Failed to create WebSocket:`, e);
        this._scheduleReconnect();
      }
    }

    /** Send a message to the backend, buffering if disconnected */
    send(payload) {
      if (this.connected && this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify(payload));
      } else {
        // Buffer up to 100 messages while disconnected
        if (this.messageQueue.length < 100) {
          this.messageQueue.push(payload);
        }
      }
    }

    /** Register an event listener */
    on(event, callback) {
      if (!this.listeners.has(event)) {
        this.listeners.set(event, []);
      }
      this.listeners.get(event).push(callback);
    }

    /** Emit an event to all registered listeners */
    _emit(event, data) {
      const callbacks = this.listeners.get(event) || [];
      for (const cb of callbacks) {
        try {
          cb(data);
        } catch (e) {
          console.warn(`${LOG_PREFIX} Listener error:`, e);
        }
      }
    }

    /**
     * Schedule a reconnection attempt with exponential backoff + jitter.
     * Jitter prevents thundering herd when many tabs reconnect simultaneously.
     */
    _scheduleReconnect() {
      if (this.reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.warn(
          `${LOG_PREFIX} Max reconnection attempts (${MAX_RECONNECT_ATTEMPTS}) reached. ` +
          `Extension will continue with local-only protection.`
        );
        return;
      }

      this.reconnectAttempts++;
      const exponentialDelay = RECONNECT_BASE_DELAY_MS * Math.min(Math.pow(1.5, this.reconnectAttempts - 1), 10);
      // Add ±25% jitter.
      const jitter = exponentialDelay * (0.75 + Math.random() * 0.5);
      const delay = Math.round(jitter);

      console.log(
        `${LOG_PREFIX} Reconnecting in ${(delay / 1000).toFixed(1)}s ` +
        `(attempt ${this.reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS})...`
      );

      setTimeout(() => this.connect(), delay);
    }

    /** Clean shutdown */
    disconnect() {
      if (this.ws) {
        this.ws.close(1000, "Extension shutting down");
        this.ws = null;
      }
      this.connected = false;
    }
  }

  // ========================================================================
  // 2. Settings Loader
  // ========================================================================

  let currentSettings = null;

  async function loadSettings() {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type: "get-settings" }, (response) => {
          currentSettings = response || {};
          resolve(currentSettings);
        });
      } catch (e) {
        resolve({});
      }
    });
  }

  // ========================================================================
  // 3. Message Bridge — MAIN world ↔ ISOLATED world
  // ========================================================================

  let backend = null;

  /**
   * Listen for telemetry events from the MAIN world content script.
   * The content script posts messages via window.postMessage with a
   * specific channel identifier.
   */
  window.addEventListener("message", (event) => {
    // Only accept messages from the same page
    if (event.source !== window) return;

    const msg = event.data;
    if (!msg || msg.channel !== MESSAGE_CHANNEL) return;

    switch (msg.type) {
      case "telemetry":
        // Forward API interception telemetry to the backend
        if (backend) {
          backend.send({
            type: "telemetry",
            payload: msg.payload,
          });
        }

        // Also notify background worker for badge updates.
        try {
          chrome.runtime.sendMessage({
            type: "telemetry-event",
            origin: msg.payload?.origin,
            intent: msg.payload?.intent,
          });
        } catch (e) {
          // Extension context may be invalidated.
        }
        break;

      case "script_source":
        // Forward captured script source for AI analysis (Phase 3)
        if (backend) {
          backend.send({
            type: "script_source",
            payload: msg.payload,
          });
        }
        break;

      default:
        break;
    }
  });

  // ========================================================================
  // 4. Background Worker Message Handler
  // ========================================================================

  try {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === "settings-changed") {
        currentSettings = message.settings;

        // Forward to MAIN world content script.
        window.postMessage(
          {
            channel: MESSAGE_CHANNEL,
            type: "settings-update",
            enabled: message.settings.enabled,
          },
          "*"
        );

        // Update backend URL if changed.
        if (backend && message.settings.backendUrl) {
          backend.updateUrl(message.settings.backendUrl);
        }
      }

      if (message.type === "rotate-salt") {
        // Salt rotation — the MAIN world PRNG cache will pick up the new
        // date on next seed creation. No explicit action needed since
        // getDailySalt() reads the current date dynamically.
        console.log(`${LOG_PREFIX} Daily salt rotation signal received`);
      }
    });
  } catch (e) {
    // chrome.runtime may not be available in all contexts.
  }

  // ========================================================================
  // 5. Script Source Capture (Phase 3 Preparation)
  //
  // Uses a MutationObserver to detect new <script> elements being added
  // to the DOM. For third-party scripts, fetches and sends the source
  // text to the backend for AI intent analysis.
  // ========================================================================

  const capturedScripts = new Set();

  /**
   * Determine if a script URL is third-party relative to the current page.
   */
  function isThirdParty(scriptUrl) {
    try {
      const scriptOrigin = new URL(scriptUrl, location.href).origin;
      return scriptOrigin !== location.origin;
    } catch {
      return false;
    }
  }

  /**
   * Attempt to capture a script's source text and send it for analysis.
   * Only processes third-party scripts to avoid noise from first-party code.
   */
  async function captureScript(scriptElement) {
    const src = scriptElement.src;
    if (!src || capturedScripts.has(src)) return;
    if (!isThirdParty(src)) return;

    capturedScripts.add(src);

    try {
      // Attempt to fetch the script source (may fail due to CORS)
      const response = await fetch(src, { mode: "cors" });
      if (!response.ok) return;

      const sourceText = await response.text();

      // Only send scripts of meaningful size (skip tiny inline helpers)
      if (sourceText.length < 100 || sourceText.length > 500000) return;

      if (backend) {
        backend.send({
          type: "script_source",
          payload: {
            url: src,
            origin: new URL(src).origin,
            page_origin: location.origin,
            source_length: sourceText.length,
            source_text: sourceText.substring(0, 50000), // Cap at 50KB
            timestamp: Date.now(),
          },
        });
      }

      console.debug(`${LOG_PREFIX} Captured third-party script: ${src} (${sourceText.length} bytes)`);
    } catch (e) {
      // CORS failures are expected for many third-party scripts — silent fail
    }
  }

  /**
   * Watch for new script elements being added to the page.
   */
  const scriptObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeName === "SCRIPT") {
          captureScript(node);
        }
        // Also check children of added nodes (e.g., template insertions)
        if (node.querySelectorAll) {
          const scripts = node.querySelectorAll("script[src]");
          scripts.forEach(captureScript);
        }
      }
    }
  });

  // Start observing once the DOM is available
  if (document.documentElement) {
    scriptObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      scriptObserver.observe(document.documentElement, {
        childList: true,
        subtree: true,
      });
    });
  }

  // Also capture scripts already in the page
  document.querySelectorAll("script[src]").forEach(captureScript);

  // ========================================================================
  // 6. Initialize
  // ========================================================================

  async function init() {
    const settings = await loadSettings();
    const wsUrl = settings.backendUrl || DEFAULT_WS_URL;

    backend = new BackendConnection(wsUrl);

    // Relay classification responses from the backend back to the MAIN world.
    backend.on("response", (data) => {
      window.postMessage(
        {
          channel: MESSAGE_CHANNEL,
          type: "classification",
          payload: data,
        },
        "*"
      );
    });

    backend.connect();

    console.log(
      `%c${LOG_PREFIX} Telemetry bridge v1.0.0 initialized — connecting to ${wsUrl}`,
      "color: #76ff03; font-weight: bold;"
    );
  }

  init();
})();
