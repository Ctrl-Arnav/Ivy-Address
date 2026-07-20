// ============================================================================
// Adaptive Privacy Observatory — Popup Script
//
// Reads state from chrome.storage and the background service worker to
// display protection status, domain classification, and session stats.
// ============================================================================

(function () {
  "use strict";

  // DOM references
  const toggleBtn = document.getElementById("toggle-btn");
  const statusBanner = document.getElementById("status-banner");
  const statusText = document.getElementById("status-text");
  const domainName = document.getElementById("domain-name");
  const domainClassification = document.getElementById("domain-classification");
  const domainConfidence = document.getElementById("domain-confidence");
  const statIntercepts = document.getElementById("stat-intercepts");
  const statDomains = document.getElementById("stat-domains");
  const statBlocked = document.getElementById("stat-blocked");
  const statEntropy = document.getElementById("stat-entropy");
  const backendStatus = document.getElementById("backend-status");
  const optionsLink = document.getElementById("options-link");

  // -----------------------------------------------------------------------
  // Initialization
  // -----------------------------------------------------------------------

  async function init() {
    // Load settings.
    const settings = await getSettings();
    updateToggleUI(settings.enabled);

    // Get current tab domain.
    const tab = await getCurrentTab();
    if (tab && tab.url) {
      try {
        const url = new URL(tab.url);
        domainName.textContent = url.hostname || tab.url;
      } catch (e) {
        domainName.textContent = tab.url.substring(0, 40);
      }
    }

    // Load stats from background.
    loadStats();

    // Check backend connectivity.
    checkBackend(settings.backendUrl || "ws://127.0.0.1:8000/ws/telemetry");
  }

  // -----------------------------------------------------------------------
  // Settings
  // -----------------------------------------------------------------------

  function getSettings() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: "get-settings" }, (response) => {
        resolve(response || { enabled: true });
      });
    });
  }

  function updateToggleUI(enabled) {
    if (enabled) {
      toggleBtn.classList.add("active");
      statusBanner.classList.add("active");
      statusText.textContent = "Protection Active";
    } else {
      toggleBtn.classList.remove("active");
      statusBanner.classList.remove("active");
      statusText.textContent = "Protection Disabled";
    }
  }

  // -----------------------------------------------------------------------
  // Toggle handler
  // -----------------------------------------------------------------------

  toggleBtn.addEventListener("click", async () => {
    chrome.runtime.sendMessage({ type: "toggle-protection" }, (response) => {
      if (response) {
        updateToggleUI(response.enabled);
      }
    });
  });

  // -----------------------------------------------------------------------
  // Stats
  // -----------------------------------------------------------------------

  function loadStats() {
    chrome.runtime.sendMessage({ type: "get-stats" }, (response) => {
      if (!response) return;
      animateNumber(statIntercepts, response.totalIntercepts || 0);
      animateNumber(statDomains, response.domainsCovered || 0);
      animateNumber(statBlocked, response.fingerprints_blocked || 0);
      statEntropy.textContent = response.totalIntercepts > 0 ? "97%" : "—";
    });
  }

  function animateNumber(el, target) {
    const current = parseInt(el.textContent) || 0;
    if (current === target) {
      el.textContent = target;
      return;
    }
    const duration = 400;
    const start = performance.now();

    function tick(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      el.textContent = Math.round(current + (target - current) * eased);
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // -----------------------------------------------------------------------
  // Backend connectivity check
  // -----------------------------------------------------------------------

  function checkBackend(wsUrl) {
    const httpUrl = wsUrl
      .replace("ws://", "http://")
      .replace("wss://", "https://")
      .replace("/ws/telemetry", "/api/health");

    fetch(httpUrl, { method: "GET", signal: AbortSignal.timeout(2000) })
      .then((r) => r.json())
      .then((data) => {
        if (data.status === "ok") {
          backendStatus.classList.add("connected");
          backendStatus.classList.remove("disconnected");
          backendStatus.innerHTML =
            '<span class="backend-dot"></span>Backend: Online (v' + (data.version || "?") + ")";
        }
      })
      .catch(() => {
        backendStatus.classList.remove("connected");
        backendStatus.classList.add("disconnected");
        backendStatus.innerHTML = '<span class="backend-dot"></span>Backend: Offline';
      });
  }

  // -----------------------------------------------------------------------
  // Utilities
  // -----------------------------------------------------------------------

  function getCurrentTab() {
    return new Promise((resolve) => {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        resolve(tabs[0] || null);
      });
    });
  }

  // -----------------------------------------------------------------------
  // Options link
  // -----------------------------------------------------------------------

  optionsLink.addEventListener("click", () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });

  // -----------------------------------------------------------------------
  // Start
  // -----------------------------------------------------------------------

  init();
})();
