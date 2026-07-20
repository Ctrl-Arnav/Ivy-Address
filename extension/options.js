// ============================================================================
// Adaptive Privacy Observatory — Options Page Script
// ============================================================================

(function () {
  "use strict";

  const DEFAULT_SETTINGS = {
    enabled: true,
    backendUrl: "ws://127.0.0.1:8000/ws/telemetry",
    noiseLevel: "adaptive",
    whitelistedDomains: [],
    blacklistedDomains: [],
    saltRotationHours: 24,
    showBadge: true,
  };

  // DOM references
  const backendUrl = document.getElementById("backend-url");
  const noiseLevel = document.getElementById("noise-level");
  const saltRotation = document.getElementById("salt-rotation");
  const whitelist = document.getElementById("whitelist");
  const blacklist = document.getElementById("blacklist");
  const showBadge = document.getElementById("show-badge");
  const saveBtn = document.getElementById("save-btn");
  const resetBtn = document.getElementById("reset-btn");
  const saveStatus = document.getElementById("save-status");

  // -----------------------------------------------------------------------
  // Load settings
  // -----------------------------------------------------------------------

  async function loadSettings() {
    const result = await chrome.storage.local.get("settings");
    const settings = result.settings || DEFAULT_SETTINGS;

    backendUrl.value = settings.backendUrl || DEFAULT_SETTINGS.backendUrl;
    noiseLevel.value = settings.noiseLevel || DEFAULT_SETTINGS.noiseLevel;
    saltRotation.value = settings.saltRotationHours || DEFAULT_SETTINGS.saltRotationHours;
    whitelist.value = (settings.whitelistedDomains || []).join("\n");
    blacklist.value = (settings.blacklistedDomains || []).join("\n");
    showBadge.checked = settings.showBadge !== false;
  }

  // -----------------------------------------------------------------------
  // Save settings
  // -----------------------------------------------------------------------

  function parseTextarea(el) {
    return el.value
      .split("\n")
      .map((line) => line.trim().toLowerCase())
      .filter((line) => line.length > 0);
  }

  saveBtn.addEventListener("click", async () => {
    const result = await chrome.storage.local.get("settings");
    const currentSettings = result.settings || DEFAULT_SETTINGS;

    const newSettings = {
      ...currentSettings,
      backendUrl: backendUrl.value.trim(),
      noiseLevel: noiseLevel.value,
      saltRotationHours: parseInt(saltRotation.value, 10) || 24,
      whitelistedDomains: parseTextarea(whitelist),
      blacklistedDomains: parseTextarea(blacklist),
      showBadge: showBadge.checked,
    };

    chrome.runtime.sendMessage(
      { type: "update-settings", settings: newSettings },
      () => {
        showSaveStatus("✓ Settings saved successfully");
      }
    );
  });

  // -----------------------------------------------------------------------
  // Reset
  // -----------------------------------------------------------------------

  resetBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage(
      { type: "update-settings", settings: DEFAULT_SETTINGS },
      () => {
        loadSettings();
        showSaveStatus("✓ Settings reset to defaults");
      }
    );
  });

  // -----------------------------------------------------------------------
  // Status indicator
  // -----------------------------------------------------------------------

  function showSaveStatus(message) {
    saveStatus.textContent = message;
    saveStatus.classList.add("visible");
    setTimeout(() => {
      saveStatus.classList.remove("visible");
    }, 2500);
  }

  // -----------------------------------------------------------------------
  // Init
  // -----------------------------------------------------------------------

  loadSettings();
})();
