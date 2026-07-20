// ============================================================================
// Adaptive Privacy Observatory — Background Service Worker
//
// Handles:
//   1. Badge updates showing intercept count
//   2. Storage management for settings
//   3. Message relay between popup ↔ content scripts
//   4. Daily salt rotation alarm
// ============================================================================

const DEFAULT_SETTINGS = {
  enabled: true,
  backendUrl: "ws://127.0.0.1:8000/ws/telemetry",
  noiseLevel: "adaptive",   // "off" | "low" | "adaptive" | "max"
  whitelistedDomains: [],
  blacklistedDomains: [],
  saltRotationHours: 24,
  showBadge: true,
};

// Aggregate stats across all tabs.
let sessionStats = {
  totalIntercepts: 0,
  domainsCovered: new Set(),
  fingerprints_blocked: 0,
};

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("[APO:BG] Extension installed/updated:", details.reason);

  // Initialize settings if first install.
  const stored = await chrome.storage.local.get("settings");
  if (!stored.settings) {
    await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  }

  // Set up daily salt rotation alarm.
  chrome.alarms.create("daily-salt-rotation", {
    periodInMinutes: 24 * 60,
  });

  // Set initial badge.
  updateBadge(true);
});

// ---------------------------------------------------------------------------
// Badge Management
// ---------------------------------------------------------------------------

function updateBadge(enabled) {
  if (enabled) {
    chrome.action.setBadgeBackgroundColor({ color: "#00BFA5" });
    chrome.action.setBadgeText({ text: "ON" });
    chrome.action.setTitle({ title: "Adaptive Privacy Observatory — Active" });
  } else {
    chrome.action.setBadgeBackgroundColor({ color: "#FF5252" });
    chrome.action.setBadgeText({ text: "OFF" });
    chrome.action.setTitle({ title: "Adaptive Privacy Observatory — Disabled" });
  }
}

function updateBadgeCount(count) {
  if (count === 0) return;
  const text = count > 999 ? "999+" : String(count);
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color: "#00E5FF" });
}

// ---------------------------------------------------------------------------
// Message Handling (popup, content scripts, injector)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "get-settings":
      chrome.storage.local.get("settings").then((result) => {
        sendResponse(result.settings || DEFAULT_SETTINGS);
      });
      return true; // async response

    case "update-settings":
      chrome.storage.local.set({ settings: message.settings }).then(() => {
        updateBadge(message.settings.enabled);
        // Notify all tabs of settings change.
        broadcastToTabs({ type: "settings-changed", settings: message.settings });
        sendResponse({ status: "ok" });
      });
      return true;

    case "get-stats":
      sendResponse({
        totalIntercepts: sessionStats.totalIntercepts,
        domainsCovered: sessionStats.domainsCovered.size,
        fingerprints_blocked: sessionStats.fingerprints_blocked,
      });
      return true;

    case "telemetry-event":
      // Content script reports an interception.
      sessionStats.totalIntercepts++;
      if (message.origin) {
        sessionStats.domainsCovered.add(message.origin);
      }
      if (message.intent === "fingerprint") {
        sessionStats.fingerprints_blocked++;
      }
      // Update badge with count.
      chrome.storage.local.get("settings").then((result) => {
        const settings = result.settings || DEFAULT_SETTINGS;
        if (settings.showBadge && settings.enabled) {
          updateBadgeCount(sessionStats.totalIntercepts);
        }
      });
      break;

    case "toggle-protection":
      chrome.storage.local.get("settings").then(async (result) => {
        const settings = result.settings || DEFAULT_SETTINGS;
        settings.enabled = !settings.enabled;
        await chrome.storage.local.set({ settings });
        updateBadge(settings.enabled);
        broadcastToTabs({ type: "settings-changed", settings });
        sendResponse({ enabled: settings.enabled });
      });
      return true;
  }
});

// ---------------------------------------------------------------------------
// Broadcast to all tabs
// ---------------------------------------------------------------------------

async function broadcastToTabs(message) {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    try {
      await chrome.tabs.sendMessage(tab.id, message);
    } catch (e) {
      // Tab might not have a content script.
    }
  }
}

// ---------------------------------------------------------------------------
// Alarms
// ---------------------------------------------------------------------------

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "daily-salt-rotation") {
    console.log("[APO:BG] Daily salt rotation triggered");
    // Notify all tabs to rotate their PRNG seeds.
    broadcastToTabs({ type: "rotate-salt" });
  }
});

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

chrome.storage.local.get("settings").then((result) => {
  const settings = result.settings || DEFAULT_SETTINGS;
  updateBadge(settings.enabled);
});

console.log("[APO:BG] Background service worker initialized");
