// ============================================================================
// Adaptive Privacy Observatory — Dashboard Application
//
// Connects to the backend WebSocket at /ws/dashboard to receive real-time
// telemetry events and classification updates. Renders stats, charts,
// event feed, domain policies, and entropy analysis.
// ============================================================================

(function () {
  "use strict";

  // -----------------------------------------------------------------------
  // Configuration
  // -----------------------------------------------------------------------

  const WS_URL = `ws://${location.host}/ws/dashboard`;
  const API_BASE = `${location.protocol}//${location.host}/api`;
  const RECONNECT_DELAY = 3000;
  const MAX_FEED_ENTRIES = 500;
  const MAX_ACTIVITY_BARS = 60;

  // -----------------------------------------------------------------------
  // State
  // -----------------------------------------------------------------------

  let ws = null;
  let reconnectTimer = null;
  const activityHistory = []; // Per-second intercept counts
  const classificationCounts = { fingerprint: 0, unknown: 0, legitimate: 0 };
  let totalEventsReceived = 0;

  // -----------------------------------------------------------------------
  // DOM References
  // -----------------------------------------------------------------------

  const $id = (id) => document.getElementById(id);

  const dom = {
    wsStatus: $id("ws-status"),
    wsStatusText: $id("ws-status-text"),
    totalIntercepts: $id("total-intercepts"),
    cacheSize: $id("cache-size"),
    entropyReduction: $id("entropy-reduction"),
    dashboardClients: $id("dashboard-clients"),
    uptimeDisplay: $id("uptime-display"),
    versionDisplay: $id("version-display"),
    recentEventsBody: $id("recent-events-body"),
    activityChart: $id("activity-chart"),
    donut: $id("donut"),
    donutTotal: $id("donut-total"),
    donutLegend: $id("donut-legend"),
    telemetryFeed: $id("telemetry-feed"),
    clearTelemetry: $id("clear-telemetry"),
    autoScroll: $id("auto-scroll"),
    policiesBody: $id("policies-body"),
    policySearch: $id("policy-search"),
    entropySummary: $id("entropy-summary"),
    entropyBars: $id("entropy-bars"),
  };

  // -----------------------------------------------------------------------
  // Navigation
  // -----------------------------------------------------------------------

  document.querySelectorAll(".nav-item").forEach((item) => {
    item.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));

      item.classList.add("active");
      const viewId = `view-${item.dataset.view}`;
      const view = $id(viewId);
      if (view) view.classList.add("active");

      // Load view-specific data
      if (item.dataset.view === "policies") fetchPolicies();
      if (item.dataset.view === "entropy") fetchEntropy();
    });
  });

  // -----------------------------------------------------------------------
  // WebSocket Connection
  // -----------------------------------------------------------------------

  function connect() {
    updateConnectionStatus("connecting");

    try {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        updateConnectionStatus("connected");
        if (reconnectTimer) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleMessage(data);
        } catch (e) {
          console.warn("[Dashboard] Parse error:", e);
        }
      };

      ws.onclose = () => {
        updateConnectionStatus("disconnected");
        scheduleReconnect();
      };

      ws.onerror = () => {
        updateConnectionStatus("disconnected");
      };
    } catch (e) {
      updateConnectionStatus("disconnected");
      scheduleReconnect();
    }
  }

  function scheduleReconnect() {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, RECONNECT_DELAY);
  }

  function updateConnectionStatus(state) {
    const dot = dom.wsStatus.querySelector(".status-dot");
    dot.className = `status-dot ${state}`;
    const labels = {
      connected: "Connected",
      disconnected: "Disconnected",
      connecting: "Connecting...",
    };
    dom.wsStatusText.textContent = labels[state] || state;
  }

  // -----------------------------------------------------------------------
  // Message Handling
  // -----------------------------------------------------------------------

  function handleMessage(data) {
    switch (data.type) {
      case "snapshot":
        handleSnapshot(data);
        break;
      case "telemetry_event":
        handleTelemetryEvent(data);
        break;
    }
  }

  function handleSnapshot(data) {
    // Update status
    if (data.status) {
      updateStats(data.status);
    }

    // Populate recent events
    if (data.recent_events) {
      dom.recentEventsBody.innerHTML = "";
      data.recent_events.forEach((event) => addEventRow(event));
    }

    // Populate policies
    if (data.policies) {
      renderPolicies(data.policies);
    }
  }

  function handleTelemetryEvent(data) {
    totalEventsReceived++;

    // Update classification counts
    const intent = data.classification?.classification?.intent || "unknown";
    if (intent in classificationCounts) {
      classificationCounts[intent]++;
    }

    // Update donut chart
    updateDonutChart();

    // Add to activity history
    const now = Math.floor(Date.now() / 1000);
    if (activityHistory.length === 0 || activityHistory[activityHistory.length - 1].time !== now) {
      activityHistory.push({ time: now, count: 1 });
      if (activityHistory.length > MAX_ACTIVITY_BARS) activityHistory.shift();
    } else {
      activityHistory[activityHistory.length - 1].count++;
    }
    renderActivityChart();

    // Add to event table
    if (data.event) {
      const enrichedEvent = {
        ...data.event,
        intent: data.classification?.classification?.intent,
        confidence: data.classification?.classification?.confidence,
        entropy_before: data.classification?.entropy_before,
        entropy_after: data.classification?.entropy_after,
      };
      addEventRow(enrichedEvent, true);
    }

    // Add to telemetry feed
    addFeedEntry(data.event, data.classification);

    // Refresh status
    fetchStatus();
  }

  // -----------------------------------------------------------------------
  // Stats Update
  // -----------------------------------------------------------------------

  function updateStats(status) {
    animateValue(dom.totalIntercepts, status.total_intercepts || 0);
    animateValue(dom.cacheSize, status.cache_size || 0);
    animateValue(dom.dashboardClients, status.dashboard_clients || 0);

    dom.uptimeDisplay.textContent = `Uptime: ${formatUptime(status.uptime_seconds)}`;
    dom.versionDisplay.textContent = `v${status.version || "?"}`;
  }

  function animateValue(el, target) {
    const current = parseInt(el.textContent) || 0;
    if (current === target) { el.textContent = target; return; }
    const duration = 400;
    const start = performance.now();
    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(current + (target - current) * eased);
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  function formatUptime(seconds) {
    if (!seconds) return "—";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  // -----------------------------------------------------------------------
  // Event Table
  // -----------------------------------------------------------------------

  function addEventRow(event, isNew = false) {
    const tr = document.createElement("tr");
    if (isNew) tr.classList.add("new-row");

    const time = event.timestamp
      ? new Date(event.timestamp * (event.timestamp > 1e12 ? 1 : 1000)).toLocaleTimeString()
      : "—";

    const intent = event.intent || "—";
    const badgeClass = `badge badge-${intent}`;

    const entropyBefore = event.entropy_before != null ? event.entropy_before.toFixed(1) : "—";
    const entropyAfter = event.entropy_after != null ? event.entropy_after.toFixed(1) : "—";

    tr.innerHTML = `
      <td>${time}</td>
      <td style="color: var(--cyan)">${event.api || "—"}</td>
      <td>${truncate(event.origin || "—", 30)}</td>
      <td><span class="${badgeClass}">${intent}</span></td>
      <td>${event.confidence != null ? event.confidence.toFixed(2) : "—"}</td>
      <td>${entropyBefore} → ${entropyAfter}</td>
    `;

    // Prepend new events at the top.
    if (dom.recentEventsBody.firstChild) {
      dom.recentEventsBody.insertBefore(tr, dom.recentEventsBody.firstChild);
    } else {
      dom.recentEventsBody.appendChild(tr);
    }

    // Keep table size bounded.
    while (dom.recentEventsBody.children.length > 50) {
      dom.recentEventsBody.removeChild(dom.recentEventsBody.lastChild);
    }
  }

  // -----------------------------------------------------------------------
  // Activity Chart
  // -----------------------------------------------------------------------

  function renderActivityChart() {
    if (!dom.activityChart) return;

    const maxCount = Math.max(1, ...activityHistory.map((h) => h.count));

    let html = '<div class="activity-bars">';
    for (const bar of activityHistory) {
      const height = Math.max(2, (bar.count / maxCount) * 180);
      html += `<div class="activity-bar" style="height:${height}px" title="${bar.count} events"></div>`;
    }
    html += "</div>";
    dom.activityChart.innerHTML = html;
  }

  // -----------------------------------------------------------------------
  // Donut Chart
  // -----------------------------------------------------------------------

  function updateDonutChart() {
    const total = classificationCounts.fingerprint + classificationCounts.unknown + classificationCounts.legitimate;
    dom.donutTotal.textContent = total;

    if (total === 0) return;

    const fp = (classificationCounts.fingerprint / total) * 100;
    const uk = (classificationCounts.unknown / total) * 100;
    const lg = (classificationCounts.legitimate / total) * 100;

    dom.donut.style.background = `conic-gradient(
      var(--red) 0% ${fp}%,
      var(--amber) ${fp}% ${fp + uk}%,
      var(--green) ${fp + uk}% ${fp + uk + lg}%,
      var(--text-dim) ${fp + uk + lg}% 100%
    )`;

    dom.donutLegend.innerHTML = `
      <span class="legend-item"><span class="legend-dot" style="background:var(--red)"></span>Fingerprint (${classificationCounts.fingerprint})</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--amber)"></span>Unknown (${classificationCounts.unknown})</span>
      <span class="legend-item"><span class="legend-dot" style="background:var(--green)"></span>Legitimate (${classificationCounts.legitimate})</span>
    `;
  }

  // -----------------------------------------------------------------------
  // Telemetry Feed
  // -----------------------------------------------------------------------

  function addFeedEntry(event, classification) {
    if (!event || !dom.telemetryFeed) return;

    const time = new Date().toLocaleTimeString();
    const intent = classification?.classification?.intent || "unknown";
    const intentColors = {
      fingerprint: "var(--red)",
      unknown: "var(--amber)",
      legitimate: "var(--green)",
    };

    const entry = document.createElement("div");
    entry.className = "feed-entry";
    entry.innerHTML = `
      <span class="feed-time">${time}</span>
      <span class="feed-api">${event.api || "?"}</span>
      <span class="feed-origin">${truncate(event.origin || "?", 40)}</span>
      <span class="feed-intent" style="color:${intentColors[intent] || "var(--text-muted)"}">${intent}</span>
    `;

    dom.telemetryFeed.appendChild(entry);

    // Trim old entries
    while (dom.telemetryFeed.children.length > MAX_FEED_ENTRIES) {
      dom.telemetryFeed.removeChild(dom.telemetryFeed.firstChild);
    }

    // Auto-scroll
    if (dom.autoScroll.checked) {
      dom.telemetryFeed.scrollTop = dom.telemetryFeed.scrollHeight;
    }
  }

  dom.clearTelemetry.addEventListener("click", () => {
    dom.telemetryFeed.innerHTML = "";
  });

  // -----------------------------------------------------------------------
  // Policies View
  // -----------------------------------------------------------------------

  async function fetchPolicies() {
    try {
      const resp = await fetch(`${API_BASE}/policies`);
      const data = await resp.json();
      renderPolicies(data.policies || {});
    } catch (e) {
      console.warn("[Dashboard] Failed to fetch policies:", e);
    }
  }

  function renderPolicies(policies) {
    const searchTerm = (dom.policySearch?.value || "").toLowerCase();

    dom.policiesBody.innerHTML = "";

    for (const [origin, policy] of Object.entries(policies)) {
      if (searchTerm && !origin.toLowerCase().includes(searchTerm)) continue;

      const intent = policy.intent || "unknown";
      const badgeClass = `badge badge-${intent}`;

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${truncate(origin, 40)}</td>
        <td><span class="${badgeClass}">${intent}</span></td>
        <td>${(policy.confidence || 0).toFixed(2)}</td>
        <td>${(policy.noise_multiplier || 0).toFixed(2)}</td>
        <td>${policy.source || "—"}</td>
        <td>${(policy.signals || []).join(", ") || "—"}</td>
        <td><button class="btn btn-danger btn-sm" data-origin="${escapeHtml(origin)}">Delete</button></td>
      `;

      // Delete handler
      tr.querySelector("button").addEventListener("click", async (e) => {
        const origin = e.target.dataset.origin;
        await fetch(`${API_BASE}/policies/${encodeURIComponent(origin)}`, { method: "DELETE" });
        fetchPolicies();
      });

      dom.policiesBody.appendChild(tr);
    }
  }

  dom.policySearch?.addEventListener("input", fetchPolicies);

  // -----------------------------------------------------------------------
  // Entropy View
  // -----------------------------------------------------------------------

  async function fetchEntropy() {
    try {
      const resp = await fetch(`${API_BASE}/entropy-summary`);
      const data = await resp.json();
      renderEntropy(data);
    } catch (e) {
      console.warn("[Dashboard] Failed to fetch entropy:", e);
    }
  }

  function renderEntropy(data) {
    // Summary stats
    dom.entropySummary.innerHTML = `
      <div class="entropy-stat">
        <div class="entropy-stat-value">${data.total_before?.toFixed(1) || "0"}</div>
        <div class="entropy-stat-label">Bits Before</div>
      </div>
      <div class="entropy-stat">
        <div class="entropy-stat-value">${data.total_after?.toFixed(1) || "0"}</div>
        <div class="entropy-stat-label">Bits After</div>
      </div>
      <div class="entropy-stat">
        <div class="entropy-stat-value">${data.reduction_pct?.toFixed(1) || "0"}%</div>
        <div class="entropy-stat-label">Entropy Reduction</div>
      </div>
    `;

    // Update overview card
    dom.entropyReduction.textContent = `${data.reduction_pct?.toFixed(0) || "—"}%`;

    // Per-API bars
    const maxBits = Math.max(1, ...((data.per_api || []).map((a) => a.entropy_before)));
    dom.entropyBars.innerHTML = "";

    for (const api of data.per_api || []) {
      const beforePct = (api.entropy_before / maxBits) * 100;
      const afterPct = (api.entropy_after / maxBits) * 100;

      const row = document.createElement("div");
      row.className = "entropy-row";
      row.innerHTML = `
        <div class="entropy-api-name">${api.api}</div>
        <div class="entropy-bar-wrapper">
          <div class="entropy-bar-before" style="width:${beforePct}%"></div>
          <div class="entropy-bar-after" style="width:${afterPct}%"></div>
        </div>
        <div class="entropy-bits">${api.entropy_before.toFixed(1)} → ${api.entropy_after.toFixed(1)}</div>
      `;
      dom.entropyBars.appendChild(row);
    }
  }

  // -----------------------------------------------------------------------
  // Status Polling (fallback for when WS is slow)
  // -----------------------------------------------------------------------

  async function fetchStatus() {
    try {
      const resp = await fetch(`${API_BASE}/status`);
      const data = await resp.json();
      updateStats(data);
    } catch (e) {
      // Silently fail — WS is primary source.
    }
  }

  // -----------------------------------------------------------------------
  // Utilities
  // -----------------------------------------------------------------------

  function truncate(str, max) {
    return str.length > max ? str.substring(0, max) + "…" : str;
  }

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  // -----------------------------------------------------------------------
  // Initialize
  // -----------------------------------------------------------------------

  connect();
  fetchStatus();
  fetchEntropy();
  renderActivityChart();
  updateDonutChart();

  // Periodic status refresh
  setInterval(fetchStatus, 10000);

  console.log("[Dashboard] Adaptive Privacy Observatory Dashboard initialized");
})();
