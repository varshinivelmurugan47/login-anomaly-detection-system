// ============================================================
// DASHBOARD CONTROLLER — real-time alert feed, stats, charts
// ============================================================

let allAlerts  = [];
let activeFilter = "all";

// ── Clock ────────────────────────────────────────────────────
function updateClock() {
  document.getElementById("clock").textContent =
    new Date().toLocaleTimeString("en-IN", { hour12: false });
}
setInterval(updateClock, 1000);
updateClock();

// ── Fetch stats ──────────────────────────────────────────────
async function fetchStats() {
  const res  = await fetch("/api/stats");
  const data = await res.json();

  document.getElementById("v-total").textContent  = data.total;
  document.getElementById("v-flagged").textContent = data.flagged;
  document.getElementById("v-high").textContent   = data.high_risk;
  document.getElementById("v-medium").textContent = data.medium_risk;
  document.getElementById("v-low").textContent    = data.low_risk;
  document.getElementById("v-normal").textContent = data.normal;

  renderChart(data);
}

// ── Fetch alerts ─────────────────────────────────────────────
async function fetchAlerts() {
  const res  = await fetch("/api/alerts?limit=60");
  allAlerts  = await res.json();
  renderFeed();
}

// ── Render feed ──────────────────────────────────────────────
function renderFeed() {
  const feed = document.getElementById("alert-feed");
  const list = activeFilter === "all"
    ? allAlerts
    : allAlerts.filter(a => a.risk.level === activeFilter);

  if (!list.length) {
    feed.innerHTML = `<div class="loading">No alerts for this filter.</div>`;
    return;
  }

  feed.innerHTML = list.map(alert => {
    const e    = alert.event;
    const risk = alert.risk;
    const lvl  = risk.level;
    const time = e.time_str || e.timestamp.slice(11, 19);
    const anoms = alert.anomalies.map(a => a.replace(/_/g, " ")).join(", ") || "—";

    return `<div class="alert-card ${lvl}" onclick='showDetail(${JSON.stringify(alert).replace(/'/g, "&#39;")})'>
      <div>
        <span class="risk-badge badge-${lvl}">${lvl}</span>
      </div>
      <div class="alert-info">
        <div class="alert-user">👤 ${e.username}</div>
        <div class="alert-meta">🌐 ${e.ip_address} · 📍 ${e.location}</div>
        <div class="alert-meta">💻 ${e.device}</div>
        ${alert.anomalies.length
          ? `<div class="alert-summary">⚠ ${anoms}</div>`
          : `<div class="alert-summary" style="color:#22C55E">✓ Normal login</div>`
        }
      </div>
      <div class="alert-time">${time}</div>
    </div>`;
  }).join("");
}

// ── Filter ───────────────────────────────────────────────────
function setFilter(f, btn) {
  activeFilter = f;
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  renderFeed();
}

// ── Bar Chart ─────────────────────────────────────────────────
function renderChart(stats) {
  const max   = Math.max(stats.high_risk, stats.medium_risk, stats.low_risk, stats.normal, 1);
  const bars  = [
    { label: "High",   count: stats.high_risk,   color: "#E24B4A" },
    { label: "Medium", count: stats.medium_risk,  color: "#EF9F27" },
    { label: "Low",    count: stats.low_risk,     color: "#14B8A6" },
    { label: "Normal", count: stats.normal,       color: "#22C55E" },
  ];

  document.getElementById("bar-chart").innerHTML = bars.map(b => `
    <div class="bar-row">
      <span class="bar-label">${b.label}</span>
      <div class="bar-track">
        <div class="bar-fill" style="width:${(b.count/max*100).toFixed(1)}%;background:${b.color}"></div>
      </div>
      <span class="bar-count" style="color:${b.color}">${b.count}</span>
    </div>
  `).join("");
}

// ── Inline Detail Panel ──────────────────────────────────────
function showDetail(alert) {
  const e   = alert.event;
  const exp = alert.explanation;
  const risk = alert.risk;

  const rows = [
    ["Username",    e.username],
    ["IP Address",  e.ip_address],
    ["Location",    e.location],
    ["Device",      e.device],
    ["Status",      e.status],
    ["Time",        e.time_str || e.timestamp.slice(11,19)],
    ["Date",        e.date || e.timestamp.slice(0,10)],
    ["Failed Attempts", e.failed_attempts],
    ["Risk Score",  `${risk.score} / 100`],
  ];

  const reasonsHtml = exp.reasons.length
    ? exp.reasons.map(r => `<div class="reason-item">• ${r}</div>`).join("")
    : `<div class="reason-item" style="color:#22C55E">No anomalies detected.</div>`;

  const actionsHtml = exp.actions.length
    ? exp.actions.map(a => `<div class="action-item">${a}</div>`).join("")
    : `<div style="color:#7A8BA4;font-size:.78rem">No action required.</div>`;

  document.getElementById("detail-body").innerHTML = `
    <div style="padding:0.75rem">
      <div style="font-size:.82rem;font-weight:700;color:${risk.color};margin-bottom:.75rem">
        ${exp.summary}
      </div>

      <div class="detail-section">
        <div class="detail-title">Event Info</div>
        ${rows.map(([k,v]) => `
          <div class="detail-row">
            <span>${k}</span><span class="detail-val">${v}</span>
          </div>`).join("")}
      </div>

      ${alert.anomalies.length ? `
      <div class="detail-section">
        <div class="detail-title">AI Explanation</div>
        ${reasonsHtml}
      </div>
      <div class="detail-section">
        <div class="detail-title">Recommended Actions</div>
        ${actionsHtml}
      </div>` : ""}
    </div>
  `;
}

// ── Simulate ─────────────────────────────────────────────────
async function simulate() {
  const btn = document.querySelector(".btn-sim");
  btn.textContent = "⟳ Generating…";
  btn.disabled    = true;

  await fetch("/api/simulate?n=10");
  await fetchStats();
  await fetchAlerts();

  btn.textContent = "⟳ Simulate Events";
  btn.disabled    = false;
}

// ── Modal helpers ─────────────────────────────────────────────
function closeModal() {
  document.getElementById("modal").classList.remove("open");
}

// ── Auto-refresh every 15 seconds ────────────────────────────
async function refresh() {
  await fetchStats();
  await fetchAlerts();
}
setInterval(refresh, 15000);

// ── Initial load ─────────────────────────────────────────────
refresh();
