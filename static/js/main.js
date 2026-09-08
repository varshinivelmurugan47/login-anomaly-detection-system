var allAlerts = [];
var autoTimer = null;
var riskChart = null;
var lineChart = null;
var countHistory = [];

// Clock
setInterval(function() {
  var el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}, 1000);

// Simulate login
function simulate(forceAnomaly) {
  fetch('/api/simulate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ force_anomaly: forceAnomaly })
  })
  .then(function(res) { return res.json(); })
  .then(function(data) {
    allAlerts.unshift(data);
    refresh();
    if (data.flagged) flashHeader();
  })
  .catch(function(err) {
    console.error('Error:', err);
    alert('Error: ' + err.message);
  });
}

// Toggle auto simulate
function toggleAuto() {
  var btn = document.getElementById('autoBtn');
  if (autoTimer) {
    clearInterval(autoTimer);
    autoTimer = null;
    btn.textContent = '🔄 Auto: OFF';
    btn.classList.remove('on');
  } else {
    autoTimer = setInterval(function() {
      simulate(Math.random() < 0.3);
    }, 2500);
    btn.textContent = '🔄 Auto: ON';
    btn.classList.add('on');
  }
}

// Clear all
function clearAll() {
  fetch('/api/clear', { method: 'POST' })
  .then(function() {
    allAlerts = [];
    countHistory = [];
    refresh();
  });
}

// Refresh all UI
function refresh() {
  renderFeed();
  renderStats();
  renderCharts();
  renderSessions();
}

// Render alert feed
function renderFeed() {
  var filterEl = document.getElementById('filterSel');
  var filter = filterEl ? filterEl.value : 'all';
  var list = [];
  if (filter === 'all') {
    list = allAlerts;
  } else {
    for (var i = 0; i < allAlerts.length; i++) {
      if (allAlerts[i].risk.level === filter) {
        list.push(allAlerts[i]);
      }
    }
  }

  var feed = document.getElementById('alertFeed');
  var badge = document.getElementById('feedCount');
  if (badge) badge.textContent = list.length;

  if (!feed) return;

  if (list.length === 0) {
    feed.innerHTML = '<div class="empty-msg">No events yet — click Simulate Login to start</div>';
    return;
  }

  var html = '';
  for (var i = 0; i < list.length; i++) {
    var a = list[i];
    var tagHtml = '';
    if (a.flagged) {
      for (var j = 0; j < a.anomalies.length; j++) {
        tagHtml += '<span class="a-tag">' + a.anomalies[j].type + '</span>';
      }
    } else {
      tagHtml = '<span style="color:#14B8A6;font-size:.72rem">Normal</span>';
    }

    html += '<div class="alert-row" onclick="openModal(' + i + ',\'' + filter + '\')">';
    html += '<span class="risk-pill r-' + a.risk.level + '">' + a.risk.level + '</span>';
    html += '<div class="alert-info">';
    html += '<div class="alert-top">';
    html += '<span class="alert-user">User: ' + a.username + '</span>';
    html += '<span class="alert-time">' + a.timestamp.slice(11,16) + '</span>';
    html += '</div>';
    html += '<div class="alert-meta">';
    html += '<span>Location: ' + a.location + '</span>';
    html += '<span>IP: ' + a.ip_address + '</span>';
    html += '<span>Device: ' + a.device.split('/')[0] + '</span>';
    html += tagHtml;
    html += '</div>';
    html += '</div>';
    html += '</div>';
  }
  feed.innerHTML = html;
}

// Render stats
function renderStats() {
  var total = allAlerts.length;
  var flagged = 0;
  var high = 0;
  for (var i = 0; i < allAlerts.length; i++) {
    if (allAlerts[i].flagged) flagged++;
    if (allAlerts[i].risk.level === 'High') high++;
  }
  var t = document.getElementById('sTotal');
  var f = document.getElementById('sFlagged');
  var s = document.getElementById('sSafe');
  var h = document.getElementById('sHigh');
  if (t) t.textContent = total;
  if (f) f.textContent = flagged;
  if (s) s.textContent = total - flagged;
  if (h) h.textContent = high;
}

// Render charts
function renderCharts() {
  var counts = { High: 0, Medium: 0, Low: 0, Safe: 0 };
  for (var i = 0; i < allAlerts.length; i++) {
    var lvl = allAlerts[i].risk.level;
    if (counts[lvl] !== undefined) counts[lvl]++;
  }

  var ctx1 = document.getElementById('riskChart');
  if (ctx1) {
    if (!riskChart) {
      riskChart = new Chart(ctx1.getContext('2d'), {
        type: 'doughnut',
        data: {
          labels: ['High', 'Medium', 'Low', 'Safe'],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: ['#E24B4A', '#F97316', '#EF9F27', '#14B8A6'],
            borderColor: '#131C30',
            borderWidth: 3
          }]
        },
        options: {
          cutout: '65%',
          plugins: {
            legend: { labels: { color: '#B0BAC8', font: { size: 11 } } }
          }
        }
      });
    }
    riskChart.data.datasets[0].data = [counts.High, counts.Medium, counts.Low, counts.Safe];
    riskChart.update();
  }

  countHistory.push(allAlerts.length);
  if (countHistory.length > 15) countHistory.shift();
  var labels = [];
  for (var i = 0; i < countHistory.length; i++) labels.push(i + 1);

  var ctx2 = document.getElementById('lineChart');
  if (ctx2) {
    if (!lineChart) {
      lineChart = new Chart(ctx2.getContext('2d'), {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Events',
            data: countHistory.slice(),
            borderColor: '#1E78C8',
            backgroundColor: 'rgba(30,120,200,.12)',
            pointBackgroundColor: '#1E78C8',
            tension: 0.4,
            fill: true
          }]
        },
        options: {
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#6B7A99' }, grid: { color: '#1E3050' } },
            y: { ticks: { color: '#6B7A99' }, grid: { color: '#1E3050' }, beginAtZero: true }
          }
        }
      });
    } else {
      lineChart.data.labels = labels;
      lineChart.data.datasets[0].data = countHistory.slice();
      lineChart.update();
    }
  }
}

// Render sessions
function renderSessions() {
  var users = {};
  for (var i = 0; i < allAlerts.length; i++) {
    var a = allAlerts[i];
    if (!users[a.username]) {
      users[a.username] = { count: 0, flagged: 0, last: '' };
    }
    users[a.username].count++;
    if (a.flagged) users[a.username].flagged++;
    users[a.username].last = a.timestamp.slice(11, 16);
  }

  var box = document.getElementById('sessionBox');
  if (!box) return;

  var keys = Object.keys(users);
  if (keys.length === 0) {
    box.innerHTML = '<div class="s-empty">No sessions yet</div>';
    return;
  }

  var html = '';
  for (var i = 0; i < keys.length; i++) {
    var name = keys[i];
    var d = users[name];
    html += '<div class="session-row">';
    html += '<div>';
    html += '<div class="s-name">User: ' + name + '</div>';
    html += '<div class="s-info">Last: ' + d.last + ' | Flagged: ' + d.flagged + '</div>';
    html += '</div>';
    html += '<span class="s-count">' + d.count + '</span>';
    html += '</div>';
  }
  box.innerHTML = html;
}

// Open modal
function openModal(index, filter) {
  var list = [];
  if (filter === 'all') {
    list = allAlerts;
  } else {
    for (var i = 0; i < allAlerts.length; i++) {
      if (allAlerts[i].risk.level === filter) list.push(allAlerts[i]);
    }
  }

  var a = list[index];
  if (!a) return;

  var ex = a.explanation;
  var statusColor = a.login_success ? '#14B8A6' : '#E24B4A';
  var statusText  = a.login_success ? 'Success' : 'Failed';

  var pillHtml = '';
  for (var i = 0; i < a.anomalies.length; i++) {
    pillHtml += '<span class="a-pill">' + a.anomalies[i].type + ' +' + a.anomalies[i].weight + '</span>';
  }

  var detailHtml = '';
  for (var i = 0; i < ex.details.length; i++) {
    detailHtml += '<div class="ex-detail">' + ex.details[i].message + '</div>';
  }

  var anomalySection = '';
  if (a.anomalies.length > 0) {
    anomalySection = '<div class="m-anomalies"><div class="lbl">Detected Anomalies</div>' + pillHtml + '</div>';
  }

  var body = document.getElementById('modalBody');
  if (!body) return;

  body.innerHTML =
    '<div class="m-title">Event Detail - ' + a.event_id + '</div>' +
    '<div class="m-grid">' +
      '<div class="m-field"><div class="lbl">Username</div><div class="val">' + a.username + '</div></div>' +
      '<div class="m-field"><div class="lbl">Timestamp</div><div class="val">' + a.timestamp + '</div></div>' +
      '<div class="m-field"><div class="lbl">IP Address</div><div class="val">' + a.ip_address + '</div></div>' +
      '<div class="m-field"><div class="lbl">Location</div><div class="val">' + a.location + '</div></div>' +
      '<div class="m-field"><div class="lbl">Device</div><div class="val">' + a.device + '</div></div>' +
      '<div class="m-field"><div class="lbl">Failed Attempts</div><div class="val">' + a.failed_attempts + '</div></div>' +
      '<div class="m-field"><div class="lbl">Login Status</div><div class="val" style="color:' + statusColor + '">' + statusText + '</div></div>' +
      '<div class="m-field"><div class="lbl">Risk Score</div><div class="val" style="color:' + a.risk.color + '">' + a.risk.score + ' - ' + a.risk.level + '</div></div>' +
    '</div>' +
    anomalySection +
    '<div class="explain-box">' +
      '<div class="ex-summary">' + ex.summary + '</div>' +
      detailHtml +
      '<div class="ex-advice">Advice: ' + ex.advice + '</div>' +
    '</div>';

  document.getElementById('modal').classList.remove('hidden');
}

// Close modal
function closeModal(e) {
  var modal = document.getElementById('modal');
  if (!e || e.target === modal) {
    modal.classList.add('hidden');
  }
}

// Flash header
function flashHeader() {
  var h = document.querySelector('header');
  if (h) {
    h.style.borderBottomColor = '#E24B4A';
    setTimeout(function() {
      h.style.borderBottomColor = '';
    }, 700);
  }
}

// Start
renderFeed();
renderCharts();
renderSessions();
