
(function () {
  var SECTORS = [
    { id: 'relay',   label: 'RELAY',   url: 'https://relay.paramant.app',   host: 'relay.paramant.app' },
    { id: 'health',  label: 'HEALTH',  url: 'https://health.paramant.app',  host: 'health.paramant.app' },
    { id: 'legal',   label: 'LEGAL',   url: 'https://legal.paramant.app',   host: 'legal.paramant.app' },
    { id: 'finance', label: 'FINANCE', url: 'https://finance.paramant.app', host: 'finance.paramant.app' },
    { id: 'iot',     label: 'IoT',     url: 'https://iot.paramant.app',     host: 'iot.paramant.app' },
  ];

  var STORAGE_KEY = 'paramant_status_v1';
  var WINDOW_MS   = 24 * 60 * 60 * 1000;

  function loadHistory() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch { return {}; }
  }
  function saveHistory(h) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(h)); } catch {}
  }
  function pruneHistory(h) {
    var cutoff = Date.now() - WINDOW_MS;
    SECTORS.forEach(function (s) {
      if (h[s.id]) h[s.id] = h[s.id].filter(function (r) { return r.ts > cutoff; });
    });
    return h;
  }
  function addResult(h, id, ok) {
    if (!h[id]) h[id] = [];
    h[id].push({ ts: Date.now(), ok: ok });
    return h;
  }
  function uptimePct(h, id) {
    var arr = h[id];
    if (!arr || arr.length === 0) return null;
    var good = arr.filter(function (r) { return r.ok; }).length;
    return (good / arr.length * 100).toFixed(1);
  }

  // Build cards once
  var grid = document.getElementById('sectorGrid');
  SECTORS.forEach(function (s) {
    var card = document.createElement('div');
    card.className = 'sector-card';
    card.id = 'card-' + s.id;
    card.innerHTML =
      '<div class="card-top">' +
        '<div class="sector-name">' + s.label + '</div>' +
        '<div class="dot checking" id="dot-' + s.id + '"></div>' +
      '</div>' +
      '<div class="card-status" id="status-' + s.id + '">Checking&hellip;</div>' +
      '<div class="meta-row">' +
        '<div class="meta-item">version <span id="ver-' + s.id + '">&mdash;</span></div>' +
        '<div class="meta-item">latency <span id="ms-' + s.id + '">&mdash;</span></div>' +
        '<div class="meta-item">uptime 24h <span id="up-' + s.id + '">&mdash;</span></div>' +
      '</div>' +
      '<div class="sector-url"><a href="' + s.url + '/health" target="_blank" rel="noopener">' + s.host + '/health</a></div>';
    grid.appendChild(card);
  });

  function setCard(s, state, data, ms) {
    var card    = document.getElementById('card-' + s.id);
    var dot     = document.getElementById('dot-' + s.id);
    var statusEl = document.getElementById('status-' + s.id);
    var verEl   = document.getElementById('ver-' + s.id);
    var msEl    = document.getElementById('ms-' + s.id);

    card.className    = 'sector-card ' + (state === 'ok' ? 'ok' : state === 'checking' ? '' : 'degraded');
    dot.className     = 'dot ' + state;
    statusEl.className = 'card-status ' + (state === 'ok' ? 'ok' : state === 'checking' ? '' : 'degraded');
    statusEl.textContent = state === 'ok' ? 'Operational' : state === 'checking' ? 'Checking\u2026' : 'Degraded';

    if (data && data.version) verEl.textContent = 'v' + data.version;
    if (ms !== undefined) msEl.textContent = ms + 'ms';
  }

  function setUptime(id, pct) {
    var el = document.getElementById('up-' + id);
    if (el && pct !== null) el.textContent = pct + '%';
  }

  function setOverall(allOk, anyChecked) {
    var el   = document.getElementById('overall');
    var dot  = document.getElementById('overallDot');
    var text = document.getElementById('overallText');
    if (!anyChecked) {
      el.className = 'overall checking'; dot.className = 'dot-large checking';
      text.textContent = 'Checking all sectors\u2026';
    } else if (allOk) {
      el.className = 'overall ok'; dot.className = 'dot-large ok';
      text.textContent = 'All systems operational';
    } else {
      el.className = 'overall degraded'; dot.className = 'dot-large degraded';
      text.textContent = 'One or more sectors degraded';
    }
  }

  function checkAll() {
    var h = pruneHistory(loadHistory());
    var results = {};
    var pending = SECTORS.length;

    SECTORS.forEach(function (s) {
      var t0 = Date.now();
      fetch(s.url + '/health', { signal: AbortSignal.timeout(8000) })
        .then(function (r) {
          var ms = Date.now() - t0;
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json().then(function (body) {
            results[s.id] = { ok: true, ms: ms, data: body };
            setCard(s, 'ok', body, ms);
            addResult(h, s.id, true);
          });
        })
        .catch(function () {
          results[s.id] = { ok: false };
          setCard(s, 'degraded', null, undefined);
          addResult(h, s.id, false);
        })
        .finally(function () {
          setUptime(s.id, uptimePct(h, s.id));
          pending--;
          if (pending === 0) {
            saveHistory(h);
            var allOk = SECTORS.every(function (sec) { return results[sec.id] && results[sec.id].ok; });
            setOverall(allOk, true);
            var now = new Date();
            document.getElementById('lastChecked').textContent =
              'Last checked: ' + now.toLocaleTimeString() + ' \u2014 next check in 30s';
          }
        });
    });
  }

  // Initial state
  SECTORS.forEach(function (s) { setCard(s, 'checking'); });
  setOverall(false, false);

  // Run immediately, then every 30s
  checkAll();
  setInterval(checkAll, 30000);
}());
