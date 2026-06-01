/* Operations dashboard for /developer. Vanilla JS, no libraries (CSP). Reads
 * /api/user/developer/{snapshot,tools} and streams new audit events over SSE
 * (/api/user/developer/stream), with a polling fallback. All action controls are
 * UI-prepared but disabled with an honest tooltip until self-service keys land. */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var elFeed = $('#feed'), elTools = $('#tools'), elKeys = $('#keys'),
      elUsage = $('#usage'), elTimeline = $('#timeline'), elHb = $('#hb'),
      elHbLabel = $('#hb-label'), elFlowCap = $('#flow-cap');

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function fmtTs(ts) { if (!ts) return '--:--:--'; var d = new Date(ts); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }
  function fmtDur(ms) { if (ms == null) return '—'; return ms < 1000 ? ms + 'ms' : (ms / 1000).toFixed(1) + 's'; }
  function fmtAgo(ts) { if (!ts) return 'never'; var s = Math.round((Date.now() - ts) / 1000); if (s < 60) return s + 's ago'; if (s < 3600) return Math.round(s / 60) + 'm ago'; if (s < 86400) return Math.round(s / 3600) + 'h ago'; return Math.round(s / 86400) + 'd ago'; }

  // line-icons per tool category
  var ICONS = {
    transfer: 'M3 12h14M12 7l5 5-5 5', backup: 'M4 6c0-1.1 3.6-2 8-2s8 .9 8 2-3.6 2-8 2-8-.9-8-2zM4 6v12c0 1.1 3.6 2 8 2s8-.9 8-2V6',
    sign: 'M4 17l5-5 3 3 7-8M16 7l3-1-1 3', sync: 'M4 9a8 8 0 0 1 13-3l3 3M20 15a8 8 0 0 1-13 3l-3-3M17 6V3M7 18v3',
    ship: 'M12 3v10M8 7l4-4 4 4M4 14v5h16v-5', migrate: 'M3 8h10M9 4l4 4-4 4M14 12h6v8h-6', archive: 'M3 6h18v3H3zM5 9v11h14V9M9 13h6',
    replicate: 'M8 8h11v11H8zM5 5h11v3M5 5v11h3'
  };
  function toolIcon(cat) { return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="' + (ICONS[cat] || ICONS.transfer) + '"/></svg>'; }

  var STATE = { tools: [], status: {}, key: '', filter: '', feed: [] };

  // Which tools can genuinely run in the browser: those whose input is a local
  // file (transfer + sign). The rest need server-side data (an S3 object, your
  // database, a Docker volume), so an in-browser run is impossible -- we say so
  // honestly and point at Configure for the ready-to-run command.
  function browserFlow(cat) {
    if (cat === 'transfer') return { url: '/parashare', label: 'Send a file in your browser' };
    if (cat === 'sign')     return { url: '/sign',      label: 'Sign a file in your browser' };
    return null;
  }
  function serverReason(cat) {
    var needs = { migrate: 'an S3 object or a Docker volume on your host', backup: 'your database', replicate: 'your database', sync: 'your local secrets', archive: 'your git repo', ship: 'your build output or logs' };
    return 'Runs on your machine: it needs ' + (needs[cat] || 'access to your infrastructure') + '. Use Configure for the ready-to-run command.';
  }

  /* ---------- render ---------- */
  function renderHeader(d) {
    var e = document.querySelector('[data-dv="email"]'); if (e) e.textContent = d.email || '—';
    var p = document.querySelector('[data-dv="plan"]'); if (p) p.textContent = (d.plan || '—');
  }
  function renderKeys(d) {
    elKeys.innerHTML =
      '<div class="key-row"><span>' + esc(d.key_masked || '—') + '</span><span class="dim">primary</span></div>' +
      '<div class="key-row"><span class="dim">last used</span><span class="dim">tracked via activity</span></div>' +
      '<div class="key-row"><span class="dim">request rate</span><span class="dim">live with keys (coming)</span></div>';
  }
  function bar(used, cap) {
    var unlimited = cap == null;
    var pct = unlimited ? 4 : Math.min(100, Math.round((used / Math.max(1, cap)) * 100));
    var warn = !unlimited && pct >= 80;
    return { pct: pct, warn: warn, unlimited: unlimited };
  }
  function renderUsage(d) {
    var q = d.quota || { transfers: 0, signs: 0, caps: {} };
    function row(label, used, cap) {
      var b = bar(used, cap);
      var capTxt = b.unlimited ? '∞' : cap;
      return '<div class="usage-row"><div class="lab"><span>' + label + '</span><span><b>' + used + '</b> / ' + capTxt + '</span></div>' +
        '<div class="bar' + (b.warn ? ' warn' : '') + '"><i style="width:' + b.pct + '%"></i></div>' +
        (b.warn ? '<a class="upsell" href="/pricing">▲ Upgrade to Pro</a>' : '') + '</div>';
    }
    elUsage.innerHTML = row('Transfers', q.transfers || 0, q.caps && q.caps.transfers) +
      row('Signings', q.signs || 0, q.caps && q.caps.signs) +
      '<div class="dim mono" style="font-size:10px">live · refreshes every 5s · source: relay quota counters</div>';
  }
  function renderTools() {
    if (!STATE.tools.length) { elTools.innerHTML = '<div class="dim mono" style="font-size:12px">No tools.</div>'; return; }
    elTools.innerHTML = STATE.tools.map(function (t) {
      var st = STATE.status[t.name] || { state: 'never_used' };
      var statusTxt = st.state === 'never_used' ? 'never used' : st.state;
      var statsHtml = st.state === 'never_used'
        ? '<details class="tool-install"><summary>Install &amp; run ▸</summary><pre>' +
            esc(t.install) + '\n\n' + esc((t.usage || '').replace('{KEY}', STATE.key || 'pgp_…')) + '</pre></details>'
        : '<div class="tool-stats"><span>last <b>' + fmtAgo(st.last_run) + '</b></span>' +
            (st.success_rate != null ? '<span><b>' + st.success_rate + '%</b> ok/wk</span>' : '') +
            (st.avg_ms != null ? '<span>avg <b>' + fmtDur(st.avg_ms) + '</b></span>' : '') + '</div>';
      var flow = browserFlow(t.category);
      var runBtn = flow
        ? '<button class="dev-btn dev-btn-go" data-run="' + esc(flow.url) + '" title="' + esc(flow.label) + '">Run in browser</button>'
        : '<button class="dev-btn" disabled title="' + esc(serverReason(t.category)) + '">Run in browser</button>';
      return '<div class="dev-card tool">' +
        '<div class="tool-top"><div class="tool-icon">' + toolIcon(t.category) + '</div>' +
        '<div><div class="tool-name">' + esc(t.name) + '</div>' +
        '<span class="tool-status ' + (st.state === 'never_used' ? '' : st.state) + '"><span class="sd"></span>' + statusTxt + '</span></div></div>' +
        '<p class="tool-tag">' + esc(t.tagline) + '</p>' + statsHtml +
        '<div class="tool-actions">' +
          runBtn +
          '<button class="dev-btn dev-btn-go" data-config="' + esc(t.name) + '">Configure</button>' +
          '<a class="dev-link" href="' + esc(t.source) + '" target="_blank" rel="noopener">View source ↗</a>' +
        '</div></div>';
    }).join('');
  }
  function timelineRow(ev) {
    return '<div class="tl-row" data-ev="' + esc((ev.event_type || '') + ' ' + JSON.stringify(ev.metadata || {})) + '">' +
      '<span class="t">' + fmtTs(ev.ts) + '</span><span class="e">' + esc(ev.event_type || 'event') + '</span></div>';
  }
  function renderTimeline(events) {
    var f = STATE.filter.toLowerCase();
    var rows = events.filter(function (ev) { return !f || (ev.event_type || '').toLowerCase().indexOf(f) >= 0 || JSON.stringify(ev.metadata || {}).toLowerCase().indexOf(f) >= 0; });
    elTimeline.innerHTML = rows.length ? rows.map(timelineRow).join('') : '<div class="dim mono" style="font-size:11px;padding:6px 0">No events' + (f ? ' match "' + esc(STATE.filter) + '"' : ' yet') + '.</div>';
  }

  /* ---------- live feed + flow ---------- */
  function feedRow(ev, fresh) {
    var meta = ev.metadata || {};
    var target = meta.target || meta.tool || meta.email || meta.device || '';
    var result = meta.result || (/(_failed|_error|regression)$/.test(ev.event_type || '') ? 'fail' : 'ok');
    return '<div class="feed-row' + (fresh ? ' fresh' : '') + '"><span class="t">' + fmtTs(ev.ts) + '</span>' +
      '<span class="ev">' + esc(ev.event_type || 'event') + '</span>' +
      '<span class="tg">' + esc(target) + '</span>' +
      '<span class="rs ' + (result === 'fail' ? 'fail' : 'ok') + '">' + esc(result) + '</span></div>';
  }
  function pushFeed(ev, fresh) {
    STATE.feed.unshift(ev); STATE.feed = STATE.feed.slice(0, 10);
    elFeed.innerHTML = STATE.feed.map(function (e, i) { return feedRow(e, fresh && i === 0); }).join('');
    var rows = elFeed.children;
    for (var i = 0; i < rows.length; i++) rows[i].style.opacity = String(Math.max(0.35, 1 - i * 0.07));
    if (fresh) playFlow(ev);
  }
  var FLOW = ['fn-device', 'fa-1', 'fn-relay', 'fa-2', 'fn-recv', 'fa-3', 'fn-burn'];
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  function playFlow(ev) {
    if (elFlowCap) elFlowCap.innerHTML = '<b>' + esc(ev.event_type || 'event') + '</b> · ' + fmtTs(ev.ts);
    if (reduce) { FLOW.forEach(function (id) { var n = document.getElementById(id); if (n) n.classList.add('on'); }); return; }
    FLOW.forEach(function (id) { var n = document.getElementById(id); if (n) n.classList.remove('on'); });
    FLOW.forEach(function (id, i) { setTimeout(function () { var n = document.getElementById(id); if (n) n.classList.add('on'); }, i * 230); });
  }

  /* ---------- heartbeat ---------- */
  function heartbeat(state) {
    elHb.className = 'hb-dot ' + state;
    elHbLabel.textContent = state === 'up' ? 'relay reachable · streaming' : state === 'poll' ? 'polling fallback' : 'disconnected';
  }

  /* ---------- data flow ---------- */
  function applySnapshot(d) {
    renderHeader(d); renderKeys(d); renderUsage(d); STATE.status = d.tools_status || {};
    renderTimeline(d.audit || []);
    if (d.audit && d.audit.length && !STATE.feed.length) { STATE.feed = d.audit.slice(0, 10).slice().reverse(); STATE.feed.forEach(function () {}); STATE.feed = d.audit.slice(0, 10); elFeed.innerHTML = STATE.feed.map(function (e) { return feedRow(e, false); }).join(''); }
    renderTools();
  }
  function getJSON(url) { return fetch(url, { credentials: 'include', headers: { Accept: 'application/json' }, cache: 'no-store' }).then(function (r) { if (!r.ok) throw new Error('http ' + r.status); return r.json(); }); }

  function refreshSnapshot() { return getJSON('/api/user/developer/snapshot').then(applySnapshot); }

  /* SSE with polling fallback */
  var lastPing = 0, pollTimer = null, es = null;
  function startPolling() {
    if (pollTimer) return;
    heartbeat('poll');
    pollTimer = setInterval(function () { refreshSnapshot().then(function () { heartbeat('poll'); }).catch(function () { heartbeat('down'); }); }, 5000);
  }
  function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
  function connectSSE() {
    if (!window.EventSource) { startPolling(); return; }
    try { es = new EventSource('/api/user/developer/stream'); } catch (e) { startPolling(); return; }
    es.addEventListener('hello', function () { lastPing = Date.now(); heartbeat('up'); stopPolling(); });
    es.addEventListener('ping', function () { lastPing = Date.now(); heartbeat('up'); });
    es.addEventListener('audit', function (m) {
      try { var ev = JSON.parse(m.data); pushFeed(ev, true); STATE.status = STATE.status || {}; renderTimeline([ev].concat(STATE.feed.slice(1))); } catch (e) {}
    });
    es.onerror = function () { heartbeat('poll'); startPolling(); };
  }
  // quota stays fresh even over SSE: light snapshot poll every 5s
  setInterval(function () { refreshSnapshot().catch(function () {}); }, 5000);
  // watchdog: if no ping for 8s, mark polling
  setInterval(function () { if (es && Date.now() - lastPing > 8000) { heartbeat('poll'); startPolling(); } }, 4000);

  /* filter */
  var fi = $('#tl-filter'); if (fi) fi.addEventListener('input', function () { STATE.filter = fi.value; getJSON('/api/user/developer/snapshot').then(function (d) { renderTimeline(d.audit || []); }).catch(function () {}); });

  /* ---------- tool actions: run-in-browser + the configure modal ---------- */
  if (elTools) {
    elTools.addEventListener('click', function (ev) {
      var run = ev.target.closest && ev.target.closest('[data-run]');
      if (run) { window.location.href = run.getAttribute('data-run'); return; }
      var cfg = ev.target.closest && ev.target.closest('[data-config]');
      if (cfg) { openConfig(cfg.getAttribute('data-config')); }
    });
  }
  function openConfig(name) {
    var t = null, i;
    for (i = 0; i < STATE.tools.length; i++) { if (STATE.tools[i].name === name) { t = STATE.tools[i]; break; } }
    var modal = document.getElementById('dev-modal');
    if (!t || !modal) return;
    var key = STATE.key || '';
    var run = (t.usage || '').replace('{KEY}', key || 'pgp_YOUR_KEY');
    modal.querySelector('[data-m="title"]').textContent = 'Configure ' + t.name;
    modal.querySelector('[data-m="tag"]').textContent = t.tagline || '';
    modal.querySelector('[data-m="install"]').textContent = t.install || '';
    modal.querySelector('[data-m="key"]').textContent = 'export PARAMANT_API_KEY=' + (key || '<reveal it in the API keys panel>');
    modal.querySelector('[data-m="run"]').value = run;
    modal.querySelector('[data-m="source"]').setAttribute('href', t.source || '#');
    var bf = browserFlow(t.category), rib = modal.querySelector('[data-m="browser"]');
    if (rib) { if (bf) { rib.hidden = false; rib.setAttribute('href', bf.url); rib.textContent = '▶ ' + bf.label + ' →'; } else { rib.hidden = true; } }
    modal.hidden = false;
  }
  (function wireModal() {
    var modal = document.getElementById('dev-modal');
    if (!modal) return;
    function close() { modal.hidden = true; }
    modal.addEventListener('click', function (ev) {
      if (ev.target === modal || (ev.target.closest && ev.target.closest('[data-m="close"]'))) { close(); return; }
      var c = ev.target.closest && ev.target.closest('[data-copy]');
      if (!c) return;
      var src = modal.querySelector('[data-m="' + c.getAttribute('data-copy') + '"]');
      if (!src) return;
      var text = (src.tagName === 'TEXTAREA' || src.tagName === 'INPUT') ? src.value : src.textContent;
      if (navigator.clipboard && text) {
        navigator.clipboard.writeText(text).then(function () { var o = c.textContent; c.textContent = 'copied'; setTimeout(function () { c.textContent = o; }, 1200); }).catch(function () {});
      }
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !modal.hidden) close(); });
  })();

  /* ---------- boot ---------- */
  function boot() {
    heartbeat('poll');
    Promise.all([
      getJSON('/api/user/developer/snapshot'),
      getJSON('/api/user/developer/tools').catch(function () { return { tools: [] }; }),
      getJSON('/api/user/account/key').then(function (k) { return k.api_key || ''; }).catch(function () { return ''; })
    ]).then(function (res) {
      STATE.tools = res[1].tools || []; STATE.key = res[2];
      applySnapshot(res[0]);
      connectSSE();
    }).catch(function () { heartbeat('down'); elTools.innerHTML = '<div class="dim mono" style="font-size:12px">Could not load dashboard data.</div>'; });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
