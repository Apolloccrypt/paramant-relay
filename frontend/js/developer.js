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

  var STATE = { tools: [], status: {}, key: '', filter: '', feed: [], cfg: {} };

  // Which tools can genuinely run in the browser: those whose input is a local
  // file (transfer + sign). The rest need server-side data (an S3 object, your
  // database, a Docker volume), so an in-browser run is impossible -- we say so
  // honestly and point at Configure for the ready-to-run command.
  function browserFlow(cat) {
    if (cat === 'sign') return { url: '/sign', label: 'Sign a file in your browser' };
    // file-input tools: the browser does the encrypt-and-send half (a transfer);
    // the server-side prep (git archive, collecting artifacts) stays on you.
    if (cat === 'transfer' || cat === 'archive' || cat === 'ship' || cat === 'sync')
      return { url: '/parashare', label: 'Send a file in your browser' };
    return null; // migrate, backup, replicate need server-side data
  }
  // Hardening: only ever navigate to a known internal path. Defence in depth
  // against an open redirect, even though data-run is set by our own code.
  function safeInternalPath(u) {
    return typeof u === 'string' && u.charAt(0) === '/' && u.indexOf('//') === -1 &&
           u.indexOf(':') === -1 && /^[A-Za-z0-9/_.?=&#-]+$/.test(u);
  }
  // A tool's "source" URL comes from the server-rendered tools list. Only treat
  // it as a link if it's an http(s) URL (or a same-origin root-relative path);
  // anything else (javascript:, data:, ...) becomes '#' so it can't execute.
  function safeSourceUrl(u) {
    var s = String(u == null ? '' : u).trim();
    if (/^\/(?!\/)/.test(s)) { return s; }
    try {
      var url = new URL(s, location.origin);
      if (url.protocol === 'http:' || url.protocol === 'https:') { return url.href; }
    } catch (e) { /* not parseable */ }
    return '#';
  }
  // Per-user (per-browser) tool config: remembers your edited command per tool.
  // localStorage only -- no server, no new attack surface. Holds non-sensitive
  // params (bucket, recipient); never the key (the command uses $PARAMANT_API_KEY).
  var CFG_PREFIX = 'paramant.devcfg.v1.';
  function loadCfg(tool) { try { return localStorage.getItem(CFG_PREFIX + tool); } catch (e) { return null; } }
  function saveCfg(tool, val) { try { localStorage.setItem(CFG_PREFIX + tool, String(val).slice(0, 2000)); return true; } catch (e) { return false; } }
  function clearCfg(tool) { try { localStorage.removeItem(CFG_PREFIX + tool); } catch (e) {} }
  // Cross-device sync via the gated, account-scoped server store. Best-effort:
  // the localStorage cache above keeps Configure working if the server is
  // unreachable. The server refuses to persist anything that looks like a key.
  function saveCfgServer(tool, command) {
    return fetch('/api/user/developer/tool-config', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tool: tool, command: command }) }).catch(function () {});
  }
  function clearCfgServer(tool) {
    return fetch('/api/user/developer/tool-config', { method: 'DELETE', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tool: tool }) }).catch(function () {});
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
          '<a class="dev-link" href="' + esc(safeSourceUrl(t.source)) + '" target="_blank" rel="noopener">View source ↗</a>' +
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

  /* SSE with polling fallback.
   * ONE shared 5s snapshot poll runs for the whole page: it keeps the quota
   * fresh even while SSE is up, and IS the fallback when SSE drops. We never
   * spin up a second poll loop, so the dashboard polls /snapshot at most once
   * per interval (previously startPolling()'s timer + the quota timer both ran,
   * double-polling during the fallback). The heartbeat is gated on SSE health:
   * if SSE has pinged within the window we show 'up', otherwise 'poll'. */
  var lastPing = 0, es = null;
  var SSE_STALE_MS = 8000;
  function sseHealthy() { return !!es && (Date.now() - lastPing) <= SSE_STALE_MS; }
  function connectSSE() {
    if (!window.EventSource) { heartbeat('poll'); return; }
    try { es = new EventSource('/api/user/developer/stream'); } catch (e) { es = null; heartbeat('poll'); return; }
    es.addEventListener('hello', function () { lastPing = Date.now(); heartbeat('up'); });
    es.addEventListener('ping', function () { lastPing = Date.now(); heartbeat('up'); });
    es.addEventListener('audit', function (m) {
      try { var ev = JSON.parse(m.data); pushFeed(ev, true); STATE.status = STATE.status || {}; renderTimeline([ev].concat(STATE.feed.slice(1))); } catch (e) {}
    });
    es.onerror = function () { heartbeat('poll'); };
  }
  // Single shared timer: refresh the snapshot every 5s and set the heartbeat
  // from SSE health (so the live audit stream stays primary, polling backstops).
  setInterval(function () {
    refreshSnapshot()
      .then(function () { heartbeat(sseHealthy() ? 'up' : 'poll'); })
      .catch(function () { heartbeat('down'); });
  }, 5000);

  /* filter */
  var fi = $('#tl-filter'); if (fi) fi.addEventListener('input', function () { STATE.filter = fi.value; getJSON('/api/user/developer/snapshot').then(function (d) { renderTimeline(d.audit || []); }).catch(function () {}); });

  /* ---------- tool actions: run-in-browser + the configure modal ---------- */
  if (elTools) {
    elTools.addEventListener('click', function (ev) {
      var run = ev.target.closest && ev.target.closest('[data-run]');
      if (run) { var u = run.getAttribute('data-run'); if (safeInternalPath(u)) window.location.assign(u); return; }
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
    // The command relies on the PARAMANT_API_KEY env var (step 2), so the key is
    // never inlined -> nothing sensitive ever reaches localStorage.
    var def = (t.usage || '').replace(/^PARAMANT_API_KEY=\{KEY\}\s+/, '').replace('{KEY}', '$PARAMANT_API_KEY');
    var saved = (STATE.cfg && STATE.cfg[t.name] != null) ? STATE.cfg[t.name] : loadCfg(t.name);
    modal.querySelector('[data-m="title"]').textContent = 'Configure ' + t.name;
    modal.querySelector('[data-m="tag"]').textContent = t.tagline || '';
    modal.querySelector('[data-m="install"]').textContent = t.install || '';
    modal.querySelector('[data-m="key"]').textContent = 'export PARAMANT_API_KEY=' + (key || '<reveal it in the API keys panel>');
    var runEl = modal.querySelector('[data-m="run"]');
    runEl.value = saved != null ? saved : def;
    runEl.setAttribute('data-default', def);
    modal.setAttribute('data-tool', t.name);
    var savedNote = modal.querySelector('[data-m="saved"]'); if (savedNote) savedNote.hidden = (saved == null);
    modal.querySelector('[data-m="source"]').setAttribute('href', safeSourceUrl(t.source));
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
      var save = ev.target.closest && ev.target.closest('[data-m="save"]');
      if (save) {
        var tool = modal.getAttribute('data-tool'), ta = modal.querySelector('[data-m="run"]');
        if (tool && ta) {
          saveCfg(tool, ta.value); STATE.cfg[tool] = ta.value; saveCfgServer(tool, ta.value);
          var sn = modal.querySelector('[data-m="saved"]'); if (sn) sn.hidden = false;
          var os = save.textContent; save.textContent = 'saved'; setTimeout(function () { save.textContent = os; }, 1200);
        }
        return;
      }
      var reset = ev.target.closest && ev.target.closest('[data-m="reset"]');
      if (reset) {
        var tool2 = modal.getAttribute('data-tool'), ta2 = modal.querySelector('[data-m="run"]');
        if (tool2 && ta2) { clearCfg(tool2); delete STATE.cfg[tool2]; clearCfgServer(tool2); ta2.value = ta2.getAttribute('data-default') || ''; var sn2 = modal.querySelector('[data-m="saved"]'); if (sn2) sn2.hidden = true; }
        return;
      }
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

  /* ---------- self-service ParaSign key minting ("+ New key") ---------- */
  var PSK_API = '/api/user/developer/parasign-keys';
  function renderPskKeys(list) {
    var el = document.getElementById('psk-keys'); if (!el) return;
    if (!list || !list.length) { el.textContent = ''; return; }
    el.innerHTML = list.map(function (k) {
      return '<div class="key-row"><span>' + esc(k.key_masked || k.kid || '—') + '</span><span class="dim">' + esc(k.mode || 'live') + (k.active === false ? ' · revoked' : '') + '</span></div>';
    }).join('');
  }
  function loadPskKeys() {
    return getJSON(PSK_API).then(function (d) { renderPskKeys((d && d.keys) || []); }).catch(function () {});
  }
  function pskView(name) {
    ['confirm', 'key', 'error'].forEach(function (v) {
      var n = document.querySelector('#psk-modal [data-psk="view-' + v + '"]');
      if (n) n.hidden = (v !== name);
    });
  }
  function openPsk() { var m = document.getElementById('psk-modal'); if (!m) return; pskView('confirm'); m.hidden = false; }
  function closePsk() { var m = document.getElementById('psk-modal'); if (m) m.hidden = true; }
  function mintPsk() {
    var m = document.getElementById('psk-modal'); if (!m) return;
    var gen = m.querySelector('[data-psk="generate"]'); if (gen) { gen.disabled = true; gen.textContent = 'Generating…'; }
    fetch(PSK_API, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', Accept: 'application/json' }, cache: 'no-store', body: JSON.stringify({}) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }).catch(function () { return { status: r.status, body: {} }; }); })
      .then(function (res) {
        if (gen) { gen.disabled = false; gen.textContent = 'Generate key'; }
        if (res.status === 201 && res.body && res.body.key) {
          m.querySelector('[data-psk="keyval"]').textContent = res.body.key;
          m.querySelector('[data-psk="meta"]').textContent = 'kid ' + (res.body.kid || '—') + ' · ' + (res.body.mode || 'live') + ' · plan ' + (res.body.plan || '—');
          pskView('key'); loadPskKeys();
        } else if (res.status === 403) {
          var em = m.querySelector('[data-psk="errmsg"]'); if (em) em.textContent = (res.body && res.body.message) || 'This account is not entitled to the ParaSign API. Upgrade to a paid plan or ask an admin to enable ParaSign.';
          var up = m.querySelector('[data-psk="upsell"]'); if (up) up.hidden = false;
          pskView('error');
        } else {
          var em2 = m.querySelector('[data-psk="errmsg"]'); if (em2) em2.textContent = 'Could not create a key (' + ((res.body && res.body.error) || ('http ' + res.status)) + '). Please try again.';
          var up2 = m.querySelector('[data-psk="upsell"]'); if (up2) up2.hidden = true;
          pskView('error');
        }
      })
      .catch(function () {
        if (gen) { gen.disabled = false; gen.textContent = 'Generate key'; }
        var em3 = m.querySelector('[data-psk="errmsg"]'); if (em3) em3.textContent = 'Network error while creating the key. Please try again.';
        var up3 = m.querySelector('[data-psk="upsell"]'); if (up3) up3.hidden = true;
        pskView('error');
      });
  }
  (function wirePsk() {
    var btn = document.getElementById('psk-new');
    if (btn) btn.addEventListener('click', openPsk);
    var m = document.getElementById('psk-modal');
    if (!m) return;
    m.addEventListener('click', function (ev) {
      var t = ev.target;
      if (t === m || (t.closest && t.closest('[data-psk="close"]'))) { closePsk(); return; }
      if (t.closest && t.closest('[data-psk="done"]')) { closePsk(); return; }
      if (t.closest && t.closest('[data-psk="generate"]')) { mintPsk(); return; }
      var cp = t.closest && t.closest('[data-psk="copy"]');
      if (cp) {
        var kv = m.querySelector('[data-psk="keyval"]'); var text = kv ? kv.textContent : '';
        if (navigator.clipboard && text) { navigator.clipboard.writeText(text).then(function () { var o = cp.textContent; cp.textContent = 'copied'; setTimeout(function () { cp.textContent = o; }, 1200); }).catch(function () {}); }
      }
    });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !m.hidden) closePsk(); });
  })();

  /* ---------- boot ---------- */
  function boot() {
    heartbeat('poll');
    Promise.all([
      getJSON('/api/user/developer/snapshot'),
      getJSON('/api/user/developer/tools').catch(function () { return { tools: [] }; }),
      getJSON('/api/user/account/key').then(function (k) { return k.api_key || ''; }).catch(function () { return ''; }),
      getJSON('/api/user/developer/tool-config').then(function (c) { return c.configs || {}; }).catch(function () { return {}; })
    ]).then(function (res) {
      STATE.tools = res[1].tools || []; STATE.key = res[2]; STATE.cfg = res[3] || {};
      applySnapshot(res[0]);
      connectSSE();
      loadPskKeys();
    }).catch(function () { heartbeat('down'); elTools.innerHTML = '<div class="dim mono" style="font-size:12px">Could not load dashboard data.</div>'; });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();
