/* Dashboard: "Your history" view + ParaSign audit export.
 *
 * Surfaces two relay endpoints on the user dashboard, CSP-safe (external JS,
 * no inline script):
 *   GET /v2/user/history            per-account send/envelope history (Pro+)
 *   GET /v2/parasign/audit-export   signing-audit export, CSV or JSON (Business+)
 *
 * Both are gated by X-Api-Key (a pgp_ key). The browser never stores that key:
 * it reveals the account's own primary key on demand via the session-cookie
 * endpoint /api/user/account/key (the same source the developer dashboard uses),
 * calls the relay, then drops it. A 403 renders an honest upgrade/lock message.
 *
 * ASCII-only. Vanilla JS, no libraries.
 */
(function () {
  'use strict';

  var histLoad = document.getElementById('dh-hist-load');
  var histBody = document.getElementById('dh-hist-body');
  var expCsv   = document.getElementById('dh-export-csv');
  var expJson  = document.getElementById('dh-export-json');
  var expBody  = document.getElementById('dh-export-body');
  // Nothing to wire if the markup is absent (e.g. a trimmed dashboard).
  if (!histLoad && !expCsv && !expJson) return;

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c];
    });
  }
  function fmtTime(ts) {
    if (!ts) return '--';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return String(ts).slice(0, 19);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    var mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getMonth()];
    return d.getDate() + ' ' + mon + ' ' + d.getFullYear() + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function statusLabel(s) {
    return ({
      sent: 'sent',
      aborted: 'aborted',
      downloaded: 'downloaded',
      downloaded_burned: 'downloaded (burned)'
    })[s] || (s || 'event');
  }

  // Reveal (and cache for the page lifetime) the account's own primary pgp_ key
  // via the session-cookie endpoint. Never persisted anywhere.
  var _keyPromise = null;
  function getApiKey() {
    if (_keyPromise) return _keyPromise;
    _keyPromise = fetch('/api/user/account/key', {
      credentials: 'include', headers: { Accept: 'application/json' }, cache: 'no-store'
    }).then(function (r) {
      if (!r.ok) throw new Error('key_http_' + r.status);
      return r.json();
    }).then(function (j) {
      var k = j && j.api_key;
      if (!k) throw new Error('key_unavailable');
      return k;
    });
    return _keyPromise;
  }

  function upsell(msg, planPath) {
    return '<div class="dh-ops-dim">' + esc(msg) + '</div>' +
      '<div style="margin-top:8px"><a class="dh-btn" href="' + (planPath || '/pricing') + '">Upgrade plan</a></div>';
  }

  /* ---------- history ---------- */
  function renderHistory(entries) {
    if (!entries || !entries.length) {
      histBody.innerHTML = '<div class="dh-ops-dim">No history yet. Your sends and received envelopes will appear here.</div>';
      return;
    }
    histBody.innerHTML = entries.map(function (e) {
      return '<div class="dh-ops-row">' +
        '<span class="mono" title="' + esc(e.id) + '">' + esc(String(e.id || '').slice(0, 16) || '--') + '</span>' +
        '<span class="dim">' + esc(statusLabel(e.status)) + ' &middot; ' + esc(fmtBytes(e.bytes)) + ' &middot; ' + esc(fmtTime(e.time)) + '</span>' +
        '</div>';
    }).join('');
  }

  function loadHistory() {
    if (!histBody) return;
    histLoad.disabled = true;
    var orig = histLoad.textContent;
    histLoad.textContent = 'Loading...';
    histBody.innerHTML = '<div class="dh-ops-dim">Loading your history...</div>';
    getApiKey().then(function (key) {
      return fetch('/v2/user/history?limit=100', {
        headers: { 'X-Api-Key': key, Accept: 'application/json' }, cache: 'no-store'
      }).then(function (r) {
        return r.json().then(function (j) { return { status: r.status, body: j }; })
          .catch(function () { return { status: r.status, body: {} }; });
      });
    }).then(function (res) {
      histLoad.disabled = false; histLoad.textContent = orig;
      if (res.status === 200) { renderHistory(res.body && res.body.entries); return; }
      if (res.status === 403) {
        histBody.innerHTML = upsell((res.body && res.body.message) ||
          'Send history and link management require a Pro plan or higher.', '/pricing');
        return;
      }
      if (res.status === 401) {
        histBody.innerHTML = '<div class="dh-ops-dim">Please sign in again to view your history.</div>';
        return;
      }
      histBody.innerHTML = '<div class="dh-ops-dim">Could not load history (' +
        esc((res.body && res.body.error) || ('HTTP ' + res.status)) + ').</div>';
    }).catch(function () {
      histLoad.disabled = false; histLoad.textContent = orig;
      histBody.innerHTML = '<div class="dh-ops-dim">Network error while loading history.</div>';
    });
  }

  /* ---------- audit export ---------- */
  function triggerDownload(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  function runExport(format, btn) {
    if (!expBody) return;
    var buttons = [expCsv, expJson];
    buttons.forEach(function (b) { if (b) b.disabled = true; });
    var orig = btn.textContent;
    btn.textContent = 'Preparing...';
    var isCsv = format === 'csv';
    var url = isCsv ? '/v2/parasign/audit-export?format=csv' : '/v2/parasign/audit-export';
    getApiKey().then(function (key) {
      return fetch(url, {
        headers: { 'X-Api-Key': key, Accept: isCsv ? 'text/csv' : 'application/json' }, cache: 'no-store'
      }).then(function (r) {
        if (r.status === 200) {
          return r.blob().then(function (blob) { return { status: 200, blob: blob }; });
        }
        return r.json().then(function (j) { return { status: r.status, body: j }; })
          .catch(function () { return { status: r.status, body: {} }; });
      });
    }).then(function (res) {
      buttons.forEach(function (b) { if (b) b.disabled = false; });
      btn.textContent = orig;
      if (res.status === 200) {
        triggerDownload(res.blob, isCsv ? 'parasign_audit.csv' : 'parasign_audit.json');
        expBody.innerHTML = '<div class="dh-ops-dim">Export ready. Your download has started (' +
          (isCsv ? 'CSV' : 'JSON') + ').</div>';
        return;
      }
      if (res.status === 403) {
        expBody.innerHTML = upsell((res.body && res.body.message) ||
          'The ParaSign audit export requires a Business plan or higher.', '/pricing');
        return;
      }
      if (res.status === 401) {
        expBody.innerHTML = '<div class="dh-ops-dim">Please sign in again to export your audit trail.</div>';
        return;
      }
      expBody.innerHTML = '<div class="dh-ops-dim">Could not build the export (' +
        esc((res.body && res.body.error) || ('HTTP ' + res.status)) + ').</div>';
    }).catch(function () {
      buttons.forEach(function (b) { if (b) b.disabled = false; });
      btn.textContent = orig;
      expBody.innerHTML = '<div class="dh-ops-dim">Network error while building the export.</div>';
    });
  }

  /* ---------- wire ---------- */
  if (histLoad) histLoad.addEventListener('click', loadHistory);
  if (expCsv) expCsv.addEventListener('click', function () { runExport('csv', expCsv); });
  if (expJson) expJson.addEventListener('click', function () { runExport('json', expJson); });
})();
