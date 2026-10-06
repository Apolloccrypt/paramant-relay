/* Dashboard: "Your history" view + ParaSign audit export.
 *
 * Surfaces two relay endpoints on the user dashboard, CSP-safe (external JS,
 * no inline script):
 *   GET /v2/user/history            per-account send/envelope history (Pro+)
 *   GET /v2/parasign/audit-export   signing-audit export, CSV or JSON (Business+)
 *
 * THE CREDENTIAL. Both relay routes are authenticated. This file used to reveal
 * the account's own pgp_ key through /api/user/account/key and send it as
 * X-Api-Key: an unscoped credential with no expiry, in the tab for as long as
 * it stayed open. It now runs on the short-lived scoped token /parashare got in
 * #401. js/app-session-token.js mints a pst_ token with purpose `app`, the
 * relay accepts it on exactly GET /v2/user/history,
 * GET /v2/parasign/audit-export, POST /v2/billing/checkout,
 * POST /v2/billing/redeem and GET /v2/parasign/inbox, and refuses it on
 * everything else, including every other route under /v2/user/*. Fifteen minutes, held in memory, never
 * persisted. A 403 still renders an honest
 * upgrade/lock message; a 401 mints once more before it is believed.
 *
 * Nothing is fetched when the page loads: the token is minted on the click that
 * needs it. tests/app-pages-no-api-key.test.mjs pins that.
 *
 * Back on /dashboard since 2026-10-04: commit c10723bd ("Build document-focused
 * user dashboard") dropped the markup and the script tag, while the page kept
 * promising an exportable audit trail (fase 1, VERIFY-36-A and SENDNAME-22-A).
 * Dutch and English: the page says which in <html lang>.
 *
 * ASCII-only. Vanilla JS, no libraries.
 */
(function () {
  'use strict';

  var EN = /^en\b/i.test(document.documentElement.lang || '');
  function nlEn(nl, en) { return EN ? en : nl; }

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
    var mon = (EN ? ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                  : ['jan', 'feb', 'mrt', 'apr', 'mei', 'jun', 'jul', 'aug', 'sep', 'okt', 'nov', 'dec'])[d.getMonth()];
    return d.getDate() + ' ' + mon + ' ' + d.getFullYear() + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    var one = function (x) { var v = x.toFixed(1); return EN ? v : v.replace('.', ','); };
    if (n < 1048576) return one(n / 1024) + ' KB';
    return one(n / 1048576) + ' MB';
  }
  function statusLabel(s) {
    return ({
      sent: nlEn('verstuurd', 'sent'),
      aborted: nlEn('afgebroken', 'aborted'),
      downloaded: nlEn('opgehaald', 'collected'),
      downloaded_burned: nlEn('opgehaald en gewist', 'collected and deleted')
    })[s] || (s || nlEn('gebeurtenis', 'event'));
  }

  // One relay call on an app session token. `send(token)` must return the fetch
  // promise; paAppToken.withToken mints one, and mints a second and retries once
  // if the relay answers 401, so a tab open past the fifteen minutes recovers
  // instead of telling the reader to sign in again. The retry lives in the
  // helper so this file and pricing-billing.js cannot drift apart on it.
  function relayCall(send) {
    if (!window.paAppToken) return Promise.reject(new Error('token_unavailable'));
    return window.paAppToken.withToken(send);
  }

  function upsell(msg, planPath) {
    return '<div class="dh-ops-dim">' + esc(msg) + '</div>' +
      '<div style="margin-top:8px"><a class="dh-btn" href="' + (planPath || '/pricing') + '">' + nlEn('Plannen bekijken', 'See the plans') + '</a></div>';
  }

  /* ---------- history ---------- */
  function renderHistory(entries) {
    if (!entries || !entries.length) {
      histBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('Nog niets. Wat u verstuurt en ontvangt verschijnt hier.', 'Nothing yet. What you send and receive will appear here.') + '</div>';
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
    histLoad.textContent = nlEn('Bezig...', 'Loading...');
    histBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('Uw geschiedenis wordt geladen...', 'Loading your history...') + '</div>';
    relayCall(function (tok) {
      return fetch('/v2/user/history?limit=100', {
        headers: { Authorization: 'Bearer ' + tok, Accept: 'application/json' }, cache: 'no-store'
      });
    }).then(function (r) {
      return r.json().then(function (j) { return { status: r.status, body: j }; })
        .catch(function () { return { status: r.status, body: {} }; });
    }).then(function (res) {
      histLoad.disabled = false; histLoad.textContent = orig;
      if (res.status === 200) { renderHistory(res.body && res.body.entries); return; }
      if (res.status === 403) {
        // Fallback only; the relay sends its own message. Both name Firm,
        // the plan /pricing actually sells, not the tier key behind the gate.
        histBody.innerHTML = upsell(nlEn('De verzendgeschiedenis hoort bij Firm en Business.', 'Send history comes with Firm and Business.'), nlEn('/pricing', '/en/pricing'));
        return;
      }
      if (res.status === 401) {
        histBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('U bent uitgelogd. Log opnieuw in om uw geschiedenis te zien.', 'You were signed out. Sign in again to see your history.') + '</div>';
        return;
      }
      histBody.innerHTML = '<div class="dh-ops-dim">' + (res.status === 429
        ? nlEn('Even te veel tegelijk. Probeer het over een minuut opnieuw.', 'Too much at once. Try again in a minute.')
        : nlEn('We konden uw geschiedenis nu niet laden. Er is niets veranderd. Probeer het zo opnieuw.', 'We could not load your history just now. Nothing changed. Try again shortly.')) + '</div>';
    }).catch(function () {
      histLoad.disabled = false; histLoad.textContent = orig;
      histBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('Geen verbinding. Er is niets veranderd. Probeer het opnieuw.', 'No connection. Nothing changed. Try again.') + '</div>';
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
    btn.textContent = nlEn('Bezig...', 'Preparing...');
    var isCsv = format === 'csv';
    var url = isCsv ? '/v2/parasign/audit-export?format=csv' : '/v2/parasign/audit-export';
    relayCall(function (tok) {
      return fetch(url, {
        headers: { Authorization: 'Bearer ' + tok, Accept: isCsv ? 'text/csv' : 'application/json' }, cache: 'no-store'
      });
    }).then(function (r) {
      if (r.status === 200) {
        return r.blob().then(function (blob) { return { status: 200, blob: blob }; });
      }
      return r.json().then(function (j) { return { status: r.status, body: j }; })
        .catch(function () { return { status: r.status, body: {} }; });
    }).then(function (res) {
      buttons.forEach(function (b) { if (b) b.disabled = false; });
      btn.textContent = orig;
      if (res.status === 200) {
        triggerDownload(res.blob, isCsv ? 'parasign_audit.csv' : 'parasign_audit.json');
        expBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('De export is klaar en wordt gedownload (', 'The export is ready and downloading (') +
          (isCsv ? 'CSV' : 'JSON') + ').</div>';
        return;
      }
      if (res.status === 403) {
        expBody.innerHTML = upsell(nlEn('Exporteren hoort bij Business. Business is op aanvraag via privacy@paramant.app.', 'Exporting comes with Business.'), nlEn('/pricing#wat-u-kunt', '/en/pricing'));
        return;
      }
      if (res.status === 401) {
        expBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('U bent uitgelogd. Log opnieuw in om te exporteren.', 'You were signed out. Sign in again to export.') + '</div>';
        return;
      }
      expBody.innerHTML = '<div class="dh-ops-dim">' + (res.status === 429
        ? nlEn('Even te veel tegelijk. Probeer het over een minuut opnieuw.', 'Too much at once. Try again in a minute.')
        : nlEn('De export kon nu niet worden gemaakt. Probeer het zo opnieuw.', 'The export could not be made just now. Try again shortly.')) + '</div>';
    }).catch(function () {
      buttons.forEach(function (b) { if (b) b.disabled = false; });
      btn.textContent = orig;
      expBody.innerHTML = '<div class="dh-ops-dim">' + nlEn('Geen verbinding. Probeer het opnieuw.', 'No connection. Try again.') + '</div>';
    });
  }

  /* ---------- wire ---------- */
  if (histLoad) histLoad.addEventListener('click', loadHistory);
  if (expCsv) expCsv.addEventListener('click', function () { runExport('csv', expCsv); });
  if (expJson) expJson.addEventListener('click', function () { runExport('json', expJson); });
})();
