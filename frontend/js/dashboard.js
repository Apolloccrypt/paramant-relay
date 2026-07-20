/* Paramant user dashboard. Client-side renderer.
 *
 * Fetches GET /api/user/me (JSON, credentials: include) and hydrates the
 * existing markup. Auth-gate is hard: 401/403 -> hard-redirect to
 * /auth/login?next=/dashboard before any tool-surface markup becomes
 * visible (the #dh-root container starts hidden, only revealed on 200).
 *
 * ASCII-only. Same security model as the prior loader (10s AbortController,
 * credentials: include, no-store cache).
 */
(function () {
  'use strict';

  var ONBOARDING_KEY = 'paramant.onboarding.dismissed.v1';
  var KEYSETUP_KEY = 'paramant.keysetup.dismissed.v1';
  var LOGIN_URL = '/auth/login?next=' + encodeURIComponent('/dashboard');

  var loading = document.getElementById('dh-loading');
  var root    = document.getElementById('dh-root');
  var errBox  = document.getElementById('dh-error');
  var errMsg  = document.getElementById('dh-error-detail');
  if (!root || !loading) return;

  function show(el)   { if (el) el.hidden = false; }
  function hide(el)   { if (el) el.hidden = true; }
  function txt(sel, value) {
    var nodes = root.querySelectorAll('[data-dh="' + sel + '"]');
    for (var i = 0; i < nodes.length; i++) nodes[i].textContent = value;
  }

  function fmtDate(iso) {
    if (!iso) return '--';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso).slice(0, 10);
    var y = d.getUTCFullYear();
    var m = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getUTCMonth()];
    var day = d.getUTCDate();
    return m + ' ' + day + ', ' + y;
  }

  function fmtMinutesUntil(iso) {
    if (!iso) return '--';
    var ms = new Date(iso).getTime() - Date.now();
    if (isNaN(ms) || ms <= 0) return 'expired';
    var min = Math.round(ms / 60000);
    if (min < 60) return min + ' min';
    var h = Math.floor(min / 60);
    var r = min % 60;
    return h + 'h ' + (r < 10 ? '0' + r : r) + 'm';
  }

  function emailLocal(email) {
    if (!email) return '';
    var at = email.indexOf('@');
    return at > 0 ? email.slice(0, at) : email;
  }

  function applyOnboardingState() {
    try {
      if (localStorage.getItem(ONBOARDING_KEY) === '1') {
        var hint = root.querySelector('[data-pa-onboarding]');
        if (hint) hint.hidden = true;
      } else {
        var firstHint = root.querySelector('[data-pa-onboarding]');
        if (firstHint) firstHint.hidden = false;
      }
    } catch (_) {
      var openHint = root.querySelector('[data-pa-onboarding]');
      if (openHint) openHint.hidden = false;
    }
  }

  function showError(detail) {
    hide(loading);
    hide(root);
    show(errBox);
    if (errMsg && detail) errMsg.textContent = detail;
  }

  function render(data) {
    var email = data.email || '';
    var plan  = data.plan  || 'standard';
    var label = data.label || emailLocal(email) || 'there';

    txt('email',        email);
    txt('email-full',   email || '--');
    txt('plan',         plan);
    txt('plan-strong',  plan);
    txt('api-key',      data.api_key_masked || '--');
    txt('created',      fmtDate(data.created_at));
    txt('backup',       String(data.backup_codes_remaining != null ? data.backup_codes_remaining : '--'));
    txt('session',      fmtMinutesUntil(data.session_expires_at));

    var h1 = document.getElementById('dh-h1');
    if (h1 && h1.childNodes.length && h1.childNodes[0].nodeType === 3) {
      h1.childNodes[0].nodeValue = 'Welcome back, ' + label;
    }

    applyOnboardingState();
    initPurposeCard(data);

    hide(loading);
    hide(errBox);
    show(root);
    root.classList.add('dh-loaded');

    checkKeySetup();
    loadOperations();
  }

  function wireActions() {
    root.addEventListener('click', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-pa-action]');
      if (!t) return;
      var act = t.getAttribute('data-pa-action');
      if (act === 'refresh') {
        ev.preventDefault();
        location.reload();
        return;
      }
      if (act === 'signout') {
        ev.preventDefault();
        t.disabled = true;
        fetch('/api/user/logout', { method: 'POST', credentials: 'include' })
          .catch(function () {})
          .then(function () { location.href = '/auth/login'; });
        return;
      }
      if (act === 'dismiss-onboarding') {
        ev.preventDefault();
        var hint = t.closest('[data-pa-onboarding]');
        if (hint) hint.hidden = true;
        try { localStorage.setItem(ONBOARDING_KEY, '1'); } catch (_) {}
      }
    });
  }

  // One-time usage-purpose question. Server-driven: /api/user/me returns
  // usage_purpose (null while unanswered). Answering or skipping posts to
  // /api/user/usage-purpose; the server stores it on the account, so the card
  // never returns on any device. On a failed save the card stays and the
  // buttons re-enable (never lose the answer silently).
  function initPurposeCard(data) {
    var card = document.getElementById('dh-purpose');
    if (!card) return;
    if (data.usage_purpose) { card.hidden = true; return; }
    card.hidden = false;
    if (card._wired) return;
    card._wired = 1;
    card.addEventListener('click', function (ev) {
      var t = ev.target.closest && ev.target.closest('[data-pa-purpose]');
      if (!t) return;
      var purpose = t.getAttribute('data-pa-purpose');
      var btns = card.querySelectorAll('[data-pa-purpose]');
      var i;
      for (i = 0; i < btns.length; i++) btns[i].disabled = true;
      fetch('/api/user/usage-purpose', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ purpose: purpose })
      }).then(function (r) {
        if (!r.ok) throw new Error('http_' + r.status);
        card.hidden = true;
      }).catch(function () {
        for (i = 0; i < btns.length; i++) btns[i].disabled = false;
        var note = document.getElementById('dh-purpose-note');
        if (note) { note.hidden = false; note.textContent = 'Could not save right now. Try again, or skip.'; }
      });
    });
  }

  // One-time nudge: if the account is missing a signing key and/or a sign-in
  // passkey, surface a dismissible popup that links into /account. Best-effort
  // and tolerant -- we only flag something as missing when the endpoint answers
  // cleanly with an empty list, never on a fetch error (so we never false-nag).
  function checkKeySetup() {
    try { if (localStorage.getItem(KEYSETUP_KEY) === '1') return; } catch (_) {}

    var modal = document.getElementById('dh-passkey-modal');
    var itemsBox = document.getElementById('dh-pm-items');
    var dismissBtn = document.getElementById('dh-pm-dismiss');
    if (!modal || !itemsBox) return;

    function getJSON(url) {
      return fetch(url, { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; });
    }

    Promise.all([
      getJSON('/api/user/account/signing-key'),
      getJSON('/api/user/account/webauthn/credentials')
    ]).then(function (res) {
      var signing = res[0], passkeys = res[1];
      var items = [];
      if (signing && Array.isArray(signing.keys) && signing.keys.length === 0) {
        items.push({
          href: '/account#signing-identity-section',
          title: 'Set up document signing',
          body: 'Create your ML-DSA-65 signing key so you can sign and co-sign documents.'
        });
      }
      if (passkeys && Array.isArray(passkeys.passkeys) && passkeys.passkeys.length === 0) {
        items.push({
          href: '/account#passkey-section',
          title: 'Add a sign-in passkey',
          body: 'Use Face ID, Touch ID, or a security key to sign in without a code.'
        });
      }
      if (!items.length) return;

      // Titles/bodies are static literals (no user input) -> safe innerHTML.
      itemsBox.innerHTML = items.map(function (it) {
        return '<a class="dh-pm-item" href="' + it.href + '">'
          + '<strong>' + it.title + '</strong>'
          + '<span>' + it.body + '</span></a>';
      }).join('');
      modal.hidden = false;

      function dismiss() {
        modal.hidden = true;
        try { localStorage.setItem(KEYSETUP_KEY, '1'); } catch (_) {}
      }
      if (dismissBtn) dismissBtn.addEventListener('click', dismiss);
      modal.addEventListener('click', function (ev) { if (ev.target === modal) dismiss(); });
      document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && !modal.hidden) dismiss(); });
    });
  }

  // ---- Operations: read-only live keys / usage / activity cards ----
  // Fed by GET /api/user/dashboard/overview (authUser). Polled every 5s so the
  // usage bars stay current; the audit feed and key are refreshed on the same tick.
  var opsAudit = [], opsFilter = '', opsPollTimer = 0;
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }
  function fmtTime(ts) {
    if (!ts) return '--:--:--';
    var d = new Date(ts);
    function p(n) { return (n < 10 ? '0' : '') + n; }
    var hm = p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
    var now = new Date();
    if (d.toDateString() === now.toDateString()) return hm;
    var mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getMonth()];
    var day = d.getDate() + ' ' + mon + (d.getFullYear() !== now.getFullYear() ? ' ' + d.getFullYear() : '');
    return day + ' ' + hm;
  }
  function opsBar(used, cap) {
    var unlimited = (cap == null);
    var pct = unlimited ? 4 : Math.min(100, Math.round(((used || 0) / Math.max(1, cap)) * 100));
    return { pct: pct, warn: !unlimited && pct >= 80, capTxt: unlimited ? '&#8734;' : String(cap) };
  }
  function renderOpsTimeline() {
    var el = document.getElementById('dh-ops-timeline');
    if (!el) return;
    var f = (opsFilter || '').toLowerCase();
    var rows = opsAudit.filter(function (ev) {
      if (!f) return true;
      return (ev.event_type || '').toLowerCase().indexOf(f) >= 0 ||
             JSON.stringify(ev.metadata || {}).toLowerCase().indexOf(f) >= 0;
    });
    el.innerHTML = rows.length
      ? rows.slice(0, 50).map(function (ev) {
          return '<div class="dh-tl-row"><span class="t">' + fmtTime(ev.ts) + '</span><span class="e">' + esc(ev.event_type || 'event') + '</span></div>';
        }).join('')
      : '<div class="dh-ops-dim">No activity' + (f ? ' matches "' + esc(opsFilter) + '"' : ' yet') + '.</div>';
  }
  function renderOps(d) {
    var keysEl = document.getElementById('dh-ops-keys');
    if (keysEl) {
      keysEl.innerHTML =
        '<div class="dh-ops-row"><span class="mono">' + esc(d.key_masked || '--') + '</span><span class="dim">primary</span></div>' +
        '<div class="dh-ops-row"><span class="dim">last used</span><span class="dim">tracked via activity</span></div>';
    }
    var q = d.quota || { transfers: 0, signs: 0, caps: {} };
    var caps = q.caps || {};
    function usageRow(label, used, cap) {
      var b = opsBar(used, cap);
      return '<div class="dh-usage-row"><div class="dh-usage-lab"><span>' + label + '</span><span><b>' + (used || 0) + '</b> / ' + b.capTxt + '</span></div>' +
        '<div class="dh-bar' + (b.warn ? ' warn' : '') + '"><i style="width:' + b.pct + '%"></i></div>' +
        (b.warn ? '<a class="dh-usage-upsell" href="/pricing">Upgrade to Pro</a>' : '') + '</div>';
    }
    var usageEl = document.getElementById('dh-ops-usage');
    if (usageEl) {
      usageEl.innerHTML = usageRow('Transfers', q.transfers, caps.transfers) + usageRow('Signings', q.signs, caps.signs) +
        '<div class="dh-ops-dim" style="font-size:10px">Live, refreshes every 5s.</div>';
    }
    opsAudit = d.audit || [];
    renderOpsTimeline();
  }
  function loadOperations() {
    if (!document.getElementById('dh-ops')) return;
    var fi = document.getElementById('dh-ops-filter');
    if (fi && !fi._wired) { fi._wired = 1; fi.addEventListener('input', function () { opsFilter = fi.value; renderOpsTimeline(); }); }
    function pull() {
      return fetch('/api/user/dashboard/overview', { credentials: 'include', headers: { 'Accept': 'application/json' }, cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) { if (d) renderOps(d); })
        .catch(function () {});
    }
    pull();
    if (!opsPollTimer) opsPollTimer = setInterval(pull, 5000);
  }

  function start() {
    wireActions();

    var ctrl = ('AbortController' in window) ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : 0;
    var opts = {
      credentials: 'include',
      headers: { 'Accept': 'application/json' },
      cache: 'no-store',
    };
    if (ctrl) opts.signal = ctrl.signal;

    fetch('/api/user/me', opts)
      .then(function (r) {
        if (timer) clearTimeout(timer);
        if (r.status === 401 || r.status === 403) {
          location.replace(LOGIN_URL);
          return null;
        }
        if (!r.ok) {
          showError('HTTP ' + r.status);
          return null;
        }
        return r.json();
      })
      .then(function (data) {
        if (data) render(data);
      })
      .catch(function () {
        if (timer) clearTimeout(timer);
        showError('Network error');
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
