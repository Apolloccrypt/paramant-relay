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

    hide(loading);
    hide(errBox);
    show(root);
    root.classList.add('dh-loaded');
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
