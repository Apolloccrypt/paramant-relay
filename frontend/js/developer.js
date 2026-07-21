/* ParaSign API dashboard. No generic tool catalogue and no secret persistence. */
(function () {
  'use strict';

  var API = '/api/user/developer/parasign-keys';
  var snapshot = null;
  var modal = document.getElementById('psk-modal');

  function byId(id) { return document.getElementById(id); }
  function esc(value) {
    return String(value == null ? '' : value).replace(/[&<>"']/g, function (char) {
      return ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[char];
    });
  }
  function json(url, options) {
    return fetch(url, Object.assign({ credentials:'include', cache:'no-store', headers:{ Accept:'application/json' } }, options || {})).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok) { var error = new Error(body.message || body.error || ('HTTP ' + response.status)); error.status = response.status; error.data = body; throw error; }
        return body;
      });
    });
  }
  function copyText(text, button) {
    if (!navigator.clipboard) return Promise.reject(new Error('clipboard_unavailable'));
    return navigator.clipboard.writeText(text).then(function () {
      var old = button.textContent; button.textContent = 'Copied';
      setTimeout(function () { button.textContent = old; }, 1400);
    });
  }
  function formatTime(ts) {
    if (!ts) return '--:--';
    var date = new Date(ts);
    return date.toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
  }
  function isSignEvent(event) {
    var type = String(event && event.event_type || '').toLowerCase();
    return /sign|envelope|parasign/.test(type);
  }

  function renderSnapshot(data) {
    snapshot = data;
    var email = document.querySelector('[data-dv="email"]');
    var plan = document.querySelector('[data-dv="plan"]');
    if (email) email.textContent = data.email || '--';
    if (plan) plan.textContent = String(data.plan || '--').toUpperCase();
    byId('api-status-dot').className = 'status-dot ok';

    var quota = data.quota || {};
    var used = Number(quota.signs || 0);
    var cap = quota.caps && quota.caps.signs;
    byId('sign-used').textContent = String(used);
    byId('sign-cap').textContent = cap == null ? 'no fixed limit' : 'of ' + cap;
    var percent = cap == null ? (used ? 8 : 0) : Math.min(100, Math.round((used / Math.max(1, cap)) * 100));
    var bar = byId('sign-bar'); bar.style.width = percent + '%'; bar.className = percent >= 80 ? 'warn' : '';
    byId('usage-note').textContent = cap == null ? 'Your current plan has no fixed monthly signing cap.' : Math.max(0, cap - used) + ' signatures remain in the current month.';
    renderActivity((data.audit || []).filter(isSignEvent));
  }

  function renderActivity(events) {
    var host = byId('activity');
    if (!events.length) { host.innerHTML = '<div class="empty">No ParaSign activity yet. Create a signing request through the API to see it here.</div>'; return; }
    host.innerHTML = events.slice(0, 20).map(function (event) {
      return '<div class="event"><time>' + esc(formatTime(event.ts)) + '</time><span>' + esc(event.event_type || 'parasign_event') + '</span></div>';
    }).join('');
  }

  function renderKeys(keys) {
    var host = byId('psk-keys');
    if (!keys || !keys.length) { host.innerHTML = '<div class="empty">No ParaSign API key yet. Create one to connect your first application.</div>'; return; }
    host.innerHTML = keys.map(function (key) {
      var active = key.active !== false;
      var id = key.kid || '';
      return '<div class="key-row"><div class="key-main"><div class="key-value">' + esc(key.key_masked || id || '--') + '</div><div class="key-meta"><span class="pill ' + (active ? '' : 'off') + '">' + (active ? 'active' : 'revoked') + '</span>' + (key.label ? '<span>' + esc(key.label) + '</span>' : '') + (key.mode ? '<span>' + esc(key.mode) + '</span>' : '') + '</div></div>' + (active ? '<button class="key-revoke" type="button" data-revoke="' + esc(id) + '">Revoke</button>' : '') + '</div>';
    }).join('');
  }

  function loadKeys() {
    return json(API).then(function (data) { renderKeys(data.keys || []); }).catch(function (error) {
      byId('psk-keys').innerHTML = '<div class="empty">Could not load API keys. ' + esc(error.message) + '</div>';
    });
  }
  function loadSnapshot() {
    return json('/api/user/developer/snapshot').then(renderSnapshot).catch(function () {
      byId('api-status-dot').className = 'status-dot err';
    });
  }

  function showView(name) {
    modal.querySelectorAll('[data-view]').forEach(function (node) { node.hidden = node.getAttribute('data-view') !== name; });
  }
  function openModal() {
    byId('psk-label').value = '';
    byId('psk-error').hidden = true;
    showView('create'); modal.hidden = false;
    setTimeout(function () { byId('psk-label').focus(); }, 0);
  }
  function closeModal() {
    byId('psk-secret').textContent = '';
    modal.hidden = true;
    byId('psk-new').focus();
  }
  function createKey() {
    var button = byId('psk-generate');
    var label = byId('psk-label').value.trim();
    var error = byId('psk-error');
    button.disabled = true; button.textContent = 'Creating'; error.hidden = true;
    json(API, { method:'POST', headers:{ 'Content-Type':'application/json', Accept:'application/json' }, body:JSON.stringify({ label:label }) }).then(function (data) {
      byId('psk-secret').textContent = data.key || '';
      byId('psk-meta').textContent = 'Key ' + (data.kid || '--') + ' · ' + (data.mode || 'live') + ' · plan ' + (data.plan || snapshot && snapshot.plan || '--');
      showView('secret'); loadKeys();
    }).catch(function (failure) {
      error.textContent = failure.status === 403 ? 'Your account does not have ParaSign API access. Check the plan or ask an administrator to enable it.' : 'The key could not be created. ' + failure.message;
      error.hidden = false;
    }).finally(function () { button.disabled = false; button.textContent = 'Create key'; });
  }
  function revokeKey(kid, button) {
    if (!kid || !window.confirm('Revoke this ParaSign API key? Applications using it will stop working immediately.')) return;
    button.disabled = true;
    json(API, { method:'DELETE', headers:{ 'Content-Type':'application/json', Accept:'application/json' }, body:JSON.stringify({ kid:kid }) }).then(loadKeys).catch(function (error) {
      button.disabled = false;
      window.alert('The key could not be revoked. ' + error.message);
    });
  }

  byId('psk-new').addEventListener('click', openModal);
  byId('psk-generate').addEventListener('click', createKey);
  byId('psk-copy').addEventListener('click', function (event) { copyText(byId('psk-secret').textContent, event.currentTarget).catch(function () {}); });
  byId('copy-example').addEventListener('click', function (event) { copyText(byId('quick-example').textContent, event.currentTarget).catch(function () {}); });
  byId('psk-keys').addEventListener('click', function (event) {
    var button = event.target.closest('[data-revoke]'); if (button) revokeKey(button.getAttribute('data-revoke'), button);
  });
  modal.addEventListener('click', function (event) { if (event.target === modal || event.target.closest('[data-close]')) closeModal(); });
  document.addEventListener('keydown', function (event) { if (event.key === 'Escape' && !modal.hidden) closeModal(); });

  Promise.all([loadSnapshot(), loadKeys()]);
  setInterval(loadSnapshot, 10000);
}());
