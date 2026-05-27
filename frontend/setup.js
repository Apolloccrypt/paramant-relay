// /setup wizard state machine.
// Skeleton: drives the multi-step UX and shapes the config payload.
// The real apply logic lives behind POST /v2/setup/apply (currently a 501
// stub per ADR R005); this file is wired so the frontend works on its own.

'use strict';

var STEP_ORDER = [1, 2, 3, 4, 5, 6, 'done'];

var state = {
  step: 1,
  config: {
    sectors: ['general'],
    domain: '',
    autoTls: true,
    adminEmail: '',
    enableTotp: true,
    firstUserEmail: '',
    firstUserLabel: '',
    firstUserPlan: 'pro',
    complianceTemplate: 'generic'
  }
};

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
function stepEl(n) { return $('.step[data-step="' + n + '"]'); }

// Show one step, hide the others.
function goToStep(n) {
  if (STEP_ORDER.indexOf(n) === -1) { return; }
  state.step = n;
  $all('.step').forEach(function (el) {
    el.hidden = (el.getAttribute('data-step') !== String(n));
  });
  if (n === 6) { renderReview(); }
}

// Gather the inputs on a given step into state.config.
function collectStep(n) {
  var el = stepEl(n);
  if (!el) { return; }
  var c = state.config;
  if (n === 1) {
    c.sectors = [];
    if ($('[name="sector-general"]', el).checked) { c.sectors.push('general'); }
    if ($('[name="sector-health"]', el).checked) { c.sectors.push('health'); }
    if ($('[name="sector-finance"]', el).checked) { c.sectors.push('finance'); }
    if ($('[name="sector-legal"]', el).checked) { c.sectors.push('legal'); }
    if ($('[name="sector-iot"]', el).checked) { c.sectors.push('iot'); }
  } else if (n === 2) {
    c.domain = $('[name="domain"]', el).value.trim();
    c.autoTls = $('[name="auto-tls"]', el).checked;
  } else if (n === 3) {
    c.adminEmail = $('[name="admin-email"]', el).value.trim();
    c.enableTotp = $('[name="enable-totp"]', el).checked;
  } else if (n === 4) {
    c.firstUserEmail = $('[name="first-user-email"]', el).value.trim();
    c.firstUserLabel = $('[name="first-user-label"]', el).value.trim();
    c.firstUserPlan = $('[name="first-user-plan"]', el).value;
  } else if (n === 5) {
    c.complianceTemplate = $('[name="compliance-template"]', el).value;
  }
}

function renderReview() {
  var out = $('#review-summary');
  if (out) { out.textContent = JSON.stringify(state.config, null, 2); }
}

// Confirm we are still in first-time mode before showing the wizard.
function checkSetupMode() {
  return fetch('/v2/setup/check', { method: 'GET' })
    .then(function (r) { return r.ok ? r.json() : { setupMode: true }; })
    .then(function (data) {
      if (data && data.setupMode === false) {
        var main = $('.setup-wizard');
        if (main) {
          main.innerHTML =
            '<h1>Setup already complete</h1>' +
            '<p>This relay already has at least one user, so first-time ' +
            'setup is closed. <a href="/auth/login">Sign in</a> instead.</p>';
        }
      }
    })
    .catch(function () { /* offline / no backend yet: keep the wizard usable */ });
}

// Apply config: POST to /v2/setup/apply.
function applyConfig() {
  collectStep(state.step);
  renderReview();
  var status = $('#apply-status');
  if (status) { status.textContent = 'Applying...'; }
  return fetch('/v2/setup/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(state.config)
  })
    .then(function (r) {
      return r.json().then(function (body) { return { ok: r.ok, status: r.status, body: body }; });
    })
    .then(function (res) {
      if (res.ok) {
        goToStep('done');
      } else if (status) {
        // Backend is a stub for now (501). Surface the message; the review
        // payload above is still the source of truth for manual setup.
        status.textContent = (res.body && res.body.error)
          ? res.body.error
          : ('Setup failed (HTTP ' + res.status + ').');
      }
    })
    .catch(function () {
      if (status) {
        status.textContent =
          'Could not reach the relay. Your configuration is shown above; ' +
          'you can apply it manually for now.';
      }
    });
}

function wire() {
  $all('.next').forEach(function (b) {
    b.addEventListener('click', function () {
      collectStep(state.step);
      var i = STEP_ORDER.indexOf(state.step);
      if (i !== -1 && i < STEP_ORDER.length - 1) { goToStep(STEP_ORDER[i + 1]); }
    });
  });
  $all('.back').forEach(function (b) {
    b.addEventListener('click', function () {
      var i = STEP_ORDER.indexOf(state.step);
      if (i > 0) { goToStep(STEP_ORDER[i - 1]); }
    });
  });
  var applyBtn = $('#apply');
  if (applyBtn) { applyBtn.addEventListener('click', applyConfig); }
  goToStep(1);
  checkSetupMode();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', wire);
} else {
  wire();
}
