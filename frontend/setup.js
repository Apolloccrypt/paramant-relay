// /setup wizard state machine.
// Drives the multi-step UX, validates each step, previews the config with
// per-section edit links, and applies it via POST /v2/setup/apply.
// Vanilla ES5, single file, no external dependencies (matches setup.html).

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

var EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
var DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/;

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
function stepEl(n) { return $('.step[data-step="' + n + '"]'); }

function goToStep(n) {
  if (STEP_ORDER.indexOf(n) === -1) { return; }
  state.step = n;
  $all('.step').forEach(function (el) {
    el.hidden = (el.getAttribute('data-step') !== String(n));
  });
  if (n === 6) { renderReview(); }
  if (window.scrollTo) { window.scrollTo(0, 0); }
}

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

// Validate a step. Returns null when OK, or an error string to show inline.
function validateStep(n) {
  var c = state.config;
  if (n === 1) {
    return c.sectors.length ? null : 'Select at least one sector.';
  }
  if (n === 2) {
    if (c.domain && !DOMAIN_RE.test(c.domain.toLowerCase())) {
      return 'That domain looks invalid. Use e.g. relay.your-org.com, or leave it blank for localhost mode.';
    }
    return null; // empty domain = localhost mode, allowed
  }
  if (n === 3) {
    return EMAIL_RE.test(c.adminEmail) ? null : 'A valid admin email is required.';
  }
  if (n === 4) {
    if (c.firstUserEmail && !EMAIL_RE.test(c.firstUserEmail)) {
      return 'First-user email is invalid. Leave it blank to skip creating a user now.';
    }
    return null; // first user is optional
  }
  return null;
}

function showStepError(n, msg) {
  var el = stepEl(n);
  if (!el) { return; }
  var box = $('.step-error', el);
  if (!box) {
    box = document.createElement('p');
    box.className = 'step-error hint';
    box.setAttribute('role', 'alert');
    box.style.color = '#b00020';
    var actions = $('.actions', el);
    el.insertBefore(box, actions);
  }
  box.textContent = msg || '';
  box.style.display = msg ? '' : 'none';
}

// Client-side DNS preflight (informational) when a domain is entered.
function dnsPreflight() {
  var out = $('#dns-status');
  if (!out) { return; }
  var domain = $('[name="domain"]', stepEl(2)).value.trim().toLowerCase();
  if (!domain) { out.textContent = ''; return; }
  if (!DOMAIN_RE.test(domain)) { out.textContent = ''; return; }
  out.textContent = 'Checking DNS for ' + domain + '...';
  fetch('/v2/setup/dns-check?domain=' + encodeURIComponent(domain))
    .then(function (r) { return r.json(); })
    .then(function (d) {
      if (d && d.resolves) {
        out.textContent = 'DNS OK: ' + domain + ' -> ' + (d.addresses || []).join(', ');
        out.style.color = '#0a7';
      } else {
        out.textContent = 'DNS not resolving yet for ' + domain + '. You can still continue and configure DNS later.';
        out.style.color = '#a60';
      }
    })
    .catch(function () { out.textContent = ''; });
}

function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;'); }

function renderReview() {
  var c = state.config;
  var out = $('#review-summary');
  if (!out) { return; }
  var rows = [
    { step: 1, label: 'Sectors', value: c.sectors.join(', ') },
    { step: 2, label: 'Domain', value: c.domain ? (c.domain + (c.autoTls ? ' (auto-TLS)' : ' (no TLS)')) : 'localhost mode' },
    { step: 3, label: 'Admin', value: c.adminEmail + (c.enableTotp ? ' (TOTP on)' : '') },
    { step: 4, label: 'First user', value: c.firstUserEmail ? (c.firstUserEmail + ' / ' + (c.firstUserLabel || 'first-user') + ' / ' + c.firstUserPlan) : 'skip for now' },
    { step: 5, label: 'Compliance', value: c.complianceTemplate }
  ];
  var html = '<dl class="review-list">';
  rows.forEach(function (r) {
    html += '<div class="review-row" style="display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px solid #eee">' +
      '<dt style="color:#666">' + esc(r.label) + '</dt>' +
      '<dd style="margin:0;text-align:right"><span>' + esc(r.value) + '</span> ' +
      '<button type="button" class="edit-link" data-edit="' + r.step + '" style="background:none;border:none;color:#1d4ed8;cursor:pointer;font-size:12px">Edit</button></dd>' +
      '</div>';
  });
  html += '</dl>';
  out.innerHTML = html;
  $all('.edit-link', out).forEach(function (b) {
    b.addEventListener('click', function () { goToStep(parseInt(b.getAttribute('data-edit'), 10)); });
  });
}

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

function renderDone(res) {
  var body = $('#done-body');
  if (!body) { return; }
  var b = (res && res.body) || {};
  var html = '<p>Your relay is configured and your admin key is ready. ' +
    '<strong>Copy it now</strong> -- it is shown only once.</p>';
  if (b.admin_api_key) {
    html += '<p style="font-family:monospace;background:#f5f7fa;border:1px solid #e0e0e0;padding:10px;word-break:break-all">' +
      esc(b.admin_api_key) + '</p>' +
      '<button type="button" id="copy-key" class="btn">Copy admin key</button>';
  }
  if (b.first_user_api_key) {
    html += '<p class="hint">First-user key: <code>' + esc(b.first_user_api_key_masked || '') + '</code> (delivered separately).</p>';
  }
  if (b.next_step === 'restart_relay') {
    html += '<p class="hint">A new <code>.env</code> was written' +
      (b.env_backed_up ? ' (previous one backed up to <code>.env.pre-setup</code>)' : '') +
      '. Restart the relay (<code>docker compose up -d</code>) to apply compliance and TLS settings.</p>';
  }
  html += '<div class="actions" style="margin-top:16px">' +
    '<a class="btn" href="' + esc(b.health_url || '/all-systems-go') + '">Check all systems</a> ' +
    '<a class="btn" href="' + esc((b.dashboard_url || '/dashboard')) + '?welcome=1">Go to dashboard</a>' +
    '</div>';
  body.innerHTML = html;
  var copyBtn = $('#copy-key');
  if (copyBtn && b.admin_api_key) {
    copyBtn.addEventListener('click', function () {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(b.admin_api_key).then(function () { copyBtn.textContent = 'Copied'; });
      }
    });
  }
}

function applyConfig() {
  collectStep(state.step);
  var status = $('#apply-status');
  var applyBtn = $('#apply');
  if (status) { status.style.color = ''; status.textContent = 'Configuring...'; }
  if (applyBtn) { applyBtn.disabled = true; }
  return fetch('/v2/setup/apply', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(state.config)
  })
    .then(function (r) {
      return r.json().then(function (body) { return { ok: r.ok, status: r.status, body: body }; })
        .catch(function () { return { ok: r.ok, status: r.status, body: {} }; });
    })
    .then(function (res) {
      if (res.ok) {
        goToStep('done');
        renderDone(res);
        return;
      }
      if (applyBtn) { applyBtn.disabled = false; }
      if (!status) { return; }
      status.style.color = '#b00020';
      if (res.status >= 500) {
        status.textContent = 'Setup failed (HTTP ' + res.status + '). ' +
          ((res.body && res.body.error) ? res.body.error : 'Check the relay logs: docker compose logs relay');
      } else {
        // 4xx: validation -- show message and let the user correct an earlier step.
        status.textContent = (res.body && res.body.error)
          ? res.body.error
          : ('Please review your input (HTTP ' + res.status + ').');
      }
    })
    .catch(function () {
      if (applyBtn) { applyBtn.disabled = false; }
      if (status) {
        status.style.color = '#b00020';
        status.textContent = 'Could not reach the relay. Your configuration is shown above; you can apply it manually for now.';
      }
    });
}

function wire() {
  $all('.next').forEach(function (b) {
    b.addEventListener('click', function () {
      collectStep(state.step);
      var err = validateStep(state.step);
      if (err) { showStepError(state.step, err); return; }
      showStepError(state.step, '');
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
  var domainInput = $('[name="domain"]', stepEl(2));
  if (domainInput) { domainInput.addEventListener('blur', dnsPreflight); }
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
