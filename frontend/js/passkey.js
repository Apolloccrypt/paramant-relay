// Passkey (WebAuthn) client wiring for the account-setup and login pages
// (ADR R018, PR-A). ESM module, self-hosted deps only (CSP script-src 'self').
// Runs ALONGSIDE the existing email+TOTP flows; it never touches them. Each
// wire-fn no-ops when its page elements are absent, so this one file is safe to
// include on both pages.
import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
} from '/vendor/simplewebauthn-browser/index.js';

async function postJSON(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
    credentials: 'include',
  });
  let data = null;
  try { data = await r.json(); } catch { /* non-JSON */ }
  return { ok: r.ok, status: r.status, data };
}

// The status line. `techCode`, when present, is the raw technical detail: it
// goes on a second, quieter line UNDER the sentence instead of being the whole
// message. "could_not_start (400)" was the entire thing a customer saw on the
// login page, which names an HTTP status and no next step. Support still needs
// the code, so it is kept rather than dropped.
//
// Built with createElement/textContent, never innerHTML: this file runs under
// script-src 'self' with no inline script anywhere (scripts/check-csp-inline.sh).
function setStatus(el, text, isError, techCode) {
  if (!el) return;
  el.textContent = '';
  el.appendChild(document.createTextNode(text));
  if (techCode) {
    el.appendChild(document.createElement('br'));
    const code = document.createElement('span');
    code.className = 'small';
    code.style.color = 'var(--ink-dim, #6b7280)';
    code.style.opacity = '.85';
    code.textContent = techCode;
    el.appendChild(code);
  }
  el.classList.toggle('error', !!isError);
  el.classList.add('visible');
  el.style.display = '';
}

// Why the passkey prompt never opened, said to somebody who wants to sign in.
//
// The start call is the one step that can fail before the device is ever asked
// anything, and the page used to print the bare `could_not_start (<status>)`
// for all of it. That sentence tells a customer nothing they can act on, and on
// 2026-09-04 it was the whole of what a real sign-in attempt produced while the
// cross-device link right below it worked on the first tap. So: plain language
// plus the one route that is known to still work, and the code kept small
// underneath for support.
const PASSKEY_START_FALLBACK =
  'We could not start the passkey prompt on this device. '
  + 'Try “My passkey is on another device”, or use a 6-digit code.';
// Creating a passkey is a different screen with different exits: the
// cross-device link and the 6-digit code are not on it, so the sign-in sentence
// would send somebody looking for a button that is not there.
const PASSKEY_CREATE_FALLBACK =
  'We could not start the passkey setup on this device. '
  + 'Reload this page and try again, or set up the authenticator app instead.';

// `kind` picks which exits the sentence may point at: 'login' (default) or
// 'create'. The technical code is the same in both.
function passkeyStartFailure(status, serverError, kind) {
  let text = kind === 'create' ? PASSKEY_CREATE_FALLBACK : PASSKEY_START_FALLBACK;
  if (serverError === 'invalid_email') {
    text = 'That email address does not look complete, so we could not look up your passkey. '
      + 'Check it and try again, or use “My passkey is on another device”.';
  } else if (serverError === 'setup_token_required' || serverError === 'invalid_setup_token') {
    text = 'This setup link is no longer valid. Ask for a new one on the sign-in page '
      + 'under “Email me a new setup link”.';
  } else if (status === 429) {
    text = kind === 'create'
      ? 'Too many attempts from this internet connection. Wait a few minutes and try again.'
      : 'Too many sign-in attempts from this internet connection. Wait a few minutes, '
        + 'then try again or use a 6-digit code.';
  }
  const e = new Error(text);
  e.techCode = 'could_not_start (' + status + (serverError ? ' ' + serverError : '') + ')';
  return e;
}

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}

// Honest, case-split message for a failed passkey assertion. The DOMException /
// WebAuthnError name is the only reliable signal: AbortError is a real cancel,
// SecurityError is an origin/rpId problem, and NotAllowedError is the genuinely
// ambiguous bucket (cancel OR timeout OR no passkey for this account on THIS
// device) that the platform refuses to disambiguate. We therefore never assert
// "you cancelled" for the ambiguous case — we offer the recovery paths instead.
function passkeyAuthErrorMessage(e) {
  const name = e && e.name;
  if (name === 'AbortError') {
    return 'Passkey sign-in was cancelled.';
  }
  if (name === 'SecurityError') {
    return 'Passkey sign-in could not start on this site. If this keeps happening, contact support.';
  }
  // NotAllowedError and anything else: ambiguous. Give the actionable options.
  return 'No passkey was used on this device. Sign in with your email and code above, '
    + 'or tap “My passkey is on another device” to sign in with the passkey on your phone. '
    + 'If you cancelled, just try again.';
}

// ── Registration: account-setup page (/auth/setup/<setup_token>) ─────────────
function wireSetupPasskey() {
  const btn = document.getElementById('passkey-register-btn');
  if (!btn) return;                                  // not the setup page
  const status = document.getElementById('passkey-status');

  if (!browserSupportsWebAuthn()) {
    btn.disabled = true;
    setStatus(status, 'This browser does not support passkeys. Use the authenticator-app setup above.', true);
    return;
  }

  // The setup token is the last path segment, exactly like the TOTP flow reads it.
  const setupToken = window.location.pathname.split('/').pop();

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    setStatus(status, 'Follow your device prompt to create the passkey…', false);
    try {
      const opt = await postJSON('/api/user/auth/webauthn/register/options', { setup_token: setupToken });
      if (!opt.ok) throw passkeyStartFailure(opt.status, opt.data && opt.data.error, 'create');

      let attResp;
      try {
        attResp = await startRegistration({ optionsJSON: opt.data.options });
      } catch (e) {
        throw new Error(e && e.name === 'InvalidStateError'
          ? 'A passkey for this account already exists on this device.'
          : 'Passkey creation was cancelled.');
      }

      const ver = await postJSON('/api/user/auth/webauthn/register/verify', {
        flowId: opt.data.flowId,
        response: attResp,
      });
      if (!ver.ok) throw new Error(ver.data && ver.data.error ? ver.data.error : 'verification_failed (' + ver.status + ')');

      showRecoveryCodes(Array.isArray(ver.data.recovery_codes) ? ver.data.recovery_codes : []);
    } catch (e) {
      setStatus(status, e.message || 'Passkey registration failed.', true, e.techCode);
      btn.disabled = false;
    }
  });

  // Passkey-specific success UI (own ids; the TOTP success section is untouched).
  function showRecoveryCodes(codes) {
    document.querySelectorAll('section[id^="state-"]').forEach((s) => s.classList.add('hidden'));
    const section = document.getElementById('state-passkey-success');
    const grid = document.getElementById('passkey-backup-codes');
    if (!section || !grid) { window.location = '/dashboard'; return; }
    grid.innerHTML = '';
    codes.forEach((c) => {
      const d = document.createElement('div');
      d.className = 'backup-code';
      d.textContent = c;
      grid.appendChild(d);
    });
    section.classList.remove('hidden');

    const copyBtn = document.getElementById('passkey-copy-codes');
    if (copyBtn) copyBtn.addEventListener('click', () => navigator.clipboard.writeText(codes.join('\n')));
    const dlBtn = document.getElementById('passkey-download-codes');
    if (dlBtn) dlBtn.addEventListener('click', () => {
      const blob = new Blob([
        'Paramant backup codes\nSave these; each can be used once to sign in if you lose your passkey.\n\n' + codes.join('\n') + '\n',
      ], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'paramant-backup-codes.txt';
      a.click();
    });
    const finishBtn = document.getElementById('passkey-finish-btn');
    // Where the visitor was heading before they were asked to register. Someone
    // who clicked a price button and got sent here wants to land back on the
    // price page with their choice intact, not on a dashboard that has no idea
    // they wanted to buy anything. The login path below already reads `next`
    // this way; this button was hardcoded to /dashboard and threw it away, so
    // every new customer lost their purchase halfway through signing up.
    if (finishBtn) finishBtn.addEventListener('click', () => { window.location = safeNext(); });
  }
}

// Where to send the visitor after they are signed in or registered.
//
// Reads `next` (or the older `return`) from the query string and falls back to
// the dashboard. Only a local path is accepted: it must start with exactly one
// slash, so an attacker cannot hand out /auth/login?next=//evil.example and turn
// our sign-in into an open redirect. Anything else silently becomes /dashboard.
//
// This lives in one place because it was previously written out twice: once
// correctly on the login path, and once as a hardcoded /dashboard on the
// registration finish button. Two copies of the same rule is how one of them
// ends up wrong.
function safeNext() {
  const q = new URLSearchParams(window.location.search);
  const want = q.get('next') || q.get('return') || '/dashboard';
  return /^\/(?![\/\\])/.test(want) ? want : '/dashboard';
}

// ── Login: /auth/login (email-first passkey sign-in) ─────────────────────────
function wireLoginPasskey() {
  const btn = document.getElementById('passkey-login-btn');
  if (!btn) return;                                  // not the login page
  const status = document.getElementById('passkey-login-status');
  const emailEl = document.getElementById('email');

  if (!browserSupportsWebAuthn()) {
    btn.disabled = true;
    setStatus(status, 'This browser does not support passkeys.', true);
    return;
  }

  const returnUrl = safeNext();

  btn.addEventListener('click', async () => {
    const email = (emailEl && emailEl.value || '').trim();
    if (!email) { setStatus(status, 'Enter your email address first.', true); if (emailEl) emailEl.focus(); return; }
    btn.disabled = true;
    setStatus(status, 'Follow your device prompt to sign in…', false);
    try {
      const opt = await postJSON('/api/user/auth/webauthn/login/options', { email });
      if (!opt.ok) throw passkeyStartFailure(opt.status, opt.data && opt.data.error);

      let asseResp;
      try {
        asseResp = await startAuthentication({ optionsJSON: opt.data.options });
      } catch (e) {
        // WebAuthn deliberately makes "user cancelled" and "no matching passkey
        // on this device" indistinguishable for NotAllowedError (a privacy
        // property of the platform). So we do NOT claim a single cause: we name
        // only what the error reliably tells us, and for the ambiguous case we
        // point to the real recovery paths (email+code, or the passkey on your
        // phone via "another device").
        throw new Error(passkeyAuthErrorMessage(e));
      }

      const ver = await postJSON('/api/user/auth/webauthn/login/verify', {
        flowId: opt.data.flowId,
        response: asseResp,
      });
      if (!ver.ok) throw new Error('We could not verify a passkey for that account.');

      window.location = returnUrl;
    } catch (e) {
      setStatus(status, e.message || 'Passkey sign-in failed.', true, e.techCode);
      btn.disabled = false;
    }
  });
}

// ── Account dashboard: add a passkey to an existing logged-in account ────────
// authUser + TOTP step-up (the server gates the ceremony on a valid TOTP).
function wireAccountPasskey() {
  const btn = document.getElementById('account-passkey-btn');
  if (!btn) return;                                  // not the account page
  const status = document.getElementById('account-passkey-status');
  const totpEl = document.getElementById('account-passkey-totp');
  const listEl = document.getElementById('account-passkey-list');
  const emptyEl = document.getElementById('account-passkey-empty');

  async function refresh() {
    try {
      const r = await fetch('/api/user/account/webauthn/credentials', { credentials: 'include' });
      if (!r.ok) { if (emptyEl) { emptyEl.hidden = false; emptyEl.textContent = 'Could not load passkeys (HTTP ' + r.status + ').'; } return; }
      const d = await r.json();
      const pk = d.passkeys || [];
      if (!pk.length) {
        if (emptyEl) { emptyEl.hidden = false; emptyEl.textContent = 'No passkey on your account yet.'; }
        if (listEl) listEl.innerHTML = '';
        return;
      }
      if (emptyEl) emptyEl.hidden = true;
      if (listEl) listEl.innerHTML = pk.map((c) => {
        const lbl = c.label ? esc(c.label) : 'passkey';
        const when = c.created_at ? esc(paramantDate.moment(c.created_at, '')) : '';
        return '<li style="padding:8px 0;border-bottom:1px solid var(--ink-hair,#e5e7eb)">'
          + '<strong>' + lbl + '</strong> <span class="small" style="color:var(--ink-dim,#6b7280)">&middot; active'
          + (when ? ' &middot; added ' + when : '') + '</span></li>';
      }).join('');
    } catch { /* leave existing UI */ }
  }

  if (!browserSupportsWebAuthn()) {
    btn.disabled = true;
    setStatus(status, 'This browser does not support passkeys.', true);
    refresh();
    return;
  }

  btn.addEventListener('click', async () => {
    const totp = (totpEl && totpEl.value || '').trim();
    if (!/^\d{6}$/.test(totp)) { setStatus(status, 'Enter your current 6-digit TOTP code first.', true); if (totpEl) totpEl.focus(); return; }
    btn.disabled = true;
    setStatus(status, 'Verifying your code…', false);
    try {
      const opt = await postJSON('/api/user/account/webauthn/register/options', { totp });
      if (opt.status === 403) throw new Error('That TOTP code was not accepted. Try the current code from your authenticator.');
      if (!opt.ok) throw passkeyStartFailure(opt.status, opt.data && opt.data.error, 'create');

      setStatus(status, 'Follow your device prompt to create the passkey…', false);
      let attResp;
      try {
        attResp = await startRegistration({ optionsJSON: opt.data.options });
      } catch (e) {
        throw new Error(e && e.name === 'InvalidStateError'
          ? 'A passkey for this account already exists on this device.'
          : 'Passkey creation was cancelled.');
      }

      const ver = await postJSON('/api/user/account/webauthn/register/verify', { flowId: opt.data.flowId, response: attResp });
      if (!ver.ok) throw new Error(ver.data && ver.data.error ? ver.data.error : 'verification_failed (' + ver.status + ')');

      setStatus(status, 'Passkey activated. You can now sign in with it.', false);
      if (totpEl) totpEl.value = '';
      refresh();
    } catch (e) {
      setStatus(status, e.message || 'Could not activate passkey.', true, e.techCode);
      btn.disabled = false;
    }
  });

  refresh();
}

// ── Login: cross-device passkey (usernameless / discoverable, ADR R018) ──────
// The guaranteed cross-device path: ask the server for options with an EMPTY
// allowCredentials list, so the browser MUST offer its account-chooser + the
// "use a phone or tablet" QR (WebAuthn hybrid transport). No email is typed —
// identity comes from the discoverable credential the user proves possession of
// on their phone (Face/Touch ID). This does not depend on what `transports` a
// device happened to report at registration, so cross-device works on any
// desktop whose browser supports hybrid (Chrome/Edge/Safari/Firefox).
function wireDiscoverablePasskey() {
  const btn = document.getElementById('passkey-crossdevice-btn');
  if (!btn) return;                                  // not the login page
  const status = document.getElementById('passkey-login-status');

  if (!browserSupportsWebAuthn()) { btn.disabled = true; return; }

  const _rp = new URLSearchParams(window.location.search), _rv = _rp.get('next') || _rp.get('return') || '/dashboard';
  // Local paths only (leading single slash) — never an off-site open redirect.
  const returnUrl = /^\/(?![\/\\])/.test(_rv) ? _rv : '/dashboard';

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    setStatus(status, 'Your browser will show a QR code — scan it with your phone to sign in…', false);
    try {
      const opt = await postJSON('/api/user/auth/webauthn/login/discoverable/options', {});
      if (!opt.ok) throw passkeyStartFailure(opt.status, opt.data && opt.data.error);

      let asseResp;
      try {
        asseResp = await startAuthentication({ optionsJSON: opt.data.options });
      } catch (e) {
        throw new Error(passkeyAuthErrorMessage(e));
      }

      const ver = await postJSON('/api/user/auth/webauthn/login/verify', {
        flowId: opt.data.flowId,
        response: asseResp,
      });
      if (!ver.ok) throw new Error('We could not verify that passkey.');

      window.location = returnUrl;
    } catch (e) {
      setStatus(status, e.message || 'Cross-device passkey sign-in failed.', true, e.techCode);
      btn.disabled = false;
    }
  });
}

wireSetupPasskey();
wireLoginPasskey();
wireDiscoverablePasskey();
wireAccountPasskey();
