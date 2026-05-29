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

function setStatus(el, text, isError) {
  if (!el) return;
  el.textContent = text;
  el.classList.toggle('error', !!isError);
  el.classList.add('visible');
  el.style.display = '';
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
      if (!opt.ok) throw new Error(opt.data && opt.data.error ? opt.data.error : 'could_not_start (' + opt.status + ')');

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
      setStatus(status, e.message || 'Passkey registration failed.', true);
      btn.disabled = false;
    }
  });

  // Passkey-specific success UI (own ids; the TOTP success section is untouched).
  function showRecoveryCodes(codes) {
    document.querySelectorAll('section[id^="state-"]').forEach((s) => s.classList.add('hidden'));
    const section = document.getElementById('state-passkey-success');
    const grid = document.getElementById('passkey-backup-codes');
    if (!section || !grid) { window.location = '/account'; return; }
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
    if (finishBtn) finishBtn.addEventListener('click', () => { window.location = '/account'; });
  }
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

  const returnUrl = new URLSearchParams(window.location.search).get('return') || '/account';

  btn.addEventListener('click', async () => {
    const email = (emailEl && emailEl.value || '').trim();
    if (!email) { setStatus(status, 'Enter your email address first.', true); if (emailEl) emailEl.focus(); return; }
    btn.disabled = true;
    setStatus(status, 'Follow your device prompt to sign in…', false);
    try {
      const opt = await postJSON('/api/user/auth/webauthn/login/options', { email });
      if (!opt.ok) throw new Error('could_not_start (' + opt.status + ')');

      let asseResp;
      try {
        asseResp = await startAuthentication({ optionsJSON: opt.data.options });
      } catch (e) {
        throw new Error('Passkey sign-in was cancelled, or no passkey is available for this account on this device.');
      }

      const ver = await postJSON('/api/user/auth/webauthn/login/verify', {
        flowId: opt.data.flowId,
        response: asseResp,
      });
      if (!ver.ok) throw new Error('We could not verify a passkey for that account.');

      window.location = returnUrl;
    } catch (e) {
      setStatus(status, e.message || 'Passkey sign-in failed.', true);
      btn.disabled = false;
    }
  });
}

wireSetupPasskey();
wireLoginPasskey();
