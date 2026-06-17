// Shared in-page passphrase prompt for the ParaSign signing-key fallback.
// Used when the account's passkey provider can't do WebAuthn-PRF (e.g. Proton
// Pass): the passkey still proves the account, and this passphrase protects the
// local ML-DSA signing key in place of the PRF KEK. Self-hosted (CSP script-src
// 'self'); the only dependency is the vault's strength check.
//
// The page supplies a panel whose elements follow a
//   `${prefix}-{panel,prompt,input,input2,err,confirm,cancel}`
// id convention. promptPassphrase resolves with the entered passphrase, or null
// if the user cancels. mode 'set' = create a new passphrase (two fields, strength
// checked); 'unlock' = enter an existing one (single field).
import { assertStrongPassphrase } from '/vendor/vault.js?v=3';

export function promptPassphrase(prefix, mode) {
  const $ = (s) => document.getElementById(prefix + '-' + s);
  return new Promise((resolve) => {
    const panel = $('panel'), p1 = $('input'), p2 = $('input2');
    const errEl = $('err'), promptEl = $('prompt'), okBtn = $('confirm'), cancelBtn = $('cancel');
    const setMode = mode === 'set';
    promptEl.textContent = setMode
      ? 'Your passkey provider can’t do the one-tap unlock signing uses, so set a signing passphrase. You enter it each time you sign on this browser. Keep it safe: it protects your signing key and cannot be reset.'
      : 'Enter your signing passphrase to unlock your signing key.';
    p1.value = ''; if (p2) p2.value = '';
    p1.placeholder = setMode ? 'New signing passphrase (min. 12 characters)' : 'Signing passphrase';
    if (p2) p2.hidden = !setMode;
    errEl.hidden = true; errEl.textContent = '';
    panel.hidden = false;
    try { p1.focus(); } catch { /* focus is best-effort */ }
    const cleanup = () => {
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      p1.removeEventListener('keydown', onKey); if (p2) p2.removeEventListener('keydown', onKey);
      panel.hidden = true; p1.value = ''; if (p2) p2.value = '';
    };
    const fail = (m) => { errEl.textContent = m; errEl.hidden = false; };
    const onOk = () => {
      const v1 = p1.value, v2 = p2 ? p2.value : '';
      if (setMode) {
        try { assertStrongPassphrase(v1); } catch (e) { return fail(e.message || 'Passphrase too weak.'); }
        if (v1 !== v2) return fail('The two passphrases don’t match.');
      } else if (!v1) {
        return fail('Enter your signing passphrase.');
      }
      cleanup(); resolve(v1);
    };
    const onCancel = () => { cleanup(); resolve(null); };
    const onKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); onOk(); } };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    p1.addEventListener('keydown', onKey); if (p2) p2.addEventListener('keydown', onKey);
  });
}
