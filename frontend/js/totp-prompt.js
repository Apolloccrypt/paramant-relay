// Shared in-page authenticator-code (TOTP) prompt for the ParaSign signing-key
// fallback. Used when the account's passkey can't do the one-tap WebAuthn-PRF
// unlock (e.g. a passkey manager without PRF), or when the account has no passkey
// at all. The 6-digit code authorises binding a fresh signing key to the account
// for this one signing session — signing "like logging in again". Self-hosted
// (CSP script-src 'self'); no dependencies.
//
// The page supplies a panel whose elements follow a
//   `${prefix}-{panel,prompt,input,err,confirm,cancel}`
// id convention. promptTotp resolves with the entered 6-digit code, or null if
// the user cancels.

// Dutch by default; the English copy of the page (lang="en") gets English.
const L = (nl, en) => (typeof document !== 'undefined' && document.documentElement && document.documentElement.lang === 'en' ? en : nl);

export function promptTotp(prefix) {
  const $ = (s) => document.getElementById(prefix + '-' + s);
  return new Promise((resolve) => {
    const panel = $('panel'), input = $('input');
    const errEl = $('err'), promptEl = $('prompt'), okBtn = $('confirm'), cancelBtn = $('cancel');
    promptEl.textContent = L('Voer de code van 6 cijfers uit uw authenticator-app in om in deze browser te ondertekenen. U voert hem elke keer in als u hier tekent, net als bij opnieuw inloggen.', 'Enter the 6-digit code from your authenticator app to sign on this browser. You enter it each time you sign here, like signing in again.');
    input.value = '';
    errEl.hidden = true; errEl.textContent = '';
    panel.hidden = false;
    try { input.focus(); } catch { /* focus is best-effort */ }
    const cleanup = () => {
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      input.removeEventListener('keydown', onKey);
      panel.hidden = true; input.value = '';
    };
    const fail = (m) => { errEl.textContent = m; errEl.hidden = false; };
    const onOk = () => {
      const v = (input.value || '').trim();
      if (!/^\d{6}$/.test(v)) return fail(L('Voer de code van 6 cijfers uit uw authenticator-app in.', 'Enter the 6-digit code from your authenticator app.'));
      cleanup(); resolve(v);
    };
    const onCancel = () => { cleanup(); resolve(null); };
    const onKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); onOk(); } };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    input.addEventListener('keydown', onKey);
  });
}
