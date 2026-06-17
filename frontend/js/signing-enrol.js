// Signing-key enrolment — wires the "Set up your signing key" action on
// /account. v4: the signing key is set up with the SAME passkey you sign in
// with (ADR R018). One Face ID / Touch ID / security-key tap generates the
// ML-DSA-65 key in the browser, wraps it with that passkey's PRF (no
// passphrase), and binds the public key to the account via a passkey step-up
// (no TOTP). All of that ceremony lives in ensureSigningKey()
// (parasign-signer.js) — the EXACT path /sign and /co-sign use — so this file
// just wires the button + status and can never drift from the sign flow.
// Self-hosted deps only (CSP script-src 'self'); no-ops if the button is absent.
import { ensureSigningKey, resolvePasskeySigningKey } from '/js/parasign-signer.js?v=9';

function wireSigningEnrol() {
  const btn = document.getElementById('signing-enrol-btn');
  if (!btn) return;                                  // not the account page
  const status = document.getElementById('signing-enrol-status');
  const labelEl = document.getElementById('signing-enrol-label');

  const setStatus = (t, isErr) => {
    if (!status) return;
    status.textContent = t;
    status.style.color = isErr ? 'var(--danger, #b91c1c)' : 'var(--ink-dim, #6b7280)';
  };

  btn.addEventListener('click', async () => {
    const label = ((labelEl && labelEl.value) || '').trim() || 'Signing key';
    btn.disabled = true;
    try {
      // Resolve-or-enrol with one passkey tap. If a key already exists on this
      // device, ensureSigningKey() returns it without prompting.
      const k = await ensureSigningKey({
        rpId: location.hostname,
        label,
        onStatus: (m) => setStatus(m, false),
      });
      setStatus('Signing key ready — fingerprint ' + (k.fingerprint || (k.pk_hash || '').slice(0, 16)) + '. You can now sign at /sign.', false);
      document.dispatchEvent(new CustomEvent('signing-key-enrolled'));
    } catch (e) {
      let msg;
      if (e && e.code === 'no_passkey') msg = 'Add a passkey to your account first (the "Passkey sign-in" card above), then set up signing.';
      else if (e && e.code === 'prf_unsupported') msg = 'Your passkey provider (for example Proton Pass) can’t do the one-tap unlock signing uses. Set up your signing key the first time you sign at /sign — you’ll choose a signing passphrase there — or use a PRF-capable security key.';
      else if (e && (e.code === 'vault_unavailable' || e.code === 'no_webauthn')) msg = e.message;
      else if (e && e.name === 'NotAllowedError') msg = 'Passkey confirmation was cancelled or timed out. Tap the button to try again.';
      else if (e && e.status) msg = 'Could not set up your signing key right now (server error ' + e.status + '). Please try again in a moment.';
      else msg = 'Your passkey could not complete setup on this browser. Tap the button to try again. If it keeps failing, try a different browser, or use the passkey on your phone.';
      setStatus(msg, true);
    } finally {
      btn.disabled = false;
    }
  });

  // If a signing key already exists in this browser, say so up front so the
  // page doesn't read as "not set up".
  resolvePasskeySigningKey()
    .then((k) => setStatus('A signing key is already set up in this browser (fingerprint ' + k.fingerprint + '). Tap the button to re-create it.', false))
    .catch(() => { /* none yet — leave the default prompt */ });
}

wireSigningEnrol();
