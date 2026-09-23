// One file, two languages: the Dutch page and its English copy under /en/ load
// this same script, and <html lang> says which of the two strings to show.
function nlEn(nl, en) { return /^en\b/i.test(document.documentElement.lang || '') ? en : nl; }
// Signing-key enrolment — wires the "Set up your signing key" action on
// /account. v4: the signing key is set up with the SAME passkey you sign in
// with (ADR R018). One Face ID / Touch ID / security-key tap generates the
// ML-DSA-65 key in the browser, wraps it with that passkey's PRF (no
// passphrase), and binds the public key to the account via a passkey step-up
// (no TOTP). All of that ceremony lives in ensureSigningKey()
// (parasign-signer.js) — the EXACT path /sign and /co-sign use — so this file
// just wires the button + status and can never drift from the sign flow.
// Self-hosted deps only (CSP script-src 'self'); no-ops if the button is absent.
import { ensureSigningKey, resolvePasskeySigningKey } from '/js/parasign-signer.js?v=15';

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
    const label = ((labelEl && labelEl.value) || '').trim() || nlEn('Ondertekensleutel', 'Signing key');
    btn.disabled = true;
    try {
      let k;
      try {
        // One passkey tap (PRF). Returns an existing key fast if present.
        k = await ensureSigningKey({ rpId: location.hostname, label, onStatus: (m) => setStatus(m, false) });
      } catch (e) {
        if (!e || e.code !== 'prf_unsupported') throw e;
        // Passkey provider can't do the one-tap PRF unlock. There's nothing to set
        // up in advance here: you'll sign with your authenticator code at /sign,
        // which binds a fresh key for each signing session (no persistent key on
        // this device). Surface that instead of failing.
        setStatus(nlEn('Uw passkey kan in deze browser niet met één tik ondertekenen, dus hier is niets in te stellen. Ga naar /sign en onderteken daar met de code van 6 cijfers uit uw authenticator-app.', 'Your passkey can’t do one-tap signing on this browser, so there’s nothing to set up here. Go to /sign and you can sign with your authenticator code (6-digit) instead.'), false);
        return;
      }
      setStatus(nlEn('Ondertekensleutel klaar, vingerafdruk ', 'Signing key ready, fingerprint ') + (k.fingerprint || (k.pk_hash || '').slice(0, 16)) + nlEn('. U kunt nu ondertekenen via /sign.', '. You can now sign at /sign.'), false);
      document.dispatchEvent(new CustomEvent('signing-key-enrolled'));
    } catch (e) {
      let msg;
      if (e && e.code === 'no_passkey') msg = nlEn('Voeg eerst een passkey toe aan uw account (het blok "Inloggen met een passkey" hierboven) en stel daarna ondertekenen in. Geen passkey? U kunt nog steeds ondertekenen via /sign met de code uit uw authenticator-app.', 'Add a passkey to your account first (the "Passkey sign-in" card above), then set up signing. No passkey? You can still sign at /sign with your authenticator code.');
      else if (e && (e.code === 'vault_unavailable' || e.code === 'no_webauthn')) msg = e.message;
      else if (e && e.name === 'NotAllowedError') msg = nlEn('De bevestiging met uw passkey is afgebroken of duurde te lang. Tik op de knop om het opnieuw te proberen.', 'Passkey confirmation was cancelled or timed out. Tap the button to try again.');
      else if (e && e.status) msg = nlEn('Uw ondertekensleutel kon nu niet worden ingesteld (serverfout ', 'Could not set up your signing key right now (server error ') + e.status + nlEn('). Probeer het zo opnieuw.', '). Please try again in a moment.');
      else msg = nlEn('Uw passkey kon het instellen in deze browser niet afronden. Tik op de knop om het opnieuw te proberen. Blijft het mislukken, probeer dan een andere browser of de passkey op uw telefoon.', 'Your passkey could not complete setup on this browser. Tap the button to try again. If it keeps failing, try a different browser, or use the passkey on your phone.');
      setStatus(msg, true);
    } finally {
      btn.disabled = false;
    }
  });

  // If a signing key already exists in this browser, say so up front so the
  // page doesn't read as "not set up".
  resolvePasskeySigningKey()
    .then((k) => setStatus(nlEn('In deze browser is al een ondertekensleutel ingesteld (vingerafdruk ', 'A signing key is already set up in this browser (fingerprint ') + k.fingerprint + nlEn('). Tik op de knop om hem opnieuw te maken.', '). Tap the button to re-create it.'), false))
    .catch(() => { /* none yet — leave the default prompt */ });
}

wireSigningEnrol();
