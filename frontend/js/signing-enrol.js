// Signing-passkey enrolment — wires the "Set up signing passkey" action on
// /account (ADR R018, the deferred "stuk 2"). This is the ONE place a signing
// key is created; /sign points here. It runs the shared enrolSigningPasskey()
// orchestration (parasign-signer.js) with the three ceremony callbacks
// (registerPasskey / evalNewPrf / enrolPublicKey), then proves the result is
// resolvable so /sign can find it. Self-hosted deps only (CSP script-src
// 'self'); no-ops if the page lacks the enrol elements.
import { enrolSigningPasskey, resolvePasskeySigningKey } from '/js/parasign-signer.js?v=2';
import { startRegistration, browserSupportsWebAuthn } from '/vendor/simplewebauthn-browser/index.js';

// base64url -> bytes (WebAuthn credential id / PRF salt). Same idiom as
// parasign-signer.js so the credentialId we store round-trips at sign time.
function b64urlToBytes(s) {
  const t = (s || '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}

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

function askTotp(message) {
  const t = (window.prompt(message) || '').trim();
  if (!/^\d{6}$/.test(t)) throw new Error('A 6-digit authenticator code is required.');
  return t;
}

function wireSigningEnrol() {
  const btn = document.getElementById('signing-enrol-btn');
  if (!btn) return;                                  // not the account page
  const status = document.getElementById('signing-enrol-status');
  const passEl = document.getElementById('signing-enrol-pass');
  const pass2El = document.getElementById('signing-enrol-pass2');
  const labelEl = document.getElementById('signing-enrol-label');

  const setStatus = (t, isErr) => {
    if (!status) return;
    status.textContent = t;
    status.style.color = isErr ? 'var(--danger, #b91c1c)' : 'var(--ink-dim, #6b7280)';
  };

  btn.addEventListener('click', async () => {
    const passphrase = (passEl && passEl.value) || '';
    const confirm = (pass2El && pass2El.value) || '';
    const label = ((labelEl && labelEl.value) || '').trim() || 'Signing key';

    // Cheap client-side guards before any ceremony. The vault enforces real
    // strength (assertStrongPassphrase) inside vaultStore; we mirror the
    // length + match here for a clean message and to fail fast.
    if (passphrase.length < 12) { setStatus('Passphrase must be at least 12 characters.', true); return; }
    if (passphrase !== confirm) { setStatus('The two passphrases do not match.', true); return; }
    if (!browserSupportsWebAuthn()) { setStatus('This browser does not support passkeys.', true); return; }

    btn.disabled = true;
    setStatus('Setting up… follow the prompts on your device.', false);

    try {
      // One signing-key enrolment (ADR R018): passphrase (recovery floor) ->
      // passkey-PRF wrap -> bind the public key to the account. The private key
      // is generated and wrapped entirely in the browser.
      const { pk_hash } = await enrolSigningPasskey({
        label,
        passphrase,

        // (1) A PRF-capable passkey. Reuse an existing account passkey if there
        //     is one — every account passkey is registered with extensions.prf
        //     (server enables it), and reuse avoids both the
        //     exclude-credentials InvalidStateError and a redundant TOTP
        //     step-up. Only register a fresh passkey when the account has none.
        registerPasskey: async () => {
          try {
            const cr = await fetch('/api/user/account/webauthn/credentials', { credentials: 'include' });
            if (cr.ok) {
              const d = await cr.json();
              const list = d.passkeys || [];
              const chosen = list.find(c => c.prfSupported) || list[0];
              if (chosen && chosen.credId) return { credentialId: chosen.credId };
            }
          } catch { /* fall through to registering a fresh passkey */ }

          const totp = askTotp('Add a signing passkey — enter your current 6-digit authenticator code:');
          setStatus('Verifying code, then follow your device prompt to create the passkey…', false);
          const opt = await postJSON('/api/user/account/webauthn/register/options', { totp });
          if (opt.status === 403) throw new Error('That authenticator code was not accepted.');
          if (!opt.ok) throw new Error((opt.data && opt.data.error) || ('register_options_failed_' + opt.status));
          let attResp;
          try {
            attResp = await startRegistration({ optionsJSON: opt.data.options });
          } catch (e) {
            throw new Error(e && e.name === 'InvalidStateError'
              ? 'A passkey already exists on this device — reload the page and try again so it is reused.'
              : 'Passkey creation was cancelled.');
          }
          const ver = await postJSON('/api/user/account/webauthn/register/verify', { flowId: opt.data.flowId, response: attResp, label });
          if (!ver.ok) throw new Error((ver.data && ver.data.error) || ('register_verify_failed_' + ver.status));
          return { credentialId: attResp.id };
        },

        // (2) Evaluate the passkey PRF with the per-wrap salt. This is the SAME
        //     get()+prf.eval that LocalVaultSigner.activate() runs at sign time,
        //     so a successful enrol guarantees a successful unlock later.
        evalNewPrf: async ({ credentialId, prfSalt }) => {
          setStatus('Confirm with your passkey (Face ID / Touch ID / security key)…', false);
          const assertion = await navigator.credentials.get({
            publicKey: {
              challenge: crypto.getRandomValues(new Uint8Array(32)),
              rpId: location.hostname,
              allowCredentials: [{ type: 'public-key', id: b64urlToBytes(credentialId) }],
              userVerification: 'required',
              extensions: { prf: { eval: { first: prfSalt } } },
            },
          });
          const first = assertion.getClientExtensionResults()?.prf?.results?.first;
          if (!first) throw new Error('This passkey returned no PRF result (PRF unsupported on this authenticator).');
          return new Uint8Array(first);
        },

        // (3) Bind the PUBLIC key to the account (TOTP-gated). The relay
        //     recomputes pk_hash from pk_b64 server-side; the secret never
        //     leaves the browser.
        enrolPublicKey: async ({ pk_b64, label: keyLabel }) => {
          const totp = askTotp('Finish enrolling your signing key — enter a fresh 6-digit code:');
          setStatus('Binding your public key to your account…', false);
          const r = await postJSON('/api/user/account/signing-key', { pk_b64, label: keyLabel, totp });
          if (!r.ok) throw new Error((r.data && r.data.error) || ('signing_key_enrol_failed_' + r.status));
        },
      });

      // Close the loop: resolvePasskeySigningKey() is the EXACT call /sign makes.
      // If it returns here, the vault now holds a webauthn-prf-wrapped key under
      // id = pk_hash, and /sign will find it. Show the fingerprint as proof.
      const k = await resolvePasskeySigningKey();
      setStatus('Signing passkey ready — fingerprint ' + (k.fingerprint || pk_hash.slice(0, 16)) + '. You can now sign at /sign.', false);
      if (passEl) passEl.value = '';
      if (pass2El) pass2El.value = '';
      document.dispatchEvent(new CustomEvent('signing-key-enrolled'));
    } catch (e) {
      setStatus((e && e.message) ? e.message : 'Could not set up signing passkey.', true);
    } finally {
      btn.disabled = false;
    }
  });
}

wireSigningEnrol();
