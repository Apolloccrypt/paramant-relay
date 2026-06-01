// Signing-key enrolment — wires the "Set up your signing key" action on
// /account (ADR R018, the deferred "stuk 2"). This is the ONE place a signing
// key is created; /sign points here. It runs the shared enrolSigningPasskey()
// orchestration (parasign-signer.js) with the three ceremony callbacks
// (registerPasskey / evalNewPrf / enrolPublicKey), then proves the result is
// resolvable so /sign can find it. Self-hosted deps only (CSP script-src
// 'self'); no-ops if the page lacks the enrol elements.
import { enrolSigningPasskey, resolvePasskeySigningKey } from '/js/parasign-signer.js?v=3';
import { startRegistration, browserSupportsWebAuthn } from '/vendor/simplewebauthn-browser/index.js';
import { vaultList, vaultDelete } from '/vendor/vault.js?v=2';

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

// Inline TOTP entry (replaces window.prompt). The enrol makes TWO TOTP-gated
// server calls (register-options, then bind-public-key) with the passkey
// ceremony between them, and the relay replay-protects codes (relay.js
// _usedTotpCodes + replayKey, 90s), so ONE code cannot gate both — the user
// enters a fresh code each time, in this one inline field, no browser pop-ups.
// Returns a Promise of the 6-digit string; a bad value re-prompts inline rather
// than throwing.
function askTotp(message) {
  return new Promise((resolve) => {
    const wrap = document.getElementById('signing-enrol-totp-wrap');
    const input = document.getElementById('signing-enrol-totp');
    const confirmBtn = document.getElementById('signing-enrol-totp-confirm');
    const promptEl = document.getElementById('signing-enrol-totp-prompt');
    if (!wrap || !input || !confirmBtn || !promptEl) {
      throw new Error('A 6-digit authenticator code is required.');   // rejects the promise
    }
    promptEl.textContent = message;
    input.value = '';
    wrap.hidden = false;
    input.focus();
    const finish = (val) => {
      confirmBtn.removeEventListener('click', onConfirm);
      input.removeEventListener('keydown', onKey);
      wrap.hidden = true;
      resolve(val);
    };
    const onConfirm = () => {
      const t = (input.value || '').trim();
      if (!/^\d{6}$/.test(t)) { promptEl.textContent = 'Enter the 6-digit code from your authenticator app.'; input.focus(); return; }
      finish(t);
    };
    const onKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); onConfirm(); } };
    confirmBtn.addEventListener('click', onConfirm);
    input.addEventListener('keydown', onKey);
  });
}

// enrolSigningPasskey() stores the passphrase wrap FIRST, so an abort after that
// (cancelled Face ID, wrong code, no PRF) leaves a passphrase-only vault entry
// that can never sign — v3 needs a webauthn-prf wrap. These are dead weight, so
// sweep them after every attempt. A real signing key always ends up with BOTH
// wraps, so this only ever removes orphans.
async function cleanupOrphans() {
  try {
    for (const k of await vaultList()) {
      const s = k.kekSources || [];
      if (s.length === 1 && s[0] === 'passphrase') await vaultDelete(k.id);
    }
  } catch { /* best-effort hygiene */ }
}

function wireSigningEnrol() {
  const btn = document.getElementById('signing-enrol-btn');
  if (!btn) return;                                  // not the account page
  const status = document.getElementById('signing-enrol-status');
  const passEl = document.getElementById('signing-enrol-pass');
  const pass2El = document.getElementById('signing-enrol-pass2');
  const labelEl = document.getElementById('signing-enrol-label');

  // Live passphrase strength hint (length + character variety). Cosmetic guide;
  // the vault still enforces real strength server-side in vaultStore.
  const strengthEl = document.getElementById('signing-enrol-strength');
  if (passEl && strengthEl) {
    passEl.addEventListener('input', () => {
      const v = passEl.value || '';
      if (!v) { strengthEl.textContent = ''; return; }
      let label, color = 'var(--ink-dim, #6b7280)';
      if (v.length < 12) { label = 'Too short (needs 12+ characters)'; color = 'var(--danger, #b91c1c)'; }
      else {
        const variety = (/[a-z]/.test(v) ? 1 : 0) + (/[A-Z]/.test(v) ? 1 : 0) + (/\d/.test(v) ? 1 : 0) + (/[^a-zA-Z0-9]/.test(v) ? 1 : 0);
        if (v.length >= 20 && variety >= 3) label = 'Strong';
        else if (v.length >= 16 || variety >= 3) label = 'Good';
        else label = 'OK (longer is stronger)';
      }
      strengthEl.textContent = label;
      strengthEl.style.color = color;
    });
  }

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
      // (ML-DSA-65, post-quantum) is generated and wrapped entirely in the browser.
      const { pk_hash } = await enrolSigningPasskey({
        label,
        passphrase,

        // (1) A PRF-CAPABLE passkey. Reuse an existing passkey ONLY if it
        //     genuinely supports PRF — a non-PRF credential (e.g. one created
        //     before PRF support) can never unlock the vault, and silently
        //     reusing it is exactly what broke before. If there is no
        //     PRF-capable passkey, register a FRESH one: the server enables
        //     extensions.prf, and we strip excludeCredentials client-side so the
        //     device will mint a PRF-capable passkey even when a pre-PRF passkey
        //     already exists for this account (TOTP step-up still gates it).
        registerPasskey: async ({ forceFresh } = {}) => {
          // Fast path: reuse an existing PRF-capable passkey — UNLESS the caller
          // forces a fresh one (the fallback when a reused credential turned out
          // not to actually produce a PRF result, which is what caused the loop).
          if (!forceFresh) {
            let list = [];
            try {
              const cr = await fetch('/api/user/account/webauthn/credentials', { credentials: 'include' });
              if (cr.ok) list = (await cr.json()).passkeys || [];
            } catch { /* treat as no usable passkey */ }
            const prfCapable = list.find(c => c.prfSupported && c.credId);
            if (prfCapable) return { credentialId: prfCapable.credId, reused: true };
          }

          const totp = await askTotp('Enter the 6-digit code from your authenticator app to start.');
          setStatus('Verifying code, then follow your device prompt…', false);
          const opt = await postJSON('/api/user/account/webauthn/register/options', { totp });
          if (opt.status === 403) throw new Error('That authenticator code was not accepted.');
          if (!opt.ok) throw new Error((opt.data && opt.data.error) || ('register_options_failed_' + opt.status));
          // Allow a new (PRF-capable) passkey even if a non-PRF one exists.
          if (opt.data && opt.data.options) delete opt.data.options.excludeCredentials;
          let attResp;
          try {
            attResp = await startRegistration({ optionsJSON: opt.data.options });
          } catch (e) {
            throw new Error(e && e.name === 'InvalidStateError'
              ? 'Your device blocked creating a new passkey. Remove this site’s passkey in your device settings, then try again.'
              : 'Passkey creation was cancelled.');
          }
          const ver = await postJSON('/api/user/account/webauthn/register/verify', { flowId: opt.data.flowId, response: attResp, label });
          if (!ver.ok) throw new Error((ver.data && ver.data.error) || ('register_verify_failed_' + ver.status));
          return { credentialId: attResp.id, reused: false };
        },

        // (2) Evaluate the passkey PRF with the per-wrap salt. This is the SAME
        //     get()+prf.eval that LocalVaultSigner.activate() runs at sign time,
        //     so a successful enrol guarantees a successful unlock later.
        evalNewPrf: async ({ credentialId, prfSalt }) => {
          setStatus('Confirm with Face ID / Touch ID / your security key…', false);
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
          if (!first) {
            const e = new Error('This passkey can’t produce a PRF result. Use a device/browser with passkey-PRF (iOS 18+ or a recent Chrome), or remove an old non-PRF passkey for this site and retry.');
            e.code = 'no_prf';   // signals enrolSigningPasskey to retry with a FRESH passkey when this one was reused
            throw e;
          }
          return new Uint8Array(first);
        },

        // (3) Bind the PUBLIC key to the account (TOTP-gated). The relay
        //     recomputes pk_hash from pk_b64 server-side; the secret never
        //     leaves the browser.
        enrolPublicKey: async ({ pk_b64, label: keyLabel }) => {
          const totp = await askTotp('Almost done. Your last code is used up, so enter a fresh 6-digit code to finish.');
          setStatus('Binding your public key to your account…', false);
          const r = await postJSON('/api/user/account/signing-key', { pk_b64, label: keyLabel, totp });
          if (!r.ok) throw new Error((r.data && r.data.error) || ('signing_key_enrol_failed_' + r.status));
        },
      });

      await cleanupOrphans();   // clear any passphrase-only leftovers from prior aborted attempts

      // Close the loop: resolvePasskeySigningKey() is the EXACT call /sign makes.
      // If it returns here, the vault now holds a webauthn-prf-wrapped key under
      // id = pk_hash, and /sign will find it. Show the fingerprint as proof.
      const k = await resolvePasskeySigningKey();
      setStatus('Signing key ready — fingerprint ' + (k.fingerprint || pk_hash.slice(0, 16)) + '. You can now sign at /sign.', false);
      if (passEl) passEl.value = '';
      if (pass2El) pass2El.value = '';
      document.dispatchEvent(new CustomEvent('signing-key-enrolled'));
    } catch (e) {
      await cleanupOrphans();   // don't leave a half-finished passphrase-only entry behind
      setStatus((e && e.message) ? e.message : 'Could not set up your signing key.', true);
    } finally {
      btn.disabled = false;
    }
  });
}

wireSigningEnrol();
