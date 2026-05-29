// Co-sign flow on /co-sign — a recipient signs an existing multi-party envelope.
//
// v3-only. Co-sign goes through the SAME per-document passkey-PRF activation
// chain as /sign's doSign() (ADR R018):
//   resolvePasskeySigningKey()      public vault metadata, NO unlock
//   -> requestSignActivation()      admin authorizes: invited email == party email,
//                                   doc hash matches; mints a 300s one-shot token
//   -> LocalVaultSigner.activate()  passkey-PRF unlock -> ActivatedSigner
//   -> buildDocSignMessage() (v3)   domain-prefixed message, byte-identical to relay
//      + signer.sign() + dispose()  the secret key lives ONLY in the signer; zeroized
//   -> submitSignature()            admin consumes the activation atomically (GETDEL)
//                                   + forwards to the relay sign with the email binding
//
// The plain-key / ephemeral / passphrase-vault path (and the audit-#1 parseInt
// vault bug) is gone: the secret never exists outside the ActivatedSigner.
//
// The ONLY relay-host reference is the public, read-only envelope status fetch +
// the view receipt. The signing path itself is same-origin via the admin
// (/api/user/sign/*), bound to the logged-in invitee session.
import { sha3_256 } from '/vendor/paramant-pqc.js';
import { LocalVaultSigner, buildDocSignMessage, requestSignActivation, submitSignature, resolvePasskeySigningKey } from '/js/parasign-signer.js?v=2';

const RELAY_PUBLIC = 'https://health.paramant.app';

// ---------- helpers ----------
function $(id) { return document.getElementById(id); }
function showStep(id) { document.querySelectorAll('.step').forEach((s) => s.classList.remove('active')); $(id).classList.add('active'); }
function showError(m) { $('error-msg').textContent = m; showStep('step-error'); }
function toHex(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s; }
function toB64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// ---------- state ----------
let __envelope = null;
let __partyIndex = -1;
let __inviteToken = '';
let __session = null;       // { email } when logged in as the invited recipient
let __signKey = null;       // { vaultId, pk_b64, fingerprint } — PUBLIC metadata only
let __hashMatches = null;

// ---------- boot ----------
async function init() {
  const params = new URLSearchParams(location.search);
  const envId = (params.get('env') || '').trim();
  const partyIndex = parseInt(params.get('p') || '', 10);
  __inviteToken = (params.get('t') || '').trim();
  if (!envId || !Number.isInteger(partyIndex) || partyIndex < 0) {
    return showError('Missing or invalid env / p query parameter.');
  }
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(envId)) {
    return showError('Envelope id is malformed.');
  }
  __partyIndex = partyIndex;

  showStep('step-loading');
  $('loading-msg').textContent = 'Fetching envelope...';

  try {
    const r = await fetch(RELAY_PUBLIC + '/v2/envelopes/' + encodeURIComponent(envId));
    if (r.status === 404) return showError('Envelope not found, expired, or already burned.');
    if (r.status === 429) return showError('Rate-limited - too many requests from this address. Try again in a minute.');
    if (!r.ok) return showError('Relay error: HTTP ' + r.status);
    const data = await r.json();
    __envelope = data.envelope;
    if (__partyIndex >= __envelope.party_count) return showError('Party index out of range for this envelope.');

    // Best-effort viewed-receipt (token-gated for email-bound envelopes); ignore failures.
    try {
      await fetch(RELAY_PUBLIC + '/v2/envelopes/' + encodeURIComponent(envId) + '/view', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ party_index: partyIndex, token: __inviteToken }),
      });
    } catch {}

    renderEnvelope();
    await prepareSigning();
    showStep('step-cosign');
  } catch (e) {
    showError(e.message || 'Network error');
  }
}

function renderEnvelope() {
  const e = __envelope;
  $('env-id').textContent = e.id;
  $('env-hash').textContent = e.doc_hash;
  $('env-filename').textContent = e.original_filename || '(not provided)';
  $('env-created').textContent = e.created_at || '-';
  $('env-expires').textContent = e.expires_at || '-';
  $('env-progress').textContent = e.signed_count + ' / ' + e.party_count + ' signed';
  $('env-status').textContent = 'Status: ' + (e.status || '-');
  const dot = $('env-status-dot');
  dot.className = 'dot ' + (e.status === 'complete' ? '' : e.status === 'sent' ? 'amber' : '');

  const list = $('parties-list');
  list.innerHTML = '';
  for (const p of e.parties) {
    const row = document.createElement('div');
    row.className = 'party-row' + (p.index === __partyIndex ? ' me' : '');
    const label = escapeHtml(p.label || ('Party ' + (p.index + 1)));
    const status = p.status === 'signed' ? 'SIGNED' : p.status === 'viewed' ? 'VIEWED' : 'PENDING';
    row.innerHTML =
      '<div class="party-idx">#' + p.index + '</div>' +
      '<div class="party-label">' + label + (p.index === __partyIndex ? ' (you)' : '') + '</div>' +
      '<div class="party-status ' + (p.status || 'pending') + '">' + status + '</div>';
    list.appendChild(row);
  }

  const me = e.parties[__partyIndex] || {};
  $('me-label').textContent = (me.label || 'party ' + (__partyIndex + 1));
  $('verify-file').onchange = onVerifyFile;
}

// ---------- preconditions: the v3 chain needs a logged-in invitee + a passkey key ----------
function setStatus(kind, msg) {
  const b = $('sign-status');
  b.hidden = false;
  b.className = 'banner' + (kind ? ' ' + kind : '');
  b.textContent = msg;
}
function showCta(html) {
  const cta = $('sign-cta');
  cta.hidden = false;
  cta.innerHTML = html;
}

async function loadSession() {
  try {
    const r = await fetch('/api/user/account', { credentials: 'include' });
    if (!r.ok) return null;
    const d = await r.json().catch(() => null);
    if (!d) return null;
    const email = d.email || (d.account && d.account.email) || '';
    return { email };
  } catch { return null; }
}

async function prepareSigning() {
  const me = __envelope.parties[__partyIndex] || {};
  if (me.status === 'signed') {
    setStatus('ok', 'This slot has already been signed. Nothing to do.');
    return;
  }

  // GATE 1 — logged in. The activation endpoint enforces (server-side) that the
  // session email equals THIS party's bound email; here we only route an invitee
  // with no session to sign in first.
  __session = await loadSession();
  if (!__session) {
    setStatus('warn', 'Sign in as the recipient this invite was sent to, then return here to sign.');
    const ret = encodeURIComponent(location.pathname + location.search);
    showCta('<a class="btn" href="/auth/login?return=' + ret + '">Sign in to continue</a>');
    return;
  }

  // GATE 2 — has a passkey signing key (stuk 1). For a first-time invitee with no
  // passkey, stuk 2 wires the inline TOFU enrol here; for now, point at /account.
  try {
    __signKey = await resolvePasskeySigningKey();
  } catch (e) {
    if (e && e.code === 'no_signing_passkey') {
      setStatus('warn', 'Signed in as ' + escapeHtml(__session.email || 'your account') + ', but this device has no signing passkey yet. Set one up, then return to this link.');
      showCta('<a class="btn btn-outline" href="/account">Set up a signing passkey</a>');
    } else {
      setStatus('err', e.message || 'Could not check your signing key.');
    }
    return;
  }

  setStatus('', 'Signed in as ' + escapeHtml(__session.email || 'your account') + '. You will sign with your passkey-protected key (fingerprint ' + escapeHtml(__signKey.fingerprint) + ').');
  $('sign-confirm').disabled = false;
  $('sign-confirm').onclick = doSign;
}

async function onVerifyFile(ev) {
  const f = ev.target.files && ev.target.files[0];
  if (!f) return;
  const buf = new Uint8Array(await f.arrayBuffer());
  const h = toHex(sha3_256(buf));
  __hashMatches = (h === __envelope.doc_hash);
  const b = $('verify-result');
  b.hidden = false;
  if (__hashMatches) {
    b.className = 'banner ok';
    b.textContent = 'Hash matches. This file is the same one the creator hashed.';
  } else {
    b.className = 'banner err';
    b.textContent = 'Hash mismatch. The file you chose is different from the one in this envelope. Computed: ' + h.slice(0, 16) + '... Expected: ' + __envelope.doc_hash.slice(0, 16) + '...';
  }
}

// ---------- the v3 passkey-PRF signing chain (same gate as /sign doSign) ----------
async function doSign() {
  if (__hashMatches === false) {
    if (!confirm('The file you uploaded does not match the envelope hash. Sign anyway? You will be signing a hash that does not match your local document.')) return;
  }
  $('sign-confirm').disabled = true;
  $('sign-cta').hidden = true;

  try {
    // 1) Per-document activation (authorize -> one-shot token). The admin checks
    //    the invited email == this party's email and the doc hash, then mints a
    //    300s one-shot activation. No token -> the client cannot proceed to unlock.
    setStatus('', 'Requesting signing authorization...');
    const act = await requestSignActivation({
      envelopeId: __envelope.id,
      partyIndex: __partyIndex,
      docHash: __envelope.doc_hash,
      inviteToken: __inviteToken,
    });

    // 2) Passkey-PRF unlock + sign of the v3 domain-prefixed message. The secret
    //    key lives ONLY inside the ActivatedSigner and is zeroized by dispose().
    setStatus('', 'Confirm with your passkey (Face ID / Touch ID / security key)...');
    const signer = await new LocalVaultSigner().activate({ vaultId: __signKey.vaultId, rpId: location.hostname });
    let sigB64;
    try {
      const message = buildDocSignMessage({ envelopeId: __envelope.id, docHash: __envelope.doc_hash, partyIndex: __partyIndex, emailHash: act.email_hash });
      sigB64 = toB64(await signer.sign(message));
    } finally {
      signer.dispose();   // zeroize — the secret never outlives this block
    }

    // 3) Submit. The admin consumes the activation atomically (GETDEL) and
    //    forwards to the relay sign with the verified email binding.
    setStatus('', 'Recording your signature...');
    const data = await submitSignature({ activationId: act.activation_id, signerPublicKey: signer.publicKey, signature: sigB64 });

    $('done-env-id').textContent = __envelope.id;
    $('done-status').textContent = data.status || '-';
    $('done-progress').textContent = (data.signed_count != null ? data.signed_count : '?') + ' / ' + (data.party_count != null ? data.party_count : __envelope.party_count) + ' signed';
    $('done-pk').textContent = __signKey.fingerprint;
    showStep('step-done');
  } catch (e) {
    let msg = (e && e.message) ? e.message : String(e);
    if (e && e.status === 401) msg = 'Your session expired. Sign in again as the invited recipient, then retry.';
    else if (e && e.status === 403) msg = 'This invite is bound to a different email address. Sign in with the address the invite was sent to.';
    else if (e && e.status === 410) msg = 'This signing invite has expired (invites are valid for 7 days). Ask the sender for a new link.';
    else if (e && e.status === 409) msg = 'That signing authorization was already used or expired. Reload the page and try again.';
    setStatus('err', msg);
    $('sign-confirm').disabled = false;
  }
}

init();
