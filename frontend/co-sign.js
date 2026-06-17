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
import { LocalVaultSigner, buildDocSignMessage, requestSignActivation, submitSignature, resolvePasskeySigningKey, ensureSigningKey, enrolSigningKeyWithPassphrase, assertStrongPassphrase } from '/js/parasign-signer.js?v=8';

const RELAY_PUBLIC = 'https://health.paramant.app';

// ---------- helpers ----------
function $(id) { return document.getElementById(id); }
function showStep(id) { document.querySelectorAll('.step').forEach((s) => s.classList.remove('active')); $(id).classList.add('active'); }

// Passphrase prompt for the signing-key fallback (passkey providers without PRF).
// Resolves with the entered passphrase, or null if the user cancels. mode 'set' =
// create a new signing passphrase (two fields, strength-checked); 'unlock' = enter
// an existing one (single field).
function promptPassphrase(mode) {
  return new Promise((resolve) => {
    const panel = $('cs-pass-panel'), p1 = $('cs-pass-input'), p2 = $('cs-pass-input2');
    const errEl = $('cs-pass-err'), promptEl = $('cs-pass-prompt');
    const okBtn = $('cs-pass-confirm'), cancelBtn = $('cs-pass-cancel');
    const setMode = mode === 'set';
    promptEl.textContent = setMode
      ? 'Your passkey provider can’t do the one-tap unlock signing uses, so set a signing passphrase. You enter it each time you sign on this browser. Keep it safe: it protects your signing key and cannot be reset.'
      : 'Enter your signing passphrase to unlock your signing key.';
    p1.value = ''; p2.value = '';
    p1.placeholder = setMode ? 'New signing passphrase (min. 12 characters)' : 'Signing passphrase';
    p2.hidden = !setMode;
    errEl.hidden = true; errEl.textContent = '';
    panel.hidden = false;
    try { p1.focus(); } catch {}
    const cleanup = () => {
      okBtn.removeEventListener('click', onOk);
      cancelBtn.removeEventListener('click', onCancel);
      p1.removeEventListener('keydown', onKey); p2.removeEventListener('keydown', onKey);
      panel.hidden = true; p1.value = ''; p2.value = '';
    };
    const fail = (m) => { errEl.textContent = m; errEl.hidden = false; };
    const onOk = () => {
      const v1 = p1.value, v2 = p2.value;
      if (setMode) {
        try { assertStrongPassphrase(v1); } catch (e) { return fail(e.message || 'Passphrase too weak.'); }
        if (v1 !== v2) return fail('The two passphrases don’t match.');
      } else if (!v1) { return fail('Enter your signing passphrase.'); }
      cleanup(); resolve(v1);
    };
    const onCancel = () => { cleanup(); resolve(null); };
    const onKey = (e) => { if (e.key === 'Enter') { e.preventDefault(); onOk(); } };
    okBtn.addEventListener('click', onOk);
    cancelBtn.addEventListener('click', onCancel);
    p1.addEventListener('keydown', onKey); p2.addEventListener('keydown', onKey);
  });
}
function showError(m) { $('error-msg').textContent = m; showStep('step-error'); }
function toHex(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s; }
function toB64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

// CSP here allows img-src 'self' data: (no blob:), so image previews go through a
// data: URL. PDFs render to <canvas> via the self-hosted pdf.js (worker-src 'self').
const MAX_PREVIEW_PAGES = 30;
function bytesToDataUrl(bytes, mime) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('FileReader error'));
    r.readAsDataURL(new Blob([bytes], { type: mime }));
  });
}
function guessMimeFromMagic(bytes) {
  if (bytes.length < 4) return null;
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'image/png';
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image/jpeg';
  return null;
}
function isPdfBytes(b) { return b.length >= 4 && b[0] === 0x25 && b[1] === 0x50 && b[2] === 0x44 && b[3] === 0x46; }
function waitForPdfjs() {
  if (window.__pdfjsLib) return Promise.resolve(window.__pdfjsLib);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('PDF.js failed to load')), 10000);
    window.addEventListener('pdfjs:ready', () => { clearTimeout(t); resolve(window.__pdfjsLib); }, { once: true });
  });
}

// ---------- state ----------
let __envelope = null;
let __partyIndex = -1;
let __inviteToken = '';
let __session = null;       // { email } when logged in as the invited recipient
let __signKey = null;       // { vaultId, pk_b64, fingerprint, hasPrf, hasPassphrase } — PUBLIC metadata only
let __signPassphrase = null; // set when the signing key is passphrase-protected (provider without PRF)
let __hashMatches = null;   // null = no file opened yet, true/false after a local hash check
let __blindAck = false;     // user explicitly opted to sign without opening the document

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

  // GATE 2 — a passkey signing key. We no longer dump a first-time recipient to
  // /account: if this device has no signing key, doSign() sets one up inline with
  // a single passkey tap (no passphrase, no TOTP) — the sign-in passkey becomes
  // the signing key. Resolve now only to SHOW the fingerprint when one exists.
  try {
    __signKey = await resolvePasskeySigningKey();
  } catch (e) {
    if (e && e.code === 'no_signing_passkey') {
      __signKey = null;   // doSign() will set it up with one tap before signing
    } else {
      setStatus('err', e.message || 'Could not check your signing key.');
      return;
    }
  }

  if (__signKey) {
    setStatus('', 'Signed in as ' + escapeHtml(__session.email || 'your account') + '. You\'ll sign with your signing key (fingerprint ' + escapeHtml(__signKey.fingerprint) + ').');
  } else {
    setStatus('', 'Signed in as ' + escapeHtml(__session.email || 'your account') + '. You\'ll sign with your sign-in passkey — set up with one tap when you sign (no passphrase, no code).');
  }
  $('sign-confirm').onclick = doSign;
  refreshSignGate();   // stays disabled until the document has been reviewed (or blind-signing is acknowledged)
}

async function onVerifyFile(ev) {
  const f = ev.target.files && ev.target.files[0];
  if (!f) return;
  const buf = new Uint8Array(await f.arrayBuffer());
  const h = toHex(sha3_256(buf));
  __hashMatches = (h === __envelope.doc_hash);
  __blindAck = false;   // an opened file supersedes any earlier blind-sign override
  const b = $('verify-result');
  b.hidden = false;
  if (__hashMatches) {
    b.className = 'banner ok';
    b.textContent = 'Hash matches. This is the exact document in this envelope - what you see below is what you sign.';
  } else {
    b.className = 'banner err';
    b.textContent = 'Hash mismatch. The file you opened differs from the one in this envelope - do not sign it. Computed: ' + h.slice(0, 16) + '... Expected: ' + __envelope.doc_hash.slice(0, 16) + '...';
  }
  await renderDocPreview(buf);
  refreshSignGate();
}

// ---------- document preview (zero-knowledge: the bytes the signer holds, never the relay) ----------
async function renderDocPreview(bytes) {
  const host = $('doc-preview');
  host.hidden = false;
  host.innerHTML = '<div class="doc-preview-meta">Rendering document...</div>';
  try {
    if (isPdfBytes(bytes)) {
      await renderPdfPreview(bytes, host);
    } else {
      const mime = guessMimeFromMagic(bytes);
      if (mime && mime.startsWith('image/')) {
        await renderImagePreview(bytes, mime, host);
      } else {
        host.innerHTML = '<div class="doc-preview-meta">This file type cannot be shown in the browser. The hash check above already proves it is the exact document in this envelope - open it in your own app to read it before you sign.</div>';
      }
    }
  } catch (e) {
    host.innerHTML = '<div class="doc-preview-meta">Could not render a preview (' + escapeHtml(e.message || 'error') + '). The hash check above still tells you whether this is the right file.</div>';
  }
}

async function renderPdfPreview(bytes, host) {
  const pdfjs = await waitForPdfjs();
  const copy = new Uint8Array(bytes);   // pdf.js detaches the buffer it is handed
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
  host.innerHTML = '';
  const maxPages = Math.min(pdf.numPages, MAX_PREVIEW_PAGES);
  for (let i = 1; i <= maxPages; i++) {
    const page = await pdf.getPage(i);
    const base = page.getViewport({ scale: 1 });
    const targetWidth = Math.min(820, Math.floor(((host.clientWidth || window.innerWidth) - 20) * 0.98)) || 600;
    const viewport = page.getViewport({ scale: targetWidth / base.width });
    const wrap = document.createElement('div');
    wrap.className = 'doc-page';
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    wrap.appendChild(canvas);
    host.appendChild(wrap);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  }
  const meta = document.createElement('div');
  meta.className = 'doc-preview-meta';
  meta.textContent = pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's') +
    (pdf.numPages > maxPages ? ' (showing first ' + maxPages + ')' : '');
  host.appendChild(meta);
}

async function renderImagePreview(bytes, mime, host) {
  const url = await bytesToDataUrl(bytes, mime);
  host.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'doc-page';
  const img = document.createElement('img');
  img.alt = 'Document to sign';
  img.src = url;
  wrap.appendChild(img);
  host.appendChild(wrap);
}

// ---------- WYSIWYS gate: you cannot sign until you have opened the document (or explicitly accept signing blind) ----------
function blindLinkHtml() {
  return ' <button type="button" class="blind-link" id="blind-ack">I do not have the file - sign the hash blind</button>';
}
function refreshSignGate() {
  const btn = $('sign-confirm');
  const gate = $('review-gate');
  // Login is required; the signing key is NOT required up front — __signKey may be
  // null for a first-time signer on this device, and doSign() sets it up with one
  // passkey tap before signing. So gate only on the session here.
  if (!__session) { btn.disabled = true; gate.hidden = true; return; }

  const reviewed = (__hashMatches === true) || __blindAck;
  btn.disabled = !reviewed;
  gate.hidden = false;
  if (__hashMatches === true) {
    gate.innerHTML = '<span style="color:var(--cobalt)">You have opened and verified the document above.</span>';
  } else if (__hashMatches === false && !__blindAck) {
    gate.innerHTML = 'The file you opened does not match this envelope, so signing is blocked. Open the correct document, or' + blindLinkHtml();
  } else if (__blindAck) {
    gate.innerHTML = '<span style="color:#b45309">Signing blind - you have not opened the document. Your signature still covers its hash.</span> <button type="button" class="blind-link" id="blind-undo">Open the document instead</button>';
  } else {
    gate.innerHTML = 'Open the document above to review it before signing, or' + blindLinkHtml();
  }
  const ack = $('blind-ack'); if (ack) ack.onclick = () => { __blindAck = true; refreshSignGate(); };
  const undo = $('blind-undo'); if (undo) undo.onclick = () => { __blindAck = false; refreshSignGate(); };
}

// ---------- the v3 passkey-PRF signing chain (same gate as /sign doSign) ----------
async function doSign() {
  // The review gate keeps this button disabled until the document is verified or
  // blind-signing is acknowledged; re-check here as defence in depth.
  if (__hashMatches !== true && !__blindAck) {
    setStatus('err', 'Open and review the document above before signing.');
    refreshSignGate();
    return;
  }
  if (__blindAck && __hashMatches !== true) {
    if (!confirm('You have not opened the document - you would be signing its hash blind. Continue?')) return;
  }
  $('sign-confirm').disabled = true;
  $('sign-cta').hidden = true;

  try {
    // 0) Make sure this device has a passkey signing key — set one up inline with
    //    a single passkey tap (no passphrase, no TOTP) if not. The sign-in passkey
    //    becomes the signing key; no /account detour. Returns the existing key fast.
    if (!__signKey) {
      try {
        __signKey = await ensureSigningKey({ rpId: location.hostname, onStatus: (m) => setStatus('', m) });
      } catch (e) {
        if (!e || e.code !== 'prf_unsupported') throw e;
        // Passkey provider can't do PRF (e.g. Proton Pass): fall back to a
        // passphrase-protected signing key, still bound to the account via the passkey.
        __signPassphrase = await promptPassphrase('set');
        if (__signPassphrase == null) { const c = new Error('cancelled'); c.code = 'cancelled'; throw c; }
        setStatus('', 'Setting up your signing key…');
        __signKey = await enrolSigningKeyWithPassphrase({ rpId: location.hostname, passphrase: __signPassphrase, onStatus: (m) => setStatus('', m) });
      }
    }

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
    setStatus('', 'Confirm to sign (Face ID / Touch ID / security key)...');
    // PRF key: one tap. Passphrase key: unlock with the passphrase (reuse the one
    // set on enrol, or ask for it on an already-enrolled passphrase key).
    if (!__signKey.hasPrf && __signPassphrase == null) {
      __signPassphrase = await promptPassphrase('unlock');
      if (__signPassphrase == null) { const c = new Error('cancelled'); c.code = 'cancelled'; throw c; }
    }
    const signer = await new LocalVaultSigner().activate({ vaultId: __signKey.vaultId, rpId: location.hostname, passphrase: __signKey.hasPrf ? undefined : __signPassphrase });
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
    let msg;
    if (e && e.code === 'no_passkey') msg = 'Add a passkey to your account first (Account → Passkey sign-in), then return to this link — your sign-in passkey becomes your signing key.';
    else if (e && (e.code === 'no_prf' || e.code === 'vault_unavailable' || e.code === 'no_webauthn')) msg = e.message;
    else if (e && e.name === 'NotAllowedError') msg = 'Passkey confirmation was cancelled or timed out. Tap Sign to try again.';
    else if (e && e.status === 401) msg = 'Your session expired. Sign in again as the invited recipient, then retry.';
    else if (e && e.status === 403) msg = 'This invite is bound to a different email address. Sign in with the address the invite was sent to.';
    else if (e && e.status === 410) msg = 'This signing invite has expired (invites are valid for 7 days). Ask the sender for a new link.';
    else if (e && e.status === 409) msg = 'That signing authorization was already used or expired. Reload the page and try again.';
    else if (e && e.code === 'cancelled') msg = 'Signing cancelled. Tap Sign when you’re ready.';
    else if (e && /wrong passphrase/i.test(e.message || '')) msg = 'That signing passphrase didn’t match. Tap Sign and re-enter it.';
    else if (e && (e.code === 'prf_unsupported' || e.code === 'need_passphrase')) msg = 'Your passkey can’t do one-tap signing here. Tap Sign to set or enter a signing passphrase instead.';
    else if (e && e.status) msg = 'Signing could not be completed right now (server error ' + e.status + '). Please try again in a moment.';
    else msg = 'Your passkey could not complete signing on this browser. Tap Sign to try again. If it keeps failing, try a different browser, or use the passkey on your phone.';
    setStatus('err', msg);
    $('sign-confirm').disabled = false;
  }
}

init();
