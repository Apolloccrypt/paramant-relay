// DocuSign-style sign flow on /sign. Doc-first state machine.
//
// Steps: pick document -> (PDF: place stamp) -> identity -> review & sign -> done.
// Non-PDF inputs go through a hash-only path that skips the placement step.
//
// Reuses /vendor/parasign-bridge.js (ml_dsa65 + sha3_256 + vault helpers),
// /vendor/pdfjs (preview render) and /vendor/pdf-lib (stamp baking). All
// same-origin; CSP script-src 'self' remains intact.

// v3-only signing: ml_dsa65.sign + the passphrase vaultUnlock are GONE from the
// sign path. Signing goes through the passkey-PRF activation chain (LocalVaultSigner
// in parasign-signer.js); sha3_256 stays for document hashing only.
import { sha3_256 } from '/vendor/paramant-pqc.js';
import { LocalVaultSigner, buildDocSignMessage, createSigningEnvelope, requestSignActivation, submitSignature, resolvePasskeySigningKey, ensureSigningKey, enrolSigningKeyWithPassphrase } from '/js/parasign-signer.js?v=10';
import { promptPassphrase } from '/js/passphrase-prompt.js?v=1';

// Read-only public relay host, used ONLY for the "view envelope status" link on
// the done screen. The signing path itself is same-origin via the admin
// (/api/user/sign/*, /api/user/envelopes) — no relay host hardcoded there.
const RELAY_PUBLIC = 'https://health.paramant.app';

// ====================================================================
// State
// ====================================================================

const STAMP_PDF_W = 240;
const STAMP_PDF_H = 100;
const MAX_PREVIEW_PAGES = 30;

const state = {
  signingMode: null,     // 'alone' | 'cosign' | 'invite' (chosen on step-mode)
  mode: null,            // 'pdf' | 'image' | 'hash'
  imageType: null,       // 'png' | 'jpg' (only when mode === 'image')
  doc:  null,            // { bytes (Uint8Array), name, size }
  stamp: null,           // PDF mode: bottom-left PDF points. Image mode: top-left image pixels.
  signer: {
    name: '',
    fingerprint: '',       // public passkey-key fingerprint, resolved before sign (display only)
    sigStyle: 'typed',     // 'typed' | 'drawn' | 'image'
    sigImageBytes: null,   // Uint8Array (PNG for drawn, PNG/JPG for image)
    sigImageType: null,    // 'png' | 'jpg'
    sigImageDataUrl: null, // pre-computed data: URL for <img src=>
    docImageDataUrl: null, // pre-computed data: URL when doc is a viewable image
  },
  recipients: [],        // [{label, email}]; if empty -> single-party local sign only
  envelope: null,        // populated when recipients.length > 0 after POST /v2/envelopes
  result: null,          // { stampedBytes?, envelope, fingerprint }
};

// ====================================================================
// Utilities
// ====================================================================

const $ = id => document.getElementById(id);
function show(id) { $(id).hidden = false; }
function hide(id) { $(id).hidden = true; }

function setActive(stepId) {
  document.querySelectorAll('.ds-step').forEach(s => s.hidden = (s.id !== stepId));
  document.querySelectorAll('.ds-stepper li').forEach(li => {
    const k = li.dataset.step;
    const order = ['doc', 'place', 'recipients', 'identity', 'sign'];
    // step-done lives past the final step, so treat all stepper items as 'done'.
    const currentIdx = stepId === 'step-done'
      ? order.length
      : order.indexOf(stepId.replace('step-', '').replace('hash-only', 'place'));
    const myIdx = order.indexOf(k);
    li.classList.toggle('active', myIdx === currentIdx);
    li.classList.toggle('done',   myIdx < currentIdx);
  });
}

function toHex(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0');
  return s;
}
function toB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function formatSize(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024)    return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}
function escapeHtml(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// CSP on this site allows img-src 'self' data: (no blob:), so previews for
// drawn/uploaded signatures and for image documents must go through a
// data: URL or they fail silently and only show the alt text.
function bytesToDataUrl(bytes, mime) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error('FileReader error'));
    r.readAsDataURL(new Blob([bytes], { type: mime }));
  });
}

// ====================================================================
// Async libraries
// ====================================================================

async function waitForPdfjs() {
  if (window.__pdfjsLib) return window.__pdfjsLib;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('PDF.js failed to load')), 10000);
    window.addEventListener('pdfjs:ready', () => { clearTimeout(t); resolve(window.__pdfjsLib); }, { once: true });
  });
}

async function waitForPdfLib() {
  if (window.PDFLib) return window.PDFLib;
  return new Promise((resolve, reject) => {
    const start = Date.now();
    const tick = () => {
      if (window.PDFLib) return resolve(window.PDFLib);
      if (Date.now() - start > 10000) return reject(new Error('pdf-lib failed to load'));
      setTimeout(tick, 50);
    };
    tick();
  });
}

// ====================================================================
// Step 0: choose a signing setup (sign-alone / co-sign / invite)
// ====================================================================

function initStepMode() {
  document.querySelectorAll('.ds-mode-card').forEach(card => {
    card.addEventListener('click', () => {
      state.signingMode = card.dataset.mode;
      setStepperForMode(state.signingMode);
      setActive('step-doc');
    });
  });
}

// Show only the stepper items this mode uses, and label the last one 'Send'
// for the invite (request-signatures) flow.
function setStepperForMode(mode) {
  const steps = {
    alone:  ['doc', 'place', 'identity', 'sign'],
    cosign: ['doc', 'place', 'recipients', 'identity', 'sign'],
    invite: ['doc', 'recipients', 'sign'],
  }[mode] || ['doc', 'place', 'recipients', 'identity', 'sign'];
  document.querySelectorAll('.ds-stepper li').forEach(li => { li.hidden = !steps.includes(li.dataset.step); });
  const signLi = document.querySelector('.ds-stepper li[data-step="sign"]');
  if (signLi) signLi.textContent = (mode === 'invite') ? 'Send' : 'Sign';
}

function enterRecipients() {
  setActive('step-recipients');
  const cont = $('ds-recipients-continue');
  if (cont) { cont.textContent = (state.signingMode === 'invite') ? 'Send for signature' : 'Continue'; cont.disabled = false; }
  const hint = $('ds-recipients-hint'); if (hint) hint.hidden = true;
  renderRecipients();
}

function showRecipientsHint(msg, isErr) {
  const el = $('ds-recipients-hint');
  if (!el) return;
  el.textContent = msg; el.hidden = false; el.className = isErr ? 'ds-banner err' : 'ds-banner';
}

// Invite-to-sign: create the envelope WITHOUT the requester signing (party 0 is
// the requester; they never run the activation). Recipients (parties 1..N) sign
// at their own /co-sign links, shown on the done screen.
async function sendForSignature() {
  const cont = $('ds-recipients-continue');
  if (cont) cont.disabled = true;
  showRecipientsHint('Creating the signing request…', false);
  try {
    const docHashForEnvelope = toHex(sha3_256(state.doc.bytes));
    const created = await createSigningEnvelope({
      docHash: docHashForEnvelope,
      recipients: state.recipients,
      originalFilename: state.doc.name,
      signerLabel: 'Requester',
      creatorPublicKey: '',   // the requester does not sign
    });
    state.envelope = created.envelope;
    state.result = {
      stampedBytes: null,
      fingerprint: '',
      envelope: {
        version: 'parasign-request-1',
        original_filename: state.doc.name,
        document_hash: docHashForEnvelope,
        multiparty: {
          envelope_id: created.envelope.id,
          party_count: created.envelope.party_count,
          party_links: created.envelope.party_links,
          expires_at: created.envelope.expires_at,
        },
        disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
      },
    };
    showDone();
  } catch (e) {
    if (cont) cont.disabled = false;
    showRecipientsHint((e && e.status === 401) ? 'Please sign in first (open /auth/login), then return here.' : ((e && e.message) ? e.message : 'Could not create the request.'), true);
  }
}

// ====================================================================
// Step 1: pick a document
// ====================================================================

function initStepDoc() {
  const dz = $('ds-dropzone');
  const inp = $('ds-doc-input');
  dz.addEventListener('click', () => inp.click());
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag'));
  dz.addEventListener('drop', e => {
    e.preventDefault(); dz.classList.remove('drag');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) onDocChosen(e.dataTransfer.files[0]);
  });
  inp.addEventListener('change', e => e.target.files[0] && onDocChosen(e.target.files[0]));
}

async function onDocChosen(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  state.doc = { bytes, name: file.name, size: file.size };
  state.signer.docImageDataUrl = null;
  state.imageType = null;

  const isPdf = bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
  const mimeGuess = guessMimeFromMagic(bytes);
  const isPng = mimeGuess === 'image/png';
  const isJpg = mimeGuess === 'image/jpeg';
  const canPlaceVisually = isPdf || isPng || isJpg;

  state.mode = isPdf ? 'pdf' : (isPng || isJpg) ? 'image' : 'hash';
  if (isPng) state.imageType = 'png';
  else if (isJpg) state.imageType = 'jpg';

  // Pre-compute a data: URL for viewable images so the review pane can use
  // <img src=> without hitting CSP blob: restrictions.
  if (mimeGuess && mimeGuess.startsWith('image/')) {
    try { state.signer.docImageDataUrl = await bytesToDataUrl(bytes, mimeGuess); } catch {}
  }

  if (state.signingMode === 'invite') {
    // Requester doesn't stamp/sign — go straight to choosing who must sign.
    enterRecipients();
  } else if (canPlaceVisually) {
    setActive('step-place');
    if (isPdf) await renderPdfForPlacement();
    else       await renderImageForPlacement();
  } else {
    setActive('step-hash-only');
    $('ds-hash-only-name').textContent = file.name;
    $('ds-hash-only-size').textContent = formatSize(file.size);
    $('ds-hash-only-hash').textContent = toHex(sha3_256(bytes));
    $('ds-hash-only-continue').disabled = false;
  }
}

function loadImageElement(bytes, mime) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = () => reject(new Error('image decode failed'));
      img.src = r.result;
    };
    r.onerror = () => reject(new Error('FileReader error'));
    r.readAsDataURL(new Blob([bytes], { type: mime }));
  });
}

async function renderImageForPlacement() {
  $('ds-place-continue').disabled = true;
  const mime = state.imageType === 'jpg' ? 'image/jpeg' : 'image/png';
  const img = await loadImageElement(state.doc.bytes, mime);

  const container = $('ds-pdf-canvas-list');
  container.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'ds-page-wrap';
  wrap.dataset.pageIndex = '0';
  // For image mode we store natural image dimensions as 'page' size and a
  // mode marker so onPlaceClick knows not to flip Y.
  wrap._pdfPage = { width: img.naturalWidth, height: img.naturalHeight, index: 0, isImage: true };
  const canvas = document.createElement('canvas');
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  canvas.getContext('2d').drawImage(img, 0, 0);
  wrap.appendChild(canvas);
  container.appendChild(wrap);
  wrap.addEventListener('click', onPlaceClick);

  $('ds-place-page-count').textContent = '1 image (' + img.naturalWidth + ' x ' + img.naturalHeight + ' pixels)';
}

// ====================================================================
// Step 2 (PDF): render + click to place stamp
// ====================================================================

async function renderPdfForPlacement() {
  $('ds-place-continue').disabled = true;
  const pdfjs = await waitForPdfjs();
  const copy = new Uint8Array(state.doc.bytes);
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;

  const container = $('ds-pdf-canvas-list');
  container.innerHTML = '';
  const maxPages = Math.min(pdf.numPages, MAX_PREVIEW_PAGES);
  for (let i = 1; i <= maxPages; i++) {
    const page = await pdf.getPage(i);
    const baseViewport = page.getViewport({ scale: 1 });
    const targetWidth = Math.min(820, Math.floor(window.innerWidth * 0.88));
    const scale = targetWidth / baseViewport.width;
    const viewport = page.getViewport({ scale });
    const wrap = document.createElement('div');
    wrap.className = 'ds-page-wrap';
    wrap.dataset.pageIndex = String(i - 1);
    wrap._pdfPage = { width: baseViewport.width, height: baseViewport.height, index: i - 1 };
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    wrap.appendChild(canvas);
    container.appendChild(wrap);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
    wrap.addEventListener('click', onPlaceClick);
  }
  $('ds-place-page-count').textContent =
    pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's') +
    (pdf.numPages > maxPages ? ' (showing first ' + maxPages + ')' : '');
}

function onPlaceClick(e) {
  const wrap = e.currentTarget;
  const canvas = wrap.querySelector('canvas');
  const rect = canvas.getBoundingClientRect();
  const isImage = !!wrap._pdfPage.isImage;
  const ratio = wrap._pdfPage.width / rect.width;
  const pxX = e.clientX - rect.left;
  const pxY = e.clientY - rect.top;

  // Image mode scales the stamp to ~25% of the natural image width so it
  // stays legible regardless of the screenshot/photo resolution. PDF mode
  // uses fixed PDF-point dimensions.
  let stampNatW, stampNatH;
  if (isImage) {
    stampNatW = Math.min(wrap._pdfPage.width * 0.25, 480);
    stampNatH = stampNatW * (STAMP_PDF_H / STAMP_PDF_W);
  } else {
    stampNatW = STAMP_PDF_W;
    stampNatH = STAMP_PDF_H;
  }
  const stampPxW = stampNatW / ratio;
  const stampPxH = stampNatH / ratio;

  const left = Math.max(0, Math.min(rect.width  - stampPxW, pxX - stampPxW / 2));
  const top  = Math.max(0, Math.min(rect.height - stampPxH, pxY - stampPxH / 2));
  const natX = left * ratio;
  const natYTop = top * ratio;

  if (isImage) {
    // Image-pixel coords, top-left origin (matches canvas + ctx.drawImage).
    state.stamp = { pageIndex: 0, x: natX, y: natYTop, w: stampNatW, h: stampNatH, isImage: true };
  } else {
    // pdf-lib uses bottom-left origin in PDF points.
    const pdfYBottom = wrap._pdfPage.height - natYTop - stampNatH;
    state.stamp = { pageIndex: wrap._pdfPage.index, x: natX, y: pdfYBottom, w: stampNatW, h: stampNatH };
  }

  document.querySelectorAll('.ds-stamp-marker').forEach(el => el.remove());
  renderStampMarker(wrap, left, top, stampPxW, stampPxH);
  $('ds-place-continue').disabled = false;
  $('ds-place-hint').textContent = isImage
    ? 'Stamp placed on the image. Click another spot to move it.'
    : 'Stamp on page ' + (wrap._pdfPage.index + 1) + '. Click another spot to move it.';
}

function renderStampMarker(wrap, left, top, w, h) {
  const m = document.createElement('div');
  m.className = 'ds-stamp-marker';
  m.style.cssText = `left:${left}px;top:${top}px;width:${w}px;height:${h}px`;
  m.innerHTML = stampMockupHtml();
  wrap.appendChild(m);
}

// ====================================================================
// Step 3: identity (name + key source + optional notary)
// ====================================================================

async function initStepIdentity() {
  $('ds-signer-name').addEventListener('input', () => {
    state.signer.name = $('ds-signer-name').value.trim();
    refreshIdentityValid();
  });
  $('ds-signer-name').dispatchEvent(new Event('input'));

  // Signature style tabs
  document.querySelectorAll('.ds-sig-tabs .ds-tab').forEach(tab => {
    tab.addEventListener('click', () => selectSigStyle(tab.dataset.sig));
  });
  initDrawCanvas();
  initImageUpload();

  // No key-source dropdown any more: signing is always the account's passkey-PRF
  // key (resolved at sign time). Show the enrolled key's fingerprint (or a "set
  // up a passkey" hint) so the signer knows which identity will sign.
  showSigningIdentity().catch(() => {});
}

// Does this ACCOUNT have a signing key bound on the server, even though THIS
// browser's vault has none? The signing key's private half + PRF wrap live
// per-browser in IndexedDB; the server only holds the public binding. A key
// enrolled on your phone is therefore NOT usable in a desktop browser — each
// browser enrols once. This lets the hint say "set it up on this device too"
// instead of the misleading "you don't have a signing passkey", which is what
// made it feel like a loop when signing across devices.
async function serverHasSigningKey() {
  try {
    const r = await fetch('/api/user/account/signing-key', { credentials: 'include' });
    if (!r.ok) return false;
    const body = await r.json().catch(() => ({}));
    return Array.isArray(body.keys) && body.keys.some((k) => !k.revoked_at);
  } catch { return false; }
}

// Display the passkey signing identity in the identity step (read-only, public
// metadata only — no unlock). If none is enrolled, deep-link to the enrol
// flow on /account (the "Set up a signing passkey" card).
async function showSigningIdentity() {
  const el = $('ds-signing-identity');
  if (!el) return;
  try {
    const k = await resolvePasskeySigningKey();
    state.signer.fingerprint = k.fingerprint;
    el.className = 'ds-hint';
    el.innerHTML = 'You\'ll sign with your signing key — unlocked with Face ID / Touch ID / a security key. ' +
      'Key fingerprint <code>' + escapeHtml(k.fingerprint) + '</code>.';
  } catch (e) {
    el.className = 'ds-hint';
    if (e && e.code === 'no_signing_passkey') {
      const elsewhere = await serverHasSigningKey();
      el.innerHTML = (elsewhere
        ? 'You\'ll sign with your sign-in passkey. Signing keys live in the browser where you create them, so this device sets one up the first time you sign — one Face ID / Touch ID tap, no passphrase, no code.'
        : 'You\'ll sign with your sign-in passkey — this device sets up your signing key with one tap the first time you sign. No passphrase, no separate code.');
    } else {
      el.textContent = (e && e.message) ? e.message : 'Could not check your signing key.';
    }
  }
}

function refreshIdentityValid() {
  // Identity is valid when there's a name AND the chosen sig-style has its data.
  const hasName = !!state.signer.name;
  const hasSig =
    state.signer.sigStyle === 'typed' ? true :
    state.signer.sigStyle === 'drawn' ? !!state.signer.sigImageBytes :
    state.signer.sigStyle === 'image' ? !!state.signer.sigImageBytes :
    false;
  $('ds-identity-continue').disabled = !(hasName && hasSig);
}

function selectSigStyle(style) {
  state.signer.sigStyle = style;
  document.querySelectorAll('.ds-sig-tabs .ds-tab').forEach(t => {
    const active = t.dataset.sig === style;
    t.classList.toggle('active', active);
    t.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  for (const k of ['typed', 'drawn', 'image']) {
    $('ds-sig-panel-' + k).hidden = (k !== style);
  }
  refreshIdentityValid();
}

// ---- drawn-signature canvas (pointer + touch) ----
function initDrawCanvas() {
  const cv = $('ds-sig-canvas');
  const ctx = cv.getContext('2d');
  // Fill white so the exported PNG isn't transparent against light backgrounds
  // (pdf-lib renders transparent PNG fine, but a white-bg signature also
  // shows clearly during the on-screen preview marker).
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, cv.width, cv.height);
  ctx.strokeStyle = '#0b3a6a';
  ctx.lineWidth = 2.2;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';

  let drawing = false;
  let last = null;

  function pos(ev) {
    const r = cv.getBoundingClientRect();
    const x = ((ev.clientX ?? (ev.touches && ev.touches[0].clientX)) - r.left) * (cv.width / r.width);
    const y = ((ev.clientY ?? (ev.touches && ev.touches[0].clientY)) - r.top) * (cv.height / r.height);
    return { x, y };
  }

  function start(ev) { ev.preventDefault(); drawing = true; last = pos(ev); }
  function move(ev) {
    if (!drawing) return;
    ev.preventDefault();
    const p = pos(ev);
    ctx.beginPath();
    ctx.moveTo(last.x, last.y);
    ctx.lineTo(p.x, p.y);
    ctx.stroke();
    last = p;
  }
  async function end(ev) {
    if (!drawing) return;
    drawing = false;
    // Convert to PNG bytes + data URL and stash. refreshIdentityValid will enable Continue.
    cv.toBlob(async (blob) => {
      if (!blob) return;
      const bytes = new Uint8Array(await blob.arrayBuffer());
      state.signer.sigImageBytes = bytes;
      state.signer.sigImageType = 'png';
      state.signer.sigImageDataUrl = await bytesToDataUrl(bytes, 'image/png');
      refreshIdentityValid();
    }, 'image/png');
  }

  // Pointer Events cover mouse, touch and pen on every modern browser (iOS 13+).
  // Using ONLY pointer events avoids the double-fire you get when touch* and
  // pointer* listeners both run on a touch device. The canvas has touch-action:none,
  // so panning/zooming never hijacks a stroke.
  cv.addEventListener('pointerdown', start);
  cv.addEventListener('pointermove', move);
  cv.addEventListener('pointerup', end);
  cv.addEventListener('pointercancel', end);
  cv.addEventListener('pointerleave', end);

  $('ds-sig-clear').addEventListener('click', () => {
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, cv.width, cv.height);
    state.signer.sigImageBytes = null;
    state.signer.sigImageType = null;
    refreshIdentityValid();
  });
}

// ---- image upload ----
function initImageUpload() {
  const inp = $('ds-sig-image-input');
  const drop = $('ds-sig-image-drop');
  drop.addEventListener('click', () => inp.click());
  inp.addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > 1024 * 1024) {
      alert('Image too large (max 1 MB).');
      return;
    }
    const bytes = new Uint8Array(await f.arrayBuffer());
    const type = (f.type === 'image/jpeg') ? 'jpg' : 'png';
    state.signer.sigImageBytes = bytes;
    state.signer.sigImageType = type;
    state.signer.sigImageDataUrl = await bytesToDataUrl(bytes, f.type);
    const img = $('ds-sig-image-preview');
    img.src = state.signer.sigImageDataUrl;
    img.style.display = 'block';
    refreshIdentityValid();
  });
}

// resolvePasskeySigningKey() now lives in parasign-signer.js (the single
// definition of "what a signing key is"), shared with /co-sign so the two flows
// can never drift on key selection.

function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function signedImageName() {
  const ext = state.imageType === 'jpg' ? 'jpg' : 'png';
  const dotIdx = state.doc.name.lastIndexOf('.');
  if (dotIdx < 0) return 'signed-' + state.doc.name + '.' + ext;
  return 'signed-' + state.doc.name.slice(0, dotIdx) + '.' + ext;
}

function signedDocName() {
  if (state.mode === 'pdf')   return 'signed-' + state.doc.name;
  if (state.mode === 'image') return signedImageName();
  return state.doc.name;
}

function signedDocMime() {
  if (state.mode === 'pdf') return 'application/pdf';
  if (state.mode === 'image') return state.imageType === 'jpg' ? 'image/jpeg' : 'image/png';
  return 'application/octet-stream';
}

// (v2 buildEnvelopeSignMessage removed — the signed message is now the v3
//  domain-prefixed buildDocSignMessage() in parasign-signer.js, byte-identical
//  to relay/envelope.js signMessageBytes(...,3).)

// ====================================================================
// Step 4: review + sign
// ====================================================================

function fillReview() {
  $('ds-review-doc').textContent  = state.doc.name + ' (' + formatSize(state.doc.size) + ')';
  $('ds-review-mode').textContent =
    state.mode === 'pdf'   ? 'PDF with visual stamp on page ' + (state.stamp.pageIndex + 1) :
    state.mode === 'image' ? 'Image with visual stamp baked in (' + (state.imageType || '').toUpperCase() + ')' :
                             'Hash-only (SHA3-256 attestation)';
  $('ds-review-name').textContent = state.signer.name;
  $('ds-review-sig').textContent =
    state.signer.sigStyle === 'typed'  ? 'Typed name in the stamp' :
    state.signer.sigStyle === 'drawn'  ? 'Drawn signature (' + formatSize(state.signer.sigImageBytes.length) + ' PNG)' :
                                         'Uploaded image (' + formatSize(state.signer.sigImageBytes.length) + ' ' + state.signer.sigImageType.toUpperCase() + ')';
  // Signing key: always the account's passkey-protected ML-DSA-65 key. The
  // fingerprint is filled async (public vault metadata, no unlock) below.
  $('ds-review-key-src').textContent = 'Your signing key (ML-DSA-65)';

  // Recipients summary. Multi-party envelopes are created same-origin via your
  // logged-in session (no manual API key); each recipient signs at /co-sign
  // with their own passkey.
  const recCell = $('ds-review-recipients');
  if (state.recipients.length === 0) {
    recCell.textContent = 'None - personal signature only';
  } else {
    const list = state.recipients.map(r => r.label + (r.email ? ' (' + r.email + ')' : '')).join(', ');
    recCell.innerHTML = state.recipients.length + ' co-signer' + (state.recipients.length === 1 ? '' : 's') + ': ' + escapeHtml(list);
  }

  // Cryptographic proof card: the mathematical evidence that backs the
  // visual seal. Document hash is computed live; fingerprint depends on
  // the key source.
  const docHashHex = toHex(sha3_256(state.doc.bytes));
  $('ds-proof-doc-hash').textContent = docHashHex;
  $('ds-proof-fp').textContent = '(your signing key fingerprint)';   // filled async below
  $('ds-proof-version').textContent = 'parasign-doc-3 (recipe_version 3)';

  // Envelope-structure preview — the v3 .psign receipt (parasign-doc-3). The
  // signed_message line shows the EXACT v3 domain-prefixed message the passkey
  // will sign (byte-identical to relay/envelope.js signMessageBytes(...,3)), so
  // the review reflects what is actually signed — not the old v2 message.
  const previewEnv = (state.mode === 'pdf' || state.mode === 'image') ? {
    version: 'parasign-doc-3',
    recipe_version: 3,
    sign_domain: 'paramant/parasign/doc/v1',
    algorithm: 'ML-DSA-65',
    hash_algorithm: 'SHA3-256',
    original_filename: state.doc.name,
    stamped_filename: state.mode === 'image' ? '<signed image>' : 'signed-' + state.doc.name,
    original_hash: docHashHex,
    stamped_hash: '<computed when the document is stamped>',
    coords: { pageIndex: state.stamp.pageIndex, x: Math.round(state.stamp.x), y: Math.round(state.stamp.y), w: state.stamp.w, h: state.stamp.h, name: state.signer.name, date: '<set on sign>' },
    signature_style: state.signer.sigStyle,
    signature_image_hash: state.signer.sigImageBytes ? toHex(sha3_256(state.signer.sigImageBytes)) : null,
    signer_public_key: '<base64 of your ML-DSA-65 public key>',
    signer_pk_fingerprint: '<sha3_256(pubkey)[..16]>',
    signed_message: 'sha3_256("paramant/parasign/doc/v1" || 0x00 || envelope_id || stamped_hash || party_index || party_email_hash)',
    signature: '<base64 of ML-DSA-65 signature over signed_message>',
    multiparty: { envelope_id: '<set on sign>', party_index: 0 },
    signed_at: '<set on sign>',
    disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
  } : {
    version: 'parasign-doc-3',
    recipe_version: 3,
    sign_domain: 'paramant/parasign/doc/v1',
    algorithm: 'ML-DSA-65',
    hash_algorithm: 'SHA3-256',
    original_filename: state.doc.name,
    document_hash: docHashHex,
    signer_name: state.signer.name,
    signer_public_key: '<base64 of your ML-DSA-65 public key>',
    signer_pk_fingerprint: '<sha3_256(pubkey)[..16]>',
    signed_message: 'sha3_256("paramant/parasign/doc/v1" || 0x00 || envelope_id || document_hash || party_index || party_email_hash)',
    signature: '<base64 of ML-DSA-65 signature over signed_message>',
    multiparty: { envelope_id: '<set on sign>', party_index: 0 },
    signed_at: '<set on sign>',
    disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
  };
  $('ds-proof-json').textContent = JSON.stringify(previewEnv, null, 2);

  // Render visual previews of doc + signature so the signer sees exactly
  // what they are about to commit to before clicking Sign now.
  renderReviewPreviews().catch(err => console.warn('review preview failed', err));
  // Fill the passkey key fingerprint (async, public vault metadata only).
  fillReviewKeyFingerprint().catch(() => {});
}

// Fill the signing-key fingerprint into the review card from PUBLIC vault
// metadata (no unlock). On a device with no signing passkey, say so plainly.
async function fillReviewKeyFingerprint() {
  try {
    const k = await resolvePasskeySigningKey();
    state.signer.fingerprint = k.fingerprint;
    const fpEl = $('ds-proof-fp'); if (fpEl) fpEl.textContent = k.fingerprint;
    const ksEl = $('ds-review-key-src'); if (ksEl) ksEl.textContent = 'Your signing key (' + k.fingerprint + ')';
  } catch (e) {
    const fpEl = $('ds-proof-fp');
    if (fpEl) fpEl.textContent = (e && e.code === 'no_signing_passkey') ? '(set up with one passkey tap when you sign)' : '(unavailable)';
  }
}

async function renderReviewPreviews() {
  await renderDocPreview();
  renderSigPreview();
}

async function renderDocPreview() {
  const pane = $('ds-review-doc-preview');
  if (!pane) return;
  pane.innerHTML = '';
  pane.classList.remove('has-pdf');

  if (state.mode === 'pdf') {
    pane.classList.add('has-pdf');
    const pdfjs = await waitForPdfjs();
    const copy = new Uint8Array(state.doc.bytes);
    const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
    const page = await pdf.getPage(state.stamp.pageIndex + 1);
    const baseViewport = page.getViewport({ scale: 1 });
    // Target a smaller render for the review (max ~340px wide) so it fits the grid cell.
    const targetW = Math.min(340, Math.floor(pane.clientWidth || 340));
    const scale = targetW / baseViewport.width;
    const viewport = page.getViewport({ scale });
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    pane.appendChild(canvas);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
    // Mock the stamp as an absolutely positioned overlay so the user sees
    // where it will land. Convert PDF points -> displayed pixels.
    const ratio = baseViewport.width / canvas.getBoundingClientRect().width;
    const left = state.stamp.x / ratio;
    const top  = (baseViewport.height - state.stamp.y - state.stamp.h) / ratio;
    const w = state.stamp.w / ratio;
    const h = state.stamp.h / ratio;
    const mock = document.createElement('div');
    mock.className = 'ds-mockup-stamp';
    mock.style.cssText = `left:${left}px;top:${top}px;width:${w}px;height:${h}px`;
    mock.innerHTML = stampInnerHtml();
    pane.appendChild(mock);
    return;
  }

  // Image-mode: render the image with the same stamp-mockup overlay
  // the PDF preview gets, so the signer sees WHERE the seal will land.
  if (state.mode === 'image' && state.signer.docImageDataUrl && state.stamp) {
    pane.classList.add('has-pdf');   // reuse PDF-pane layout (top-aligned, scrollable)
    const wrap = document.createElement('div');
    wrap.style.cssText = 'position:relative;display:inline-block;width:100%';
    const img = document.createElement('img');
    img.src = state.signer.docImageDataUrl;
    img.alt = state.doc.name;
    img.style.cssText = 'display:block;width:100%;height:auto';
    wrap.appendChild(img);
    pane.appendChild(wrap);
    img.onload = () => {
      // Image natural -> displayed ratio
      const rect = img.getBoundingClientRect();
      const ratio = state.doc && state.signer.docImageDataUrl ? (img.naturalWidth / rect.width) : 1;
      const left = state.stamp.x / ratio;
      const top  = state.stamp.y / ratio;
      const w = state.stamp.w / ratio;
      const h = state.stamp.h / ratio;
      const mock = document.createElement('div');
      mock.className = 'ds-mockup-stamp';
      mock.style.cssText = `left:${left}px;top:${top}px;width:${w}px;height:${h}px`;
      mock.innerHTML = stampInnerHtml();
      wrap.appendChild(mock);
    };
    return;
  }

  // Non-PDF, non-image with mode hash: try to show as plain image if viewable.
  if (state.signer.docImageDataUrl) {
    const img = document.createElement('img');
    img.src = state.signer.docImageDataUrl;
    img.alt = state.doc.name;
    pane.appendChild(img);
    return;
  }

  // Fallback: filename + size + hash so the signer can confirm what they picked.
  const meta = document.createElement('div');
  meta.className = 'ds-pane-meta';
  const sha = toHex(sha3_256(state.doc.bytes));
  meta.innerHTML =
    '<div><strong>File</strong> ' + escapeHtml(state.doc.name) + '</div>' +
    '<div><strong>Size</strong> ' + formatSize(state.doc.size) + '</div>' +
    '<div style="margin-top:8px"><strong>SHA3-256</strong></div>' +
    '<div style="font-size:10px">' + sha + '</div>';
  pane.appendChild(meta);
}

function renderSigPreview() {
  const pane = $('ds-review-sig-preview');
  if (!pane) return;
  pane.innerHTML = '';

  if (state.signer.sigStyle === 'typed') {
    const el = document.createElement('div');
    el.className = 'ds-typed-preview';
    el.textContent = state.signer.name || '(no name)';
    pane.appendChild(el);
    return;
  }

  if (state.signer.sigImageDataUrl) {
    const img = document.createElement('img');
    img.src = state.signer.sigImageDataUrl;
    img.alt = state.signer.sigStyle === 'drawn' ? 'Drawn signature' : 'Uploaded signature';
    pane.appendChild(img);
    return;
  }

  pane.textContent = '(no signature data)';
}

function stampInnerHtml() {
  return stampMockupHtml();
}

// Single source of truth for the on-screen stamp mockup (placement marker +
// review preview). The PDF renderer in buildStampedPdf produces the real
// thing; this mockup is a faithful HTML/CSS approximation so the signer
// sees the same layout before clicking Sign.
function stampMockupHtml() {
  const name = (state.signer.name || 'Signer').slice(0, 40);
  const dateStr = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const fp = state.signer.fingerprint ? state.signer.fingerprint.slice(0, 8) : 'pending';
  let mid = '';
  if (state.signer.sigStyle !== 'typed' && state.signer.sigImageDataUrl) {
    mid = `<img class="ds-sm-sig-img" src="${state.signer.sigImageDataUrl}" alt="">`;
  } else {
    mid = `<div class="ds-sm-sig-typed">${escapeHtml(name)}</div>`;
  }
  return (
    `<div class="ds-sm-band">` +
      `<span class="ds-sm-logo">Para<span>MANT</span></span>` +
      `<span class="ds-sm-badge">POST-QUANTUM SIGNED</span>` +
    `</div>` +
    `<div class="ds-sm-mid">${mid}</div>` +
    `<div class="ds-sm-foot">` +
      `<span class="ds-sm-name">${escapeHtml(name)}</span>` +
      `<span class="ds-sm-date">${dateStr}</span>` +
    `</div>` +
    `<div class="ds-sm-crypto">ML-DSA-65 (FIPS 204) - PQ ${fp}</div>`
  );
}

function guessMimeFromMagic(bytes) {
  if (bytes.length < 4) return null;
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'image/png';
  if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'image/jpeg';
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'image/gif';
  if (bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'image/webp';
  return null;
}

async function buildStampedImage(origBytes, stamp, signerName, dateStr, fingerprint8, imageType) {
  const mime = imageType === 'jpg' ? 'image/jpeg' : 'image/png';
  const img = await loadImageElement(origBytes, mime);
  const canvas = document.createElement('canvas');
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);

  // Load the signature image (if any) before drawing so we can do a
  // synchronous compose pass.
  let sigImg = null;
  if (state.signer.sigStyle !== 'typed' && state.signer.sigImageDataUrl) {
    sigImg = await new Promise((resolve, reject) => {
      const i = new Image();
      i.onload = () => resolve(i);
      i.onerror = () => reject(new Error('signature image decode failed'));
      i.src = state.signer.sigImageDataUrl;
    });
  }

  drawStampOnCanvas(ctx, stamp, signerName, dateStr, fingerprint8, sigImg);

  return await new Promise((resolve, reject) => {
    canvas.toBlob(async (blob) => {
      if (!blob) return reject(new Error('canvas toBlob failed'));
      resolve(new Uint8Array(await blob.arrayBuffer()));
    }, mime, imageType === 'jpg' ? 0.92 : undefined);
  });
}

function drawStampOnCanvas(ctx, stamp, signerName, dateStr, fingerprint8, sigImg) {
  const { x, y, w, h } = stamp;
  // Outer fill + border
  ctx.fillStyle = 'rgba(11, 58, 106, 0.03)';
  ctx.fillRect(x, y, w, h);
  ctx.strokeStyle = '#0b3a6a';
  ctx.lineWidth = Math.max(1, w / 200);
  ctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);

  // Cobalt header band with ParaMANT wordmark + POST-QUANTUM SIGNED badge
  const bandH = h * 0.18;
  ctx.fillStyle = '#0b3a6a';
  ctx.fillRect(x, y, w, bandH);
  ctx.fillStyle = '#ffffff';
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'left';
  ctx.font = 'bold ' + (bandH * 0.55) + 'px Helvetica, Arial, sans-serif';
  ctx.fillText('ParaMANT', x + w * 0.025, y + bandH / 2);
  ctx.textAlign = 'right';
  ctx.font = 'bold ' + (bandH * 0.4) + 'px Helvetica, Arial, sans-serif';
  ctx.fillText('POST-QUANTUM SIGNED', x + w - w * 0.025, y + bandH / 2);

  // Middle area: signature image (drawn/uploaded) or italic typed name
  const midY = y + bandH + h * 0.02;
  const midH = h * 0.5;
  const padX = w * 0.04;
  if (sigImg) {
    const maxW = w - padX * 2;
    const maxH = midH;
    const scale = Math.min(maxW / sigImg.naturalWidth, maxH / sigImg.naturalHeight);
    const sw = sigImg.naturalWidth * scale;
    const sh = sigImg.naturalHeight * scale;
    ctx.drawImage(sigImg, x + (w - sw) / 2, midY + (midH - sh) / 2, sw, sh);
  } else {
    ctx.fillStyle = '#0b3a6a';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    let fontSize = midH * 0.7;
    ctx.font = 'italic ' + fontSize + 'px "Times New Roman", Times, serif';
    while (fontSize > h * 0.12 && ctx.measureText(signerName).width > (w - padX * 2)) {
      fontSize -= 1;
      ctx.font = 'italic ' + fontSize + 'px "Times New Roman", Times, serif';
    }
    ctx.fillText(signerName, x + w / 2, midY + midH / 2);
  }

  // Divider above the footer band
  ctx.strokeStyle = 'rgba(11, 58, 106, 0.25)';
  ctx.lineWidth = Math.max(0.5, w / 400);
  ctx.beginPath();
  ctx.moveTo(x + padX, y + h - h * 0.28);
  ctx.lineTo(x + w - padX, y + h - h * 0.28);
  ctx.stroke();

  // Footer: signer name + date on row 1, crypto on row 2
  const footY1 = y + h - h * 0.21;
  const footY2 = y + h - h * 0.08;
  ctx.textBaseline = 'middle';
  ctx.fillStyle = '#0b3a6a';
  ctx.textAlign = 'left';
  ctx.font = 'bold ' + (h * 0.085) + 'px Helvetica, Arial, sans-serif';
  ctx.fillText(signerName, x + padX, footY1);
  ctx.fillStyle = '#4d4d4d';
  ctx.font = (h * 0.08) + 'px ui-monospace, Menlo, monospace';
  ctx.textAlign = 'right';
  ctx.fillText(dateStr, x + w - padX, footY1);
  ctx.textAlign = 'left';
  ctx.font = (h * 0.07) + 'px ui-monospace, Menlo, monospace';
  ctx.fillText('ML-DSA-65 (FIPS 204) - PQ ' + fingerprint8, x + padX, footY2);
}

async function buildStampedPdf(origBytes, stamp, signerName, dateStr, fingerprint8) {
  const PDFLib = await waitForPdfLib();
  const pdfDoc = await PDFLib.PDFDocument.load(origBytes);
  const page = pdfDoc.getPages()[stamp.pageIndex];
  const font     = await pdfDoc.embedFont(PDFLib.StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
  const fontItal = await pdfDoc.embedFont(PDFLib.StandardFonts.TimesRomanItalic);
  const navy  = PDFLib.rgb(0.043, 0.227, 0.416);
  const dim   = PDFLib.rgb(0.30, 0.30, 0.30);
  const white = PDFLib.rgb(1, 1, 1);

  // Outer border + faint fill
  page.drawRectangle({ x: stamp.x, y: stamp.y, width: stamp.w, height: stamp.h, borderColor: navy, borderWidth: 1.2, color: navy, opacity: 0.03 });

  // Branded top band: cobalt bar with logo + PQ badge
  const bandH = 16;
  page.drawRectangle({ x: stamp.x, y: stamp.y + stamp.h - bandH, width: stamp.w, height: bandH, color: navy });
  // 'Para' + 'MANT' both white on navy (no two-tone in PDF stamp; we keep the
  // wordmark monochrome here for legibility at small print sizes).
  page.drawText('ParaMANT', { x: stamp.x + 8, y: stamp.y + stamp.h - 11, size: 9, font: fontBold, color: white });
  const badge = 'POST-QUANTUM SIGNED';
  const badgeW = fontBold.widthOfTextAtSize(badge, 6);
  page.drawText(badge, { x: stamp.x + stamp.w - badgeW - 8, y: stamp.y + stamp.h - 10.5, size: 6, font: fontBold, color: white });

  // Bottom metadata band: signer + date on row 1, algo + fingerprint on row 2
  const footerH = 22;
  page.drawText(signerName, { x: stamp.x + 8, y: stamp.y + 13, size: 8, font: fontBold, color: navy });
  const dateW = font.widthOfTextAtSize(dateStr, 7);
  page.drawText(dateStr, { x: stamp.x + stamp.w - dateW - 8, y: stamp.y + 13, size: 7, font, color: dim });
  const cryptoLine = 'ML-DSA-65 (FIPS 204)  -  PQ ' + fingerprint8;
  page.drawText(cryptoLine, { x: stamp.x + 8, y: stamp.y + 4, size: 6, font, color: dim });

  // Middle area: signature image, or signer name in italic for the 'typed' style
  const midY = stamp.y + footerH;
  const midH = stamp.h - bandH - footerH;
  const padX = 8;

  const hasImg = state.signer.sigStyle !== 'typed' && state.signer.sigImageBytes;
  if (hasImg) {
    const embed = state.signer.sigImageType === 'jpg'
      ? await pdfDoc.embedJpg(state.signer.sigImageBytes)
      : await pdfDoc.embedPng(state.signer.sigImageBytes);
    const maxW = stamp.w - padX * 2;
    const maxH = midH - 4;
    const scale = Math.min(maxW / embed.width, maxH / embed.height);
    const w = embed.width * scale;
    const h = embed.height * scale;
    page.drawImage(embed, {
      x: stamp.x + (stamp.w - w) / 2,
      y: midY + (midH - h) / 2,
      width: w, height: h,
    });
  } else {
    // Typed signature: render the name in TimesRomanItalic so it reads as
    // a 'signature' rather than a label. Scale font to fit.
    const maxW = stamp.w - padX * 2;
    let fontSize = 22;
    while (fontSize > 9 && fontItal.widthOfTextAtSize(signerName, fontSize) > maxW) fontSize -= 1;
    const w = fontItal.widthOfTextAtSize(signerName, fontSize);
    page.drawText(signerName, {
      x: stamp.x + (stamp.w - w) / 2,
      y: midY + (midH - fontSize) / 2 + 2,
      size: fontSize, font: fontItal, color: navy,
    });
  }

  // Subtle horizontal divider above the metadata band
  page.drawLine({
    start: { x: stamp.x + 6, y: stamp.y + footerH - 1 },
    end:   { x: stamp.x + stamp.w - 6, y: stamp.y + footerH - 1 },
    thickness: 0.5, color: navy, opacity: 0.25,
  });

  return await pdfDoc.save();
}

async function doSign() {
  // STEP 2 of the two-step flow: this explicit action triggers the per-document
  // passkey-PRF activation (the Face ID / Touch ID / security-key prompt fires
  // here, bound to THIS document) — step 1 was the review/preview.
  $('ds-sign-now').disabled = true;
  $('ds-sign-status').hidden = false;
  $('ds-sign-status').className = 'ds-banner';
  const status = (t) => { $('ds-sign-status').textContent = t; };

  try {
    // The signing key is the account's PASSKEY-protected ML-DSA-65 key. Read ONLY
    // its public half from vault metadata here (for the stamp fingerprint); the
    // secret is unlocked solely by the per-document PRF activation below.
    status('Locating your signing key...');
    // Resolve the account's signing key, or set one up inline. Happy path is one
    // passkey tap (PRF). If the passkey provider can't do PRF (e.g. Proton Pass),
    // ensureSigningKey throws prf_unsupported and we fall back to a passphrase-
    // protected signing key — still bound to the account via the same passkey.
    let signKey, signPassphrase = null;
    try {
      signKey = await ensureSigningKey({ rpId: location.hostname, label: state.signer.name || 'Signing key', onStatus: status });
    } catch (e) {
      if (!e || e.code !== 'prf_unsupported') throw e;
      signPassphrase = await promptPassphrase('ds-pass', 'set');
      if (signPassphrase == null) { const c = new Error('cancelled'); c.code = 'cancelled'; throw c; }
      status('Setting up your signing key…');
      signKey = await enrolSigningKeyWithPassphrase({ rpId: location.hostname, label: state.signer.name || 'Signing key', passphrase: signPassphrase, onStatus: status });
    }
    const fingerprint = signKey.fingerprint;
    const dateStr = new Date().toISOString().slice(0, 19) + 'Z';

    // 1) STAMP (PDF/image) + HASH — unchanged. The stamp shows the PUBLIC fingerprint.
    let stampedBytes = null, origHashHex = null, stampedHashHex = null, coords = null, docHashForEnvelope;
    if (state.mode === 'pdf' || state.mode === 'image') {
      status(state.mode === 'pdf' ? 'Stamping PDF...' : 'Stamping image...');
      stampedBytes = state.mode === 'pdf'
        ? await buildStampedPdf(state.doc.bytes, state.stamp, state.signer.name, dateStr, fingerprint)
        : await buildStampedImage(state.doc.bytes, state.stamp, state.signer.name, dateStr, fingerprint, state.imageType);
      origHashHex = toHex(sha3_256(state.doc.bytes));
      stampedHashHex = toHex(sha3_256(stampedBytes));
      coords = { pageIndex: state.stamp.pageIndex, x: state.stamp.x, y: state.stamp.y, w: state.stamp.w, h: state.stamp.h, name: state.signer.name, date: dateStr, isImage: !!state.stamp.isImage };
      docHashForEnvelope = stampedHashHex;
    } else {
      docHashForEnvelope = toHex(sha3_256(state.doc.bytes));
    }

    // 2) Create the signing envelope SAME-ORIGIN (party 0 = you; + any recipients),
    //    recipe_version 3. A self-sign (no recipients) STILL gets an envelope, so
    //    every signature goes through the per-document activation gate (R018) —
    //    no separate weaker self-sign route.
    status('Preparing this document for signing...');
    const created = await createSigningEnvelope({
      docHash: docHashForEnvelope,
      recipients: state.recipients,
      originalFilename: state.mode === 'pdf' ? 'signed-' + state.doc.name : state.doc.name,
      signerLabel: state.signer.name,
      creatorPublicKey: signKey.pk_b64,
    });
    const env = created.envelope;
    state.envelope = env;
    const myLink = (env.party_links || []).find((p) => p.party_index === 0) || {};

    // 3) Per-document activation (authorize -> one-shot token), THEN the passkey-PRF
    //    unlock + sign of the v3 domain-prefixed message, THEN submit. The secret
    //    key lives ONLY inside the ActivatedSigner and is zeroized by dispose().
    status('Requesting signing authorization...');
    const act = await requestSignActivation({ envelopeId: env.id, partyIndex: 0, docHash: docHashForEnvelope, inviteToken: myLink.invite_token });

    status('Confirm to sign (Face ID / Touch ID / security key)...');
    // PRF key: one tap. Passphrase key: unlock with the passphrase — reuse the one
    // just set during enrol, or ask for it on an already-enrolled passphrase key.
    if (!signKey.hasPrf && signPassphrase == null) {
      signPassphrase = await promptPassphrase('ds-pass', 'unlock');
      if (signPassphrase == null) { const c = new Error('cancelled'); c.code = 'cancelled'; throw c; }
    }
    const signer = await new LocalVaultSigner().activate({ vaultId: signKey.vaultId, rpId: location.hostname, passphrase: signKey.hasPrf ? undefined : signPassphrase });
    let sigB64;
    try {
      const message = buildDocSignMessage({ envelopeId: env.id, docHash: docHashForEnvelope, partyIndex: 0, emailHash: act.email_hash });
      sigB64 = toB64(await signer.sign(message));
    } finally {
      signer.dispose();   // zeroize — the secret never outlives this block
    }

    status('Recording your signature...');
    const submitted = await submitSignature({ activationId: act.activation_id, signerPublicKey: signer.publicKey, signature: sigB64 });

    // 4) v3 .psign receipt. The authoritative, CT-logged signature record is the
    //    relay envelope; this file points at it (envelope_id + party 0).
    const mp = { envelope_id: env.id, party_index: 0, party_count: env.party_count, party_links: env.party_links, expires_at: env.expires_at, signed_count: submitted.signed_count };
    let envelope;
    if (state.mode === 'pdf' || state.mode === 'image') {
      envelope = {
        version: 'parasign-doc-3', recipe_version: 3, sign_domain: 'paramant/parasign/doc/v1',
        algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256',
        original_filename: state.doc.name, stamped_filename: state.mode === 'image' ? signedImageName() : 'signed-' + state.doc.name,
        original_hash: origHashHex, stamped_hash: stampedHashHex, coords,
        signature_style: state.signer.sigStyle,
        signature_image_hash: state.signer.sigImageBytes ? toHex(sha3_256(state.signer.sigImageBytes)) : null,
        signer_public_key: signKey.pk_b64, signer_pk_fingerprint: fingerprint,
        signature: sigB64, signed_at: dateStr, multiparty: mp,
        disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
      };
    } else {
      envelope = {
        version: 'parasign-doc-3', recipe_version: 3, sign_domain: 'paramant/parasign/doc/v1',
        algorithm: 'ML-DSA-65', hash_algorithm: 'SHA3-256',
        original_filename: state.doc.name, document_hash: docHashForEnvelope,
        signer_name: state.signer.name,
        signer_public_key: signKey.pk_b64, signer_pk_fingerprint: fingerprint,
        signature: sigB64, signed_at: dateStr, multiparty: mp,
        disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
      };
    }

    state.result = { stampedBytes, envelope, fingerprint };
    showDone();
  } catch (e) {
    $('ds-sign-status').className = 'ds-banner err';
    // Map to an actionable message. A passkey/provider error (e.g. Firefox's
    // opaque "AuthenticatorError" from a PRF assertion) has no e.status/e.code,
    // so it lands in the final else with a recovery path — never the raw engine
    // string, which leaked before and read as a crash to the user.
    let msg;
    if (e && e.status === 401) msg = 'Please sign in to sign documents. Open /auth/login, then return here.';
    else if (e && e.code === 'no_passkey') msg = 'Add a passkey to your account first (Account → Passkey sign-in), then sign — your sign-in passkey becomes your signing key.';
    else if (e && (e.code === 'vault_unavailable' || e.code === 'no_webauthn')) msg = e.message;
    else if (e && e.name === 'NotAllowedError') msg = 'Passkey confirmation was cancelled or timed out. Tap Sign now to try again.';
    else if (e && e.code === 'cancelled') msg = 'Signing cancelled. Tap Sign now when you’re ready.';
    else if (e && /wrong passphrase/i.test(e.message || '')) msg = 'That signing passphrase didn’t match. Tap Sign now and re-enter it.';
    else if (e && (e.code === 'prf_unsupported' || e.code === 'need_passphrase')) msg = 'Your passkey can’t do one-tap signing here. Tap Sign now to set or enter a signing passphrase instead.';
    else if (e && (e.status === 403 || e.status === 409 || e.status === 410)) msg = 'That signing authorization was already used or has expired. Tap Sign now to start a fresh one.';
    else if (e && e.status) msg = 'Signing could not be completed right now (server error ' + e.status + '). Please try again in a moment.';
    else msg = 'Your passkey could not complete signing on this browser. Tap Sign now to try again. If it keeps failing, try a different browser, or use the passkey on your phone.';
    $('ds-sign-status').textContent = msg;
    $('ds-sign-now').disabled = false;
  }
}

function downloadBytes(bytes, name, mime) {
  const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);
}

function showDone() {
  setActive('step-done');
  const r = state.result;
  if (state.signingMode === 'invite') { showDoneInvite(r); return; }

  // Success banner: the signature was produced locally (the private key never
  // left the browser); the relay only recorded the public signature + CT entry.
  const sb = $('ds-success-banner');
  if (sb) {
    sb.hidden = false;
    sb.className = 'ds-success';
    sb.innerHTML =
      '<div class="ds-success-icon" aria-hidden="true">&#10003;</div>' +
      '<div><strong>Signed locally with ML-DSA-65.</strong>' +
      ' <span>Your private key never left this browser. The envelope below is self-contained and verifiable offline.</span></div>';
  }

  $('ds-done-fingerprint').textContent = r.fingerprint;
  $('ds-done-name').textContent = state.doc.name;
  $('ds-done-mode').textContent =
    state.mode === 'pdf'   ? 'PDF with visual stamp on page ' + (state.stamp.pageIndex + 1) :
    state.mode === 'image' ? 'Image with visual stamp baked in (' + (state.imageType || '').toUpperCase() + ')' :
                             'Hash-only attestation (SHA3-256)';

  // v3: the signature was submitted to the relay (same-origin, via the
  // per-document activation) which recorded it on the envelope and wrote it to
  // the public CT log. There is no optional "notary" step any more.
  if ($('ds-done-notary')) $('ds-done-notary').textContent = 'Yes - recorded on the relay and the public CT log';

  const psignName = (state.mode === 'pdf' ? 'signed-' + state.doc.name : state.doc.name).replace(/\.[^.]+$/, '') + '.psign';
  $('ds-dl-psign').onclick = () => downloadBytes(new TextEncoder().encode(JSON.stringify(r.envelope, null, 2)), psignName, 'application/json');
  if (r.stampedBytes) {
    $('ds-dl-pdf').hidden = false;
    $('ds-dl-pdf').textContent = state.mode === 'pdf' ? 'Download signed PDF' : 'Download signed image';
    $('ds-dl-pdf').onclick = () => downloadBytes(r.stampedBytes, signedDocName(), signedDocMime());
  } else {
    $('ds-dl-pdf').hidden = true;
  }

  // Populate the 'how to use' files list and notary-condition bullet.
  // psignName already computed above (used for the .psign download button).
  const filesList = $('ds-usage-files');
  if (filesList) {
    filesList.innerHTML = '';
    if (r.stampedBytes) {
      const li1 = document.createElement('li');
      const what = state.mode === 'pdf' ? 'signed PDF' : 'signed image';
      li1.innerHTML = `<span class="ds-usage-files-file">${escapeHtml(signedDocName())}</span><span class="ds-usage-files-note">the ${what} with your visible Paramant seal baked in</span>`;
      filesList.appendChild(li1);
    } else {
      const li1 = document.createElement('li');
      li1.innerHTML = `<span class="ds-usage-files-file">${escapeHtml(state.doc.name)}</span><span class="ds-usage-files-note">the original file (unchanged - hash-only mode does not modify it)</span>`;
      filesList.appendChild(li1);
    }
    const li2 = document.createElement('li');
    li2.innerHTML = `<span class="ds-usage-files-file">${escapeHtml(psignName)}</span><span class="ds-usage-files-note">the cryptographic envelope (ML-DSA-65 signature + your public key + metadata)</span>`;
    filesList.appendChild(li2);
  }
  const notaryLine = $('ds-usage-notary-line');
  if (notaryLine) {
    notaryLine.textContent = 'Your signature is recorded on the Paramant relay and written to the public CT log, so recipients get an independent witness of when this signing happened.';
  }

  // Multi-party: render share-links for the recipients (party 1..N).
  // Sender (party 0) is auto-signed; their link is not displayed.
  if (r.envelope.multiparty && r.envelope.multiparty.party_links) {
    renderPartyLinks(r.envelope.multiparty);
  }

  // Render the signed result so the user can see their stamp before downloading.
  renderSignedPreview().catch(() => {});
}

// Invite-to-sign done screen: there is no signed document (the requester didn't
// sign) — show the per-recipient signing links to share.
function showDoneInvite(r) {
  const sb = $('ds-success-banner');
  if (sb) {
    sb.hidden = false; sb.className = 'ds-success';
    sb.innerHTML = '<div class="ds-success-icon" aria-hidden="true">&#10003;</div>' +
      '<div><strong>Signing request created.</strong> <span>Send each person their link below — they verify the document hash and sign on the relay. Nothing is uploaded.</span></div>';
  }
  const h = document.querySelector('#step-done h2'); if (h) h.textContent = 'Sent for signature';
  const sub = document.querySelector('#step-done .ds-sub'); if (sub) sub.textContent = 'Each signer below gets a personal link. Share it with them; follow progress on the envelope status page.';
  const preview = $('ds-signed-preview'); if (preview) preview.hidden = true;
  ['ds-dl-pdf', 'ds-dl-psign'].forEach(id => { const el = $(id); if (el) el.hidden = true; });
  const info = document.querySelector('#step-done .ds-info-card'); if (info) info.hidden = true;
  document.querySelectorAll('#step-done .ds-usage-card').forEach(c => { if (c.id !== 'ds-party-links-card') c.hidden = true; });
  if (r.envelope.multiparty && r.envelope.multiparty.party_links) renderPartyLinks(r.envelope.multiparty);
}

function renderPartyLinks(mp) {
  const card = $('ds-party-links-card');
  const list = $('ds-party-links');
  if (!card || !list) return;
  card.hidden = false;
  list.innerHTML = '';
  // Skip party 0 (sender, already signed). Show 1..N.
  const links = mp.party_links.filter(p => p.party_index > 0);
  if (links.length === 0) { card.hidden = true; return; }

  for (const p of links) {
    const recipient = state.recipients[p.party_index - 1] || { label: 'Recipient ' + p.party_index };
    const fullUrl = location.origin + p.sign_path;
    const row = document.createElement('div');
    row.className = 'ds-party-link-row';
    row.innerHTML =
      `<div class="ds-pl-label">${escapeHtml(recipient.label)}${recipient.email ? '<div style="font-size:10px;color:var(--ink-dim);font-weight:400">' + escapeHtml(recipient.email) + '</div>' : ''}</div>` +
      `<div class="ds-pl-url" title="${escapeHtml(fullUrl)}">${escapeHtml(fullUrl)}</div>` +
      `<button class="ds-pl-copy" type="button">Copy link</button>`;
    const btn = row.querySelector('.ds-pl-copy');
    btn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(fullUrl);
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = 'Copy link'; btn.classList.remove('copied'); }, 1500);
      } catch {
        // Fallback: select the URL element for manual copy
        const range = document.createRange();
        range.selectNode(row.querySelector('.ds-pl-url'));
        getSelection().removeAllRanges();
        getSelection().addRange(range);
        btn.textContent = 'Select all (Ctrl+C)';
      }
    };
    list.appendChild(row);
  }

  // Status-page link points at the relay's redacted (public) envelope view.
  // This is the ONLY relay-host reference left in the sign path, and it is a
  // read-only status link; the signing itself routes same-origin via the admin
  // (/api/user/sign/*). The relay GET /v2/envelopes/:id is public.
  const statusLink = $('ds-envelope-status-link');
  if (statusLink) {
    statusLink.href = RELAY_PUBLIC + '/v2/envelopes/' + mp.envelope_id;
    statusLink.textContent = 'envelope ' + mp.envelope_id.slice(0, 10) + '... on the relay';
  }
}

async function renderSignedPreview() {
  const container = $('ds-signed-preview');
  if (!container) return;
  container.innerHTML = '';
  const r = state.result;

  // Hash-only mode: nothing rendered, just show the hash + signature head.
  if (state.mode === 'hash' || !r.stampedBytes) {
    container.innerHTML =
      '<div class="ds-info-card"><dl>' +
      '<dt>Signed bytes (SHA3-256)</dt><dd>' + escapeHtml(r.envelope.document_hash || '-') + '</dd>' +
      '<dt>Signature (b64, first 32)</dt><dd>' + escapeHtml((r.envelope.signature || '').slice(0, 32)) + '...</dd>' +
      '</dl></div>';
    return;
  }

  // Image mode: show the stamped image (the seal is baked into the bytes).
  if (state.mode === 'image') {
    const mime = state.imageType === 'jpg' ? 'image/jpeg' : 'image/png';
    const dataUrl = await bytesToDataUrl(r.stampedBytes, mime);
    const img = document.createElement('img');
    img.src = dataUrl;
    img.alt = signedDocName();
    img.style.cssText = 'width:100%;height:auto;display:block;border:1px solid var(--ink-hair);background:#fff';
    container.appendChild(img);
    return;
  }

  // PDF mode: render the stamp page (and the next page if it exists) so the
  // signer sees their stamp in context without scrolling long documents.
  const pdfjs = await waitForPdfjs();
  const copy = new Uint8Array(r.stampedBytes);
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
  const idxs = [state.stamp.pageIndex];
  if (state.stamp.pageIndex + 1 < pdf.numPages) idxs.push(state.stamp.pageIndex + 1);
  for (const idx of idxs) {
    const page = await pdf.getPage(idx + 1);
    const baseViewport = page.getViewport({ scale: 1 });
    const targetWidth = Math.min(820, Math.floor(window.innerWidth * 0.88));
    const scale = targetWidth / baseViewport.width;
    const viewport = page.getViewport({ scale });
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    container.appendChild(canvas);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  }
}

// ====================================================================
// Wiring
// ====================================================================

function wireNav() {
  // After the document: co-sign/invite go to recipients; sign-alone skips to identity.
  const afterDoc = () => { if (state.signingMode === 'alone') setActive('step-identity'); else enterRecipients(); };
  $('ds-place-continue').addEventListener('click', afterDoc);
  $('ds-hash-only-continue').addEventListener('click', afterDoc);
  $('ds-place-back').addEventListener('click', () => setActive('step-doc'));
  $('ds-hash-only-back').addEventListener('click', () => setActive('step-doc'));
  $('ds-recipients-back').addEventListener('click', () => {
    if (state.signingMode === 'invite') setActive('step-doc');
    else setActive(state.mode === 'pdf' ? 'step-place' : 'step-hash-only');
  });
  $('ds-recipients-continue').addEventListener('click', () => {
    commitRecipientsFromDom();
    if (state.signingMode === 'invite') {
      if (state.recipients.length === 0) { showRecipientsHint('Add at least one person to send this to.', true); return; }
      sendForSignature();
    } else {
      setActive('step-identity');
    }
  });
  $('ds-add-recipient').addEventListener('click', addRecipientRow);
  $('ds-identity-back').addEventListener('click', () => {
    if (state.signingMode === 'alone') setActive(state.mode === 'pdf' ? 'step-place' : 'step-hash-only');
    else setActive('step-recipients');
  });
  $('ds-identity-continue').addEventListener('click', () => {
    fillReview();
    setActive('step-sign');
  });
  $('ds-sign-back').addEventListener('click', () => setActive('step-identity'));
  $('ds-sign-now').addEventListener('click', doSign);
  $('ds-restart').addEventListener('click', () => location.reload());
}

// ====================================================================
// Recipients step
// ====================================================================

function renderRecipients() {
  const list = $('ds-recipients-list');
  list.innerHTML = '';
  if (state.recipients.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'ds-recipient-empty';
    empty.innerHTML = (state.signingMode === 'invite')
      ? 'Add the people who need to sign this document. Each one gets their own link to sign.'
      : 'No co-signers yet. Click <strong>+ Add recipient</strong> to invite someone, or <strong>Continue</strong> to sign just for yourself.';
    list.appendChild(empty);
    return;
  }
  state.recipients.forEach((r, i) => list.appendChild(buildRecipientRow(i, r)));
}

function buildRecipientRow(idx, data) {
  const row = document.createElement('div');
  row.className = 'ds-recipient-row';
  row.dataset.idx = String(idx);
  row.innerHTML =
    `<input class="ds-input" type="text" data-field="label" maxlength="80" placeholder="Recipient name (required)" value="${escapeHtml(data.label || '')}">` +
    `<input class="ds-input" type="email" data-field="email" maxlength="200" placeholder="Email (optional, for your reference only)" value="${escapeHtml(data.email || '')}">` +
    `<button class="ds-rm" type="button" data-action="remove">Remove</button>`;
  row.querySelector('[data-action="remove"]').addEventListener('click', () => removeRecipientRow(idx));
  return row;
}

function addRecipientRow() {
  commitRecipientsFromDom();
  state.recipients.push({ label: '', email: '' });
  renderRecipients();
  // Focus the new row's label input
  const rows = document.querySelectorAll('.ds-recipient-row');
  const last = rows[rows.length - 1];
  if (last) last.querySelector('[data-field="label"]').focus();
}

function removeRecipientRow(idx) {
  commitRecipientsFromDom();
  state.recipients.splice(idx, 1);
  renderRecipients();
}

function commitRecipientsFromDom() {
  // Read current input values back into state (the rows are uncontrolled).
  const rows = document.querySelectorAll('.ds-recipient-row');
  state.recipients = Array.from(rows).map(row => ({
    label: row.querySelector('[data-field="label"]').value.trim(),
    email: row.querySelector('[data-field="email"]').value.trim(),
  })).filter(r => r.label.length > 0);   // drop empty rows silently
}

function wireLiveStampUpdates() {
  // Whenever the signer's name changes (identity step), re-render any
  // placement marker in step-place so the name shown there reflects what
  // will end up in the stamp. Attached once at init.
  $('ds-signer-name').addEventListener('input', () => {
    if (state.mode !== 'pdf' || !state.stamp) return;
    document.querySelectorAll('.ds-stamp-marker').forEach(el => {
      el.innerHTML = stampMockupHtml();
    });
  });
}

function init() {
  initStepMode();
  initStepDoc();
  initStepIdentity();
  wireNav();
  wireLiveStampUpdates();
  setActive('step-mode');
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
