// DocuSign-style sign flow on /sign. Doc-first state machine.
//
// Steps: pick document -> (PDF: place stamp) -> identity -> review & sign -> done.
// Non-PDF inputs go through a hash-only path that skips the placement step.
//
// Reuses /vendor/parasign-bridge.js (ml_dsa65 + sha3_256 + vault helpers),
// /vendor/pdfjs (preview render) and /vendor/pdf-lib (stamp baking). All
// same-origin; CSP script-src 'self' remains intact.

import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';
import { vaultAvailable, vaultList, vaultUnlock } from '/vendor/vault.js';

const RELAY = 'https://health.paramant.app';

// ====================================================================
// State
// ====================================================================

const STAMP_PDF_W = 240;
const STAMP_PDF_H = 100;
const MAX_PREVIEW_PAGES = 30;

const state = {
  mode: null,            // 'pdf' | 'hash'
  doc:  null,            // { bytes (Uint8Array), name, size }
  stamp: null,           // { pageIndex, x, y, w, h } in PDF points
  signer: {
    name: '',
    keySrc: 'ephemeral',
    key: null,           // { secretKey, publicKey }
    apiKey: '',
    sigStyle: 'typed',     // 'typed' | 'drawn' | 'image'
    sigImageBytes: null,   // Uint8Array (PNG for drawn, PNG/JPG for image)
    sigImageType: null,    // 'png' | 'jpg'
    sigImageDataUrl: null, // pre-computed data: URL for <img src=>
    docImageDataUrl: null, // pre-computed data: URL when doc is a viewable image
  },
  result: null,          // { stampedBytes?, envelope, fingerprint, notary? }
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
    const order = ['doc', 'place', 'identity', 'sign'];
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
  const isPdf = bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
  state.mode = isPdf ? 'pdf' : 'hash';
  // Pre-compute a data: URL when the document is itself a viewable image,
  // so the review pane can render <img src=> without violating img-src CSP.
  const mimeGuess = guessMimeFromMagic(bytes);
  if (mimeGuess && mimeGuess.startsWith('image/')) {
    try { state.signer.docImageDataUrl = await bytesToDataUrl(bytes, mimeGuess); } catch {}
  }
  if (isPdf) {
    setActive('step-place');
    await renderPdfForPlacement();
  } else {
    setActive('step-hash-only');
    $('ds-hash-only-name').textContent = file.name;
    $('ds-hash-only-size').textContent = formatSize(file.size);
    $('ds-hash-only-hash').textContent = toHex(sha3_256(bytes));
    $('ds-hash-only-continue').disabled = false;
  }
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
  const ratio = wrap._pdfPage.width / rect.width;
  const pxX = e.clientX - rect.left;
  const pxY = e.clientY - rect.top;
  const stampPxW = STAMP_PDF_W / ratio;
  const stampPxH = STAMP_PDF_H / ratio;
  const left = Math.max(0, Math.min(rect.width  - stampPxW, pxX - stampPxW / 2));
  const top  = Math.max(0, Math.min(rect.height - stampPxH, pxY - stampPxH / 2));
  const pdfX = left * ratio;
  const pdfYTop = top * ratio;
  const pdfYBottom = wrap._pdfPage.height - pdfYTop - STAMP_PDF_H;
  state.stamp = { pageIndex: wrap._pdfPage.index, x: pdfX, y: pdfYBottom, w: STAMP_PDF_W, h: STAMP_PDF_H };
  document.querySelectorAll('.ds-stamp-marker').forEach(el => el.remove());
  renderStampMarker(wrap, left, top, stampPxW, stampPxH);
  $('ds-place-continue').disabled = false;
  $('ds-place-hint').textContent = 'Stamp on page ' + (wrap._pdfPage.index + 1) + '. Click another spot to move it.';
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

  // Populate vault keys if available.
  try {
    if (await vaultAvailable()) {
      const items = await vaultList();
      const sel = $('ds-key-src');
      for (const it of items) {
        const opt = document.createElement('option');
        opt.value = 'vault:' + it.id;
        opt.textContent = 'Vault: ' + (it.label || (it.pk_hash || '').slice(0, 12));
        sel.appendChild(opt);
      }
    }
  } catch {}
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

  cv.addEventListener('pointerdown', start);
  cv.addEventListener('pointermove', move);
  cv.addEventListener('pointerup', end);
  cv.addEventListener('pointerleave', end);
  cv.addEventListener('touchstart', start, { passive: false });
  cv.addEventListener('touchmove',  move,  { passive: false });
  cv.addEventListener('touchend',   end);

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

async function resolveSignerKey() {
  const src = $('ds-key-src').value;
  state.signer.keySrc = src;
  if (src === 'ephemeral') {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const kp = ml_dsa65.keygen(seed);
    return { secretKey: kp.secretKey, publicKey: kp.publicKey, kind: 'ephemeral' };
  }
  if (src === 'file') {
    return await pickKeyFile();
  }
  if (src.startsWith('vault:')) {
    const id = parseInt(src.slice('vault:'.length), 10);
    const pass = prompt('Passphrase to unlock the vault key:');
    if (!pass) throw new Error('Vault unlock cancelled');
    const u = await vaultUnlock(id, pass);
    return { secretKey: u.secretKey, publicKey: u.publicKey, kind: 'vault' };
  }
  throw new Error('Unknown key source');
}

function pickKeyFile() {
  return new Promise((resolve, reject) => {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.json,application/json';
    inp.onchange = async () => {
      try {
        const f = inp.files[0];
        if (!f) return reject(new Error('No file picked'));
        const d = JSON.parse(await f.text());
        if (!d.secretKey || !d.publicKey) return reject(new Error('Invalid key file (missing secretKey/publicKey)'));
        const secretKey = hexToBytes(d.secretKey);
        const publicKey = hexToBytes(d.publicKey);
        resolve({ secretKey, publicKey, kind: 'file' });
      } catch (e) { reject(e); }
    };
    inp.click();
  });
}

function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ====================================================================
// Step 4: review + sign
// ====================================================================

function fillReview() {
  // Sync keySrc from the dropdown into state (was only set inside resolveSignerKey,
  // which only runs after Sign is clicked - too late for the review card).
  state.signer.keySrc = $('ds-key-src').value;

  $('ds-review-doc').textContent  = state.doc.name + ' (' + formatSize(state.doc.size) + ')';
  $('ds-review-mode').textContent = state.mode === 'pdf' ? 'PDF with visual stamp on page ' + (state.stamp.pageIndex + 1) : 'Hash-only (SHA3-256 attestation)';
  $('ds-review-name').textContent = state.signer.name;
  $('ds-review-sig').textContent =
    state.signer.sigStyle === 'typed'  ? 'Typed name in the stamp' :
    state.signer.sigStyle === 'drawn'  ? 'Drawn signature (' + formatSize(state.signer.sigImageBytes.length) + ' PNG)' :
                                         'Uploaded image (' + formatSize(state.signer.sigImageBytes.length) + ' ' + state.signer.sigImageType.toUpperCase() + ')';
  $('ds-review-key-src').textContent =
    state.signer.keySrc === 'ephemeral' ? 'One-time key generated in this browser' :
    state.signer.keySrc === 'file'      ? 'Key file from disk' :
                                          'Saved key from this browser';
  const apiKey = $('ds-api-key').value.trim();
  state.signer.apiKey = apiKey;
  $('ds-review-notary').textContent = apiKey
    ? 'Yes - relay will counter-sign + write to CT log'
    : 'No - envelope is self-contained (still verifiable)';

  // Cryptographic proof card: the mathematical evidence that backs the
  // visual seal. Document hash is computed live; fingerprint depends on
  // the key source.
  const docHashHex = toHex(sha3_256(state.doc.bytes));
  $('ds-proof-doc-hash').textContent = docHashHex;
  if (state.signer.key && state.signer.key.publicKey) {
    $('ds-proof-fp').textContent = toHex(sha3_256(state.signer.key.publicKey));
  } else if (state.signer.keySrc === 'ephemeral') {
    $('ds-proof-fp').textContent = '(generated when you click Sign - the key never existed before this moment)';
  } else {
    $('ds-proof-fp').textContent = '(resolved when you click Sign)';
  }
  $('ds-proof-notary').textContent = state.signer.apiKey ? 'Yes (will fail-stop if the relay rejects the key)' : 'No (envelope is self-contained)';
  $('ds-proof-version').textContent = state.mode === 'pdf' ? 'parasign-visual-1' : 'parasign-hash-1';

  // Envelope-structure preview (placeholders where post-sign data lives).
  const previewEnv = state.mode === 'pdf' ? {
    version: 'parasign-visual-1',
    algorithm: 'ML-DSA-65',
    hash_algorithm: 'SHA3-256',
    original_filename: state.doc.name,
    stamped_filename: 'signed-' + state.doc.name,
    original_hash: docHashHex,
    stamped_hash: '<computed when the PDF is stamped>',
    coords: { pageIndex: state.stamp.pageIndex, x: Math.round(state.stamp.x), y: Math.round(state.stamp.y), w: state.stamp.w, h: state.stamp.h, name: state.signer.name, date: '<set on sign>' },
    signature_style: state.signer.sigStyle,
    signature_image_hash: state.signer.sigImageBytes ? toHex(sha3_256(state.signer.sigImageBytes)) : null,
    signer_public_key: '<base64 of your ML-DSA-65 public key>',
    signer_pk_fingerprint: '<sha3_256(pubkey)[..16]>',
    signature: '<base64 of ML-DSA-65 signature over (origHash || stampedHash || coords)>',
    signed_at: '<set on sign>',
    disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
  } : {
    version: 'parasign-hash-1',
    algorithm: 'ML-DSA-65',
    hash_algorithm: 'SHA3-256',
    original_filename: state.doc.name,
    document_hash: docHashHex,
    signer_name: state.signer.name,
    signer_public_key: '<base64 of your ML-DSA-65 public key>',
    signer_pk_fingerprint: '<sha3_256(pubkey)[..16]>',
    signature: '<base64 of ML-DSA-65 signature over document_hash>',
    signed_at: '<set on sign>',
    disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
  };
  $('ds-proof-json').textContent = JSON.stringify(previewEnv, null, 2);

  // Render visual previews of doc + signature so the signer sees exactly
  // what they are about to commit to before clicking Sign now.
  renderReviewPreviews().catch(err => console.warn('review preview failed', err));
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

  // Non-PDF: try to show the file inline if it is a viewable image. We use
  // a pre-computed data: URL because CSP blocks blob: in img-src.
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
  const fp = (state.signer.key && state.signer.key.publicKey)
    ? toHex(sha3_256(state.signer.key.publicKey)).slice(0, 8)
    : 'pending';
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
  $('ds-sign-now').disabled = true;
  $('ds-sign-status').hidden = false;
  $('ds-sign-status').className = 'ds-banner';
  $('ds-sign-status').textContent = 'Resolving signing key...';

  try {
    state.signer.key = await resolveSignerKey();
    const fingerprint = toHex(sha3_256(state.signer.key.publicKey)).slice(0, 16);
    const dateStr = new Date().toISOString().slice(0, 19) + 'Z';

    let stampedBytes = null;
    let messageBytes;
    let envelope;

    if (state.mode === 'pdf') {
      $('ds-sign-status').textContent = 'Stamping PDF...';
      stampedBytes = await buildStampedPdf(state.doc.bytes, state.stamp, state.signer.name, dateStr, fingerprint);
      const origHash = sha3_256(state.doc.bytes);
      const stampedHash = sha3_256(stampedBytes);
      const coords = { pageIndex: state.stamp.pageIndex, x: state.stamp.x, y: state.stamp.y, w: state.stamp.w, h: state.stamp.h, name: state.signer.name, date: dateStr };
      const coordsBytes = new TextEncoder().encode(JSON.stringify(coords));
      messageBytes = new Uint8Array(origHash.length + stampedHash.length + coordsBytes.length);
      messageBytes.set(origHash, 0);
      messageBytes.set(stampedHash, origHash.length);
      messageBytes.set(coordsBytes, origHash.length + stampedHash.length);
      $('ds-sign-status').textContent = 'Signing in browser (ML-DSA-65)...';
      const signature = ml_dsa65.sign(state.signer.key.secretKey, messageBytes);
      envelope = {
        version: 'parasign-visual-1',
        algorithm: 'ML-DSA-65',
        hash_algorithm: 'SHA3-256',
        original_filename: state.doc.name,
        stamped_filename: 'signed-' + state.doc.name,
        original_hash: toHex(origHash),
        stamped_hash:  toHex(stampedHash),
        coords,
        signature_style: state.signer.sigStyle,
        signature_image_hash: state.signer.sigImageBytes ? toHex(sha3_256(state.signer.sigImageBytes)) : null,
        signer_public_key: toB64(state.signer.key.publicKey),
        signer_pk_fingerprint: fingerprint,
        signature: toB64(signature),
        signed_at: dateStr,
        disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
      };
    } else {
      // Hash-only path: sign the SHA3-256 of the original file.
      const docHash = sha3_256(state.doc.bytes);
      $('ds-sign-status').textContent = 'Signing in browser (ML-DSA-65)...';
      const signature = ml_dsa65.sign(state.signer.key.secretKey, docHash);
      envelope = {
        version: 'parasign-hash-1',
        algorithm: 'ML-DSA-65',
        hash_algorithm: 'SHA3-256',
        original_filename: state.doc.name,
        document_hash: toHex(docHash),
        signer_name: state.signer.name,
        signer_public_key: toB64(state.signer.key.publicKey),
        signer_pk_fingerprint: fingerprint,
        signature: toB64(signature),
        signed_at: dateStr,
        disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
      };
    }

    // Optional notary call (only when an API key was supplied). If the user
    // explicitly asked for counter-signing, treat a failure as a HARD STOP:
    // we will NOT hand back an envelope that says 'notary requested but
    // failed', because that mixes two outcomes and quietly produces an
    // unsigned-by-relay artefact the user thought was witnessed.
    // The user stays in step-sign so they can fix the API key or clear it.
    if (state.signer.apiKey) {
      $('ds-sign-status').textContent = 'Requesting notary signature from relay...';
      let r, body;
      try {
        const docHashForNotary = state.mode === 'pdf' ? toHex(sha3_256(stampedBytes)) : envelope.document_hash;
        const sigForNotary = state.mode === 'pdf'
          ? toB64(ml_dsa65.sign(state.signer.key.secretKey, sha3_256(stampedBytes)))
          : envelope.signature;
        r = await fetch(RELAY + '/v2/sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Api-Key': state.signer.apiKey },
          body: JSON.stringify({
            document_hash: docHashForNotary,
            signature: sigForNotary,
            signer_public_key: envelope.signer_public_key,
            signer_label: state.signer.name,
          }),
        });
        body = await r.json().catch(() => null);
      } catch (netErr) {
        throw new Error('Counter-sign aborted: the relay was unreachable (' + (netErr.message || netErr) + '). Either fix your network or remove the API key under Advanced and sign locally.');
      }
      if (!r.ok) {
        const reason =
          r.status === 401 ? 'the API key was not accepted by the relay (check it under Advanced, or clear the field to sign without a counter-signature)' :
          r.status === 403 ? 'the API key does not have notary permission on this relay' :
          r.status === 429 ? 'the relay rate-limited the notary endpoint - retry in a minute' :
          'the relay returned HTTP ' + r.status + (body && body.error ? ' (' + body.error + ')' : '');
        throw new Error('Counter-sign aborted: ' + reason + '. No envelope was produced - the document was not signed.');
      }
      envelope.notary = body.envelope && body.envelope.notary ? body.envelope.notary : body.envelope;
    }

    state.result = { stampedBytes, envelope, fingerprint };
    showDone();
  } catch (e) {
    $('ds-sign-status').className = 'ds-banner err';
    $('ds-sign-status').textContent = (e.message || String(e));
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

  // Success banner: signature was produced locally regardless of the optional
  // notary outcome. Soften the wording so a failed/skipped notary call does
  // not look like 'signing failed'.
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
  $('ds-done-mode').textContent = state.mode === 'pdf'
    ? 'PDF with visual stamp on page ' + (state.stamp.pageIndex + 1)
    : 'Hash-only attestation (SHA3-256)';

  // Notary line: only show when something happened, frame failure as
  // 'optional step skipped' rather than an error.
  if (r.envelope.notary) {
    $('ds-done-notary').textContent = 'Yes - relay co-signed and added a CT-log entry';
  } else if (r.envelope.notary_error) {
    const reason = /401/.test(r.envelope.notary_error) ? 'API key was not accepted by the relay'
                 : /403/.test(r.envelope.notary_error) ? 'API key has no notary permission'
                 : 'relay was unreachable';
    $('ds-done-notary').textContent = 'Skipped (' + reason + ') - the local signature is still fully valid';
  } else {
    $('ds-done-notary').textContent = 'Skipped (no API key provided) - the local signature is still fully valid';
  }

  const psignName = (state.mode === 'pdf' ? 'signed-' + state.doc.name : state.doc.name).replace(/\.[^.]+$/, '') + '.psign';
  $('ds-dl-psign').onclick = () => downloadBytes(new TextEncoder().encode(JSON.stringify(r.envelope, null, 2)), psignName, 'application/json');
  if (r.stampedBytes) {
    $('ds-dl-pdf').hidden = false;
    $('ds-dl-pdf').onclick = () => downloadBytes(r.stampedBytes, 'signed-' + state.doc.name, 'application/pdf');
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
      li1.innerHTML = `<span class="ds-usage-files-file">signed-${escapeHtml(state.doc.name)}</span><span class="ds-usage-files-note">the visible document with your Paramant seal</span>`;
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
    notaryLine.textContent = r.envelope.notary
      ? 'Paramant\'s relay counter-signed the envelope, and the signature is logged in the public CT log - recipients see independent witness of when this signing happened.'
      : 'No relay witness on this signature - that is fine for self-attestation but means there is no independent third-party timestamp.';
  }

  // Render the signed result so the user can see their stamp before downloading.
  renderSignedPreview().catch(() => {});
}

async function renderSignedPreview() {
  const container = $('ds-signed-preview');
  if (!container) return;
  container.innerHTML = '';
  const r = state.result;
  if (state.mode !== 'pdf' || !r.stampedBytes) {
    // Hash-only mode: there's no rendered document, show the hash for confirmation.
    container.innerHTML =
      '<div class="ds-info-card"><dl>' +
      '<dt>Signed bytes (SHA3-256)</dt><dd>' + escapeHtml(r.envelope.document_hash || '-') + '</dd>' +
      '<dt>Signature (b64, first 32)</dt><dd>' + escapeHtml((r.envelope.signature || '').slice(0, 32)) + '...</dd>' +
      '</dl></div>';
    return;
  }
  const pdfjs = await waitForPdfjs();
  const copy = new Uint8Array(r.stampedBytes);
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
  // Show only the page that holds the stamp (and the next page if it exists)
  // so the user does not have to scroll far on long documents.
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
  $('ds-place-continue').addEventListener('click', () => { setActive('step-identity'); fillReviewPreviews(); });
  $('ds-hash-only-continue').addEventListener('click', () => { setActive('step-identity'); fillReviewPreviews(); });
  $('ds-place-back').addEventListener('click', () => setActive('step-doc'));
  $('ds-hash-only-back').addEventListener('click', () => setActive('step-doc'));
  $('ds-identity-back').addEventListener('click', () => setActive(state.mode === 'pdf' ? 'step-place' : 'step-hash-only'));
  $('ds-identity-continue').addEventListener('click', () => {
    fillReview();
    setActive('step-sign');
  });
  $('ds-sign-back').addEventListener('click', () => setActive('step-identity'));
  $('ds-sign-now').addEventListener('click', doSign);
  $('ds-restart').addEventListener('click', () => location.reload());
}

function fillReviewPreviews() {
  // Optional bridge so the identity step can preview the name on a placed stamp.
  // Re-render the live stamp marker text whenever the name changes.
  $('ds-signer-name').addEventListener('input', () => {
    if (state.mode !== 'pdf' || !state.stamp) return;
    document.querySelectorAll('.ds-stamp-marker .ds-sm-name').forEach(el => {
      el.textContent = 'Signed by ' + (state.signer.name || 'Signer').slice(0, 40);
    });
  });
}

function init() {
  initStepDoc();
  initStepIdentity();
  wireNav();
  setActive('step-doc');
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
