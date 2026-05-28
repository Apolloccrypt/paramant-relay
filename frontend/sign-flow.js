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
  mode: null,            // 'pdf' | 'image' | 'hash'
  imageType: null,       // 'png' | 'jpg' (only when mode === 'image')
  doc:  null,            // { bytes (Uint8Array), name, size }
  stamps: [],            // [{pageIndex, x, y, w, h, isImage?}] - one per click, removable individually.
                         // PDF mode: bottom-left PDF points. Image mode: top-left image pixels.
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
    stampTheme: 'dark',    // 'dark' (cobalt header band, white text) | 'light' (white band, navy text)
  },
  recipients: [],        // [{label, email}]; if empty -> single-party local sign only
  envelope: null,        // populated when recipients.length > 0 after POST /v2/envelopes
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
  if (window.__pdfjsLoadError) throw new Error('PDF.js failed to load: ' + (window.__pdfjsLoadError.message || window.__pdfjsLoadError));
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('PDF.js did not load within 10s. Likely cause: cached vendor file is corrupted. Try hard-refresh (Cmd/Ctrl+Shift+R) to bypass cache.')), 10000);
    window.addEventListener('pdfjs:ready', () => { clearTimeout(t); resolve(window.__pdfjsLib); }, { once: true });
    window.addEventListener('pdfjs:error', (e) => {
      clearTimeout(t);
      const detail = (e && e.detail && (e.detail.message || e.detail.toString())) || 'unknown';
      reject(new Error('PDF.js failed to load: ' + detail));
    }, { once: true });
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
  state.imageType = null;

  const isPdf = bytes.length >= 4 && bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46;
  const mimeGuess = guessMimeFromMagic(bytes);
  const isPng = mimeGuess === 'image/png';
  const isJpg = mimeGuess === 'image/jpeg';
  const canPlaceVisually = isPdf || isPng || isJpg;

  state.mode = isPdf ? 'pdf' : (isPng || isJpg) ? 'image' : 'hash';
  if (isPng) state.imageType = 'png';
  else if (isJpg) state.imageType = 'jpg';

  if (mimeGuess && mimeGuess.startsWith('image/')) {
    try { state.signer.docImageDataUrl = await bytesToDataUrl(bytes, mimeGuess); } catch {}
  }

  if (canPlaceVisually) {
    setActive('step-place');
    const container = $('ds-pdf-canvas-list');
    container.innerHTML = '<p style="padding:18px;font-family:var(--mono);font-size:12px;color:var(--ink-dim);text-align:center">Loading ' + (isPdf ? 'PDF' : 'image') + '...</p>';
    try {
      if (isPdf) await renderPdfForPlacement();
      else       await renderImageForPlacement();
    } catch (err) {
      console.error('render failed:', err);
      container.innerHTML =
        '<div style="padding:18px;border:1px solid #d4a017;background:#fff4d6;color:#5a3f00;font-size:13px;line-height:1.6">' +
        '<strong>Could not render the document.</strong> ' + escapeHtml(err && err.message ? err.message : String(err)) +
        '<p style="margin-top:8px;font-size:11px;color:var(--ink-dim)">If this is a PDF: hard-refresh the page (Cmd+Shift+R / Ctrl+Shift+R) to clear any cached PDF.js version. ' +
        'If the file is encrypted or password-protected, decrypt it first.</p>' +
        '<div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap">' +
        '  <button class="btn btn-primary" id="ds-fallback-hash" type="button" style="min-width:auto">Sign as hash-only (no visual stamp)</button>' +
        '  <button class="btn btn-tertiary" id="ds-fallback-back" type="button" style="min-width:auto">Pick a different file</button>' +
        '</div>' +
        '</div>';
      $('ds-place-continue').disabled = true;
      // Fallback: skip placement entirely and sign as hash-only attestation.
      document.getElementById('ds-fallback-hash').addEventListener('click', () => {
        state.mode = 'hash';
        state.stamps = [];
        setActive('step-hash-only');
        $('ds-hash-only-name').textContent = state.doc.name;
        $('ds-hash-only-size').textContent = formatSize(state.doc.size);
        $('ds-hash-only-hash').textContent = toHex(sha3_256(state.doc.bytes));
        $('ds-hash-only-continue').disabled = false;
      });
      document.getElementById('ds-fallback-back').addEventListener('click', () => setActive('step-doc'));
    }
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
  wrap._pdfPage = { width: img.naturalWidth, height: img.naturalHeight, index: 0, isImage: true };

  const canvas = document.createElement('canvas');
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  canvas.getContext('2d').drawImage(img, 0, 0);

  // EXPLICIT display dimensions so onPlaceClick's getBoundingClientRect()
  // matches the natural aspect ratio. Relying on CSS height:auto for canvas
  // with high-aspect intrinsic dims is unreliable across browsers - some
  // computed height:auto from the canvas height attribute instead of from
  // the aspect ratio, which broke clamping at the bottom of the image.
  const targetWidth = Math.min(820, Math.floor(window.innerWidth * 0.88));
  const scale = Math.min(1, targetWidth / img.naturalWidth);
  canvas.style.width  = (img.naturalWidth  * scale) + 'px';
  canvas.style.height = (img.naturalHeight * scale) + 'px';

  wrap.appendChild(canvas);
  container.appendChild(wrap);
  wrap.addEventListener('click', onPlaceClick);

  // If there are stamps from a previous visit, restore the markers.
  for (let i = 0; i < state.stamps.length; i++) {
    const s = state.stamps[i];
    if (s.isImage && s.pageIndex === 0) {
      await renderStampMarker(wrap, s.x * scale, s.y * scale, s.w * scale, s.h * scale, i);
    }
  }
  updatePlaceHint();

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
  // Restore existing stamps (in case user navigated away + back).
  if (state.stamps.length > 0) await rerenderAllMarkers();
  updatePlaceHint();
}

async function onPlaceClick(e) {
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

  let newStamp;
  if (isImage) {
    newStamp = { pageIndex: 0, x: natX, y: natYTop, w: stampNatW, h: stampNatH, isImage: true };
  } else {
    const pdfYBottom = wrap._pdfPage.height - natYTop - stampNatH;
    newStamp = { pageIndex: wrap._pdfPage.index, x: natX, y: pdfYBottom, w: stampNatW, h: stampNatH };
  }
  state.stamps.push(newStamp);
  const stampIdx = state.stamps.length - 1;
  await renderStampMarker(wrap, left, top, stampPxW, stampPxH, stampIdx);

  $('ds-place-continue').disabled = false;
  updatePlaceHint();
}

function updatePlaceHint() {
  const n = state.stamps.length;
  if (n === 0) {
    $('ds-place-hint').textContent = 'Click a page to drop the signature stamp.';
  } else if (n === 1) {
    $('ds-place-hint').textContent = '1 stamp placed. Click another spot to add another, or remove this one with the X.';
  } else {
    $('ds-place-hint').textContent = n + ' stamps placed. Click anywhere to add more, or remove individual stamps with the X.';
  }
  const clearBtn = $('ds-place-clear-all');
  if (clearBtn) clearBtn.hidden = (n < 2);
}

async function renderStampMarker(wrap, left, top, w, h, stampIdx) {
  const m = document.createElement('div');
  m.className = 'ds-stamp-marker';
  m.dataset.stampIdx = String(stampIdx);
  m.style.cssText = `left:${left}px;top:${top}px;width:${w}px;height:${h}px;background:transparent;border:0;padding:0;overflow:visible;pointer-events:none`;
  try {
    const canvas = await createStampPreviewCanvas(w, h);
    canvas.style.cssText = 'width:100%;height:100%;display:block';
    m.appendChild(canvas);
  } catch {
    m.style.cssText += ';border:2px solid var(--cobalt);background:rgba(11,58,106,.05)';
  }
  // X button to remove just this stamp (does not interfere with placement clicks
  // because the marker itself is pointer-events:none).
  const x = document.createElement('button');
  x.className = 'ds-stamp-x';
  x.type = 'button';
  x.title = 'Remove this stamp';
  x.textContent = 'x';
  x.dataset.stampIdx = String(stampIdx);
  x.addEventListener('click', (ev) => { ev.stopPropagation(); removeStamp(stampIdx); });
  m.appendChild(x);
  wrap.appendChild(m);
}

function removeStamp(idx) {
  state.stamps.splice(idx, 1);
  // Re-render all markers (indices shift after splice).
  document.querySelectorAll('.ds-stamp-marker').forEach(el => el.remove());
  rerenderAllMarkers().catch(() => {});
  updatePlaceHint();
  if (state.stamps.length === 0) $('ds-place-continue').disabled = true;
}

async function rerenderAllMarkers() {
  // Place all stamps back on their corresponding canvases in step-place.
  const wraps = document.querySelectorAll('.ds-page-wrap');
  for (let i = 0; i < state.stamps.length; i++) {
    const s = state.stamps[i];
    const wrap = Array.from(wraps).find(w => w._pdfPage && w._pdfPage.index === s.pageIndex);
    if (!wrap) continue;
    const canvas = wrap.querySelector('canvas');
    const rect = canvas.getBoundingClientRect();
    const ratio = wrap._pdfPage.width / rect.width;
    const stampPxW = s.w / ratio;
    const stampPxH = s.h / ratio;
    let left, top;
    if (s.isImage) {
      left = s.x / ratio;
      top  = s.y / ratio;
    } else {
      left = s.x / ratio;
      top  = (wrap._pdfPage.height - s.y - s.h) / ratio;
    }
    await renderStampMarker(wrap, left, top, stampPxW, stampPxH, i);
  }
}

// Renders the actual stamp graphic (via drawStampOnCanvas) at the requested
// display dimensions. This is the canvas equivalent of stampMockupHtml: it
// scales correctly at any size because it is the same code that bakes the
// stamp into the final PDF/image, and stays hi-dpi sharp via devicePixelRatio.
async function createStampPreviewCanvas(widthPx, heightPx) {
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, Math.round(widthPx * dpr));
  canvas.height = Math.max(1, Math.round(heightPx * dpr));
  canvas.style.width = widthPx + 'px';
  canvas.style.height = heightPx + 'px';
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  let sigImg = null;
  if (state.signer.sigStyle !== 'typed' && state.signer.sigImageDataUrl) {
    sigImg = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = () => rej(new Error('sig image load failed'));
      i.src = state.signer.sigImageDataUrl;
    });
  }

  const name = (state.signer.name || 'Signer').slice(0, 40);
  const dateStr = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const fp = (state.signer.key && state.signer.key.publicKey)
    ? toHex(sha3_256(state.signer.key.publicKey)).slice(0, 8)
    : 'pending';

  drawStampOnCanvas(ctx, { x: 0, y: 0, w: widthPx, h: heightPx }, name, dateStr, fp, sigImg);
  return canvas;
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

function signedImageName() {
  const ext = state.imageType === 'jpg' ? 'jpg' : 'png';
  const dotIdx = state.doc.name.lastIndexOf('.');
  if (dotIdx < 0) return 'signed-' + state.doc.name + '.' + ext;
  return 'signed-' + state.doc.name.slice(0, dotIdx) + '.' + ext;
}

function describePdfStamps() {
  if (state.stamps.length === 0) return 'PDF (no stamp placed yet)';
  const pages = [...new Set(state.stamps.map(s => s.pageIndex + 1))].sort((a, b) => a - b);
  const pagesStr = pages.length === 1 ? 'page ' + pages[0] : 'pages ' + pages.join(', ');
  return state.stamps.length + ' stamp' + (state.stamps.length === 1 ? '' : 's') + ' on ' + pagesStr;
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

// Matches the recipe the relay's Lua script reproduces server-side
// (see relay/envelope.js: signMessageBytes). Used to sign as party 0 when
// the user creates a multi-party envelope, and read by /co-sign for parties
// 1..N when they sign their own slot.
function buildEnvelopeSignMessage(envId, docHashHex, partyIndex) {
  const idBytes = new TextEncoder().encode(envId);
  const hashBytes = hexToBytes(docHashHex);
  const piBytes = new TextEncoder().encode(String(partyIndex));
  const combined = new Uint8Array(idBytes.length + hashBytes.length + piBytes.length);
  combined.set(idBytes, 0);
  combined.set(hashBytes, idBytes.length);
  combined.set(piBytes, idBytes.length + hashBytes.length);
  return sha3_256(combined);
}

// ====================================================================
// Step 4: review + sign
// ====================================================================

function fillReview() {
  // Sync keySrc from the dropdown into state (was only set inside resolveSignerKey,
  // which only runs after Sign is clicked - too late for the review card).
  state.signer.keySrc = $('ds-key-src').value;

  $('ds-review-doc').textContent  = state.doc.name + ' (' + formatSize(state.doc.size) + ')';
  $('ds-review-mode').textContent =
    state.mode === 'pdf'   ? describePdfStamps() :
    state.mode === 'image' ? state.stamps.length + ' stamp' + (state.stamps.length === 1 ? '' : 's') + ' baked into the image (' + (state.imageType || '').toUpperCase() + ')' :
                             'Hash-only (SHA3-256 attestation)';
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

  // Recipients summary; warn if recipients but no API key (envelope creation will fail).
  const recCell = $('ds-review-recipients');
  if (state.recipients.length === 0) {
    recCell.textContent = 'None - personal signature only';
  } else {
    const list = state.recipients.map(r => r.label + (r.email ? ' (' + r.email + ')' : '')).join(', ');
    recCell.innerHTML = state.recipients.length + ' co-signer' + (state.recipients.length === 1 ? '' : 's') + ': ' + escapeHtml(list);
    if (!apiKey) {
      recCell.innerHTML += '<br><span style="color:rgba(180,20,20,1);font-size:11px">Multi-party envelope needs your X-Api-Key in the Advanced section. Get one at <a href="/dashboard#api-keys" target="_blank" style="color:rgba(180,20,20,1);text-decoration:underline">Dashboard &gt; API Keys</a>.</span>';
    } else if (!/^pgp_/.test(apiKey)) {
      recCell.innerHTML += '<br><span style="color:rgba(180,20,20,1);font-size:11px">The API key in Advanced does not start with <code>pgp_</code>. Paramant keys look like <code>pgp_...</code> - check at <a href="/dashboard#api-keys" target="_blank" style="color:rgba(180,20,20,1);text-decoration:underline">Dashboard &gt; API Keys</a>.</span>';
    }
  }

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
  $('ds-proof-version').textContent =
    state.mode === 'pdf'   ? 'parasign-visual-1' :
    state.mode === 'image' ? 'parasign-image-1'  :
                             'parasign-hash-1';

  // Envelope-structure preview (placeholders where post-sign data lives).
  const previewEnv = state.mode === 'pdf' ? {
    version: 'parasign-visual-1',
    algorithm: 'ML-DSA-65',
    hash_algorithm: 'SHA3-256',
    original_filename: state.doc.name,
    stamped_filename: 'signed-' + state.doc.name,
    original_hash: docHashHex,
    stamped_hash: '<computed when the PDF is stamped>',
    stamps: state.stamps.map(s => ({ pageIndex: s.pageIndex, x: Math.round(s.x), y: Math.round(s.y), w: s.w, h: s.h, isImage: !!s.isImage, name: state.signer.name, date: '<set on sign>' })),
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

// Always-readable preview of the stamp graphic, sized for inspection.
// Independent of how the document is scaled in the preview pane.
async function appendStampDetail(pane) {
  const detail = document.createElement('div');
  detail.style.cssText = 'padding:14px;background:var(--bone-2);border-top:1px solid var(--ink-hair)';
  const label = document.createElement('p');
  label.style.cssText = 'font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-dim);margin:0 0 8px';
  label.textContent = 'How the seal will look (at preview size)';
  detail.appendChild(label);

  const detailW = Math.min(300, Math.max(220, (pane.clientWidth || 280) - 40));
  const detailH = Math.round(detailW * (STAMP_PDF_H / STAMP_PDF_W));
  try {
    const stampCanvas = await createStampPreviewCanvas(detailW, detailH);
    stampCanvas.style.cssText = 'width:' + detailW + 'px;height:' + detailH + 'px;display:block;border:1px solid var(--ink-hair);background:#fff';
    detail.appendChild(stampCanvas);
  } catch {
    const fallback = document.createElement('div');
    fallback.style.cssText = 'padding:20px;border:1px dashed var(--ink-hair);color:var(--ink-dim);font-size:11px';
    fallback.textContent = 'Could not render seal preview (missing signature image?).';
    detail.appendChild(fallback);
  }
  pane.appendChild(detail);
}

async function renderDocPreview() {
  const pane = $('ds-review-doc-preview');
  if (!pane) return;
  pane.innerHTML = '';
  pane.classList.remove('has-pdf');

  if (state.mode === 'pdf' && state.stamps.length > 0) {
    pane.classList.add('has-pdf');
    const pdfjs = await waitForPdfjs();
    const copy = new Uint8Array(state.doc.bytes);
    const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
    // Render every page that has at least one stamp, with all stamps for
    // that page overlaid as canvas mockups.
    const pagesNeeded = [...new Set(state.stamps.map(s => s.pageIndex))].sort((a, b) => a - b);
    const targetW = Math.min(640, Math.floor((pane.clientWidth || 640) - 24));
    for (const pageIdx of pagesNeeded) {
      const page = await pdf.getPage(pageIdx + 1);
      const baseViewport = page.getViewport({ scale: 1 });
      const scale = targetW / baseViewport.width;
      const viewport = page.getViewport({ scale });
      const wrap = document.createElement('div');
      wrap.style.cssText = 'position:relative;display:block;margin:0 auto 14px';
      const label = document.createElement('div');
      label.style.cssText = 'font-family:var(--mono);font-size:10px;color:var(--ink-dim);padding:4px 0';
      label.textContent = 'Page ' + (pageIdx + 1);
      wrap.appendChild(label);
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      wrap.appendChild(canvas);
      pane.appendChild(wrap);
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      const ratio = baseViewport.width / canvas.getBoundingClientRect().width;
      for (const stamp of state.stamps.filter(s => s.pageIndex === pageIdx)) {
        const left = stamp.x / ratio;
        const top  = (baseViewport.height - stamp.y - stamp.h) / ratio + 18;  // +18 for label
        const w = stamp.w / ratio;
        const h = stamp.h / ratio;
        try {
          const stampCanvas = await createStampPreviewCanvas(w, h);
          stampCanvas.style.cssText = `position:absolute;left:${left}px;top:${top}px;pointer-events:none`;
          wrap.appendChild(stampCanvas);
        } catch {}
      }
    }
    await appendStampDetail(pane);
    return;
  }

  // Image-mode: scrollable natural-size view (so the user can pan and see
  // the seal at full quality) + position outline on the image + zoom
  // controls + a separate seal-detail canvas below at fixed readable size.
  if (state.mode === 'image' && state.signer.docImageDataUrl && state.stamps.length > 0) {
    pane.classList.add('has-pdf');
    pane.style.display = 'block';
    pane.style.padding = '0';

    // Zoom toolbar
    const toolbar = document.createElement('div');
    toolbar.style.cssText = 'display:flex;gap:8px;align-items:center;padding:8px 12px;background:var(--bone-2);border-bottom:1px solid var(--ink-hair);font-family:var(--mono);font-size:10px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-dim)';
    toolbar.innerHTML =
      '<span style="margin-right:6px">Zoom</span>' +
      '<button class="ds-zoom-btn active" data-zoom="fit" type="button" style="padding:4px 10px;border:1px solid var(--ink-hair);background:transparent;font:inherit;color:inherit;cursor:pointer">Fit</button>' +
      '<button class="ds-zoom-btn" data-zoom="0.5" type="button" style="padding:4px 10px;border:1px solid var(--ink-hair);background:transparent;font:inherit;color:inherit;cursor:pointer">50%</button>' +
      '<button class="ds-zoom-btn" data-zoom="1" type="button" style="padding:4px 10px;border:1px solid var(--ink-hair);background:transparent;font:inherit;color:inherit;cursor:pointer">100%</button>' +
      '<button class="ds-zoom-btn" data-zoom="2" type="button" style="padding:4px 10px;border:1px solid var(--ink-hair);background:transparent;font:inherit;color:inherit;cursor:pointer">200%</button>' +
      '<span style="margin-left:auto;font-size:9px;text-transform:none;letter-spacing:0;color:var(--ink-dim)">Scroll + drag to pan</span>';
    pane.appendChild(toolbar);

    // Scrollable viewport
    const viewport = document.createElement('div');
    viewport.style.cssText = 'position:relative;width:100%;max-height:640px;overflow:auto;cursor:grab;background:repeating-linear-gradient(45deg,#f8fafc,#f8fafc 8px,#eaeef3 8px,#eaeef3 16px)';
    pane.appendChild(viewport);

    const wrap = document.createElement('div');
    wrap.style.cssText = 'position:relative;display:inline-block;line-height:0';
    viewport.appendChild(wrap);

    const img = document.createElement('img');
    img.src = state.signer.docImageDataUrl;
    img.alt = state.doc.name;
    img.style.cssText = 'display:block';
    wrap.appendChild(img);

    function applyZoom(mode) {
      if (mode === 'fit') {
        // Fit to viewport width (minus a tiny margin for the scrollbar)
        const viewW = viewport.clientWidth - 4;
        const scale = Math.min(1, viewW / img.naturalWidth);
        img.style.width = (img.naturalWidth * scale) + 'px';
        img.style.height = (img.naturalHeight * scale) + 'px';
      } else {
        const s = parseFloat(mode);
        img.style.width = (img.naturalWidth * s) + 'px';
        img.style.height = (img.naturalHeight * s) + 'px';
      }
      // Reposition every outline to match the new display scale
      const displayW = parseFloat(img.style.width);
      const ratio = img.naturalWidth / displayW;
      wrap.querySelectorAll('[data-role="stamp-outline"]').forEach((outline) => {
        const idx = parseInt(outline.dataset.stampIdx, 10);
        const s = state.stamps[idx];
        if (!s) return;
        outline.style.left   = (s.x / ratio) + 'px';
        outline.style.top    = (s.y / ratio) + 'px';
        outline.style.width  = (s.w / ratio) + 'px';
        outline.style.height = (s.h / ratio) + 'px';
      });
    }

    img.onload = () => {
      applyZoom('fit');
      // One outline per stamp.
      state.stamps.forEach((s, i) => {
        const outline = document.createElement('div');
        outline.dataset.role = 'stamp-outline';
        outline.dataset.stampIdx = String(i);
        outline.style.cssText = 'position:absolute;border:2px solid var(--cobalt);background:rgba(11,58,106,.18);pointer-events:none;box-shadow:0 0 0 1px rgba(255,255,255,.6) inset';
        wrap.appendChild(outline);
      });
      applyZoom('fit');
    };

    toolbar.querySelectorAll('.ds-zoom-btn').forEach(b => {
      b.addEventListener('click', () => {
        toolbar.querySelectorAll('.ds-zoom-btn').forEach(o => o.classList.remove('active'));
        b.classList.add('active');
        applyZoom(b.dataset.zoom);
      });
    });

    // Click-and-drag panning
    let dragging = false, dragStartX = 0, dragStartY = 0, scrollStartX = 0, scrollStartY = 0;
    viewport.addEventListener('pointerdown', (e) => {
      dragging = true;
      dragStartX = e.clientX; dragStartY = e.clientY;
      scrollStartX = viewport.scrollLeft; scrollStartY = viewport.scrollTop;
      viewport.style.cursor = 'grabbing';
      viewport.setPointerCapture(e.pointerId);
    });
    viewport.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      viewport.scrollLeft = scrollStartX - (e.clientX - dragStartX);
      viewport.scrollTop  = scrollStartY - (e.clientY - dragStartY);
    });
    viewport.addEventListener('pointerup', (e) => {
      dragging = false;
      viewport.style.cursor = 'grab';
      try { viewport.releasePointerCapture(e.pointerId); } catch {}
    });

    const cap = document.createElement('p');
    cap.style.cssText = 'font-family:var(--mono);font-size:10px;color:var(--ink-dim);padding:8px 12px;margin:0;border-top:1px solid var(--ink-hair);background:var(--bone)';
    if (state.stamps.length === 1) {
      const s = state.stamps[0];
      cap.innerHTML =
        '<strong>1 stamp</strong> at <strong>' + Math.round(s.x) + ', ' + Math.round(s.y) +
        '</strong> px - seal <strong>' + Math.round(s.w) + ' x ' + Math.round(s.h) +
        '</strong> px on the original image';
    } else {
      cap.innerHTML = '<strong>' + state.stamps.length + ' stamps</strong> placed on the image';
    }
    pane.appendChild(cap);

    // Stamp at a readable preview size so the user can inspect the content.
    await appendStampDetail(pane);
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
    el.textContent = state.signer.name || '(enter your name in step 4)';
    if (!state.signer.name) el.style.color = 'var(--ink-dim)';
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

  // Empty-state for picked-style-without-data
  const hint = document.createElement('div');
  hint.className = 'ds-pane-meta';
  hint.style.color = 'var(--ink-dim)';
  hint.textContent = state.signer.sigStyle === 'drawn'
    ? 'No signature drawn yet. Go back to Identity (step 4), pick Draw signature, and use the canvas.'
    : state.signer.sigStyle === 'image'
      ? 'No signature image uploaded yet. Go back to Identity (step 4), pick Upload image, and choose a PNG or JPG.'
      : 'No signature data.';
  pane.appendChild(hint);
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

async function buildStampedImage(origBytes, stamps, signerName, dateStr, fingerprint8, imageType) {
  const mime = imageType === 'jpg' ? 'image/jpeg' : 'image/png';
  const img = await loadImageElement(origBytes, mime);
  const canvas = document.createElement('canvas');
  canvas.width = img.naturalWidth;
  canvas.height = img.naturalHeight;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(img, 0, 0);

  let sigImg = null;
  if (state.signer.sigStyle !== 'typed' && state.signer.sigImageDataUrl) {
    sigImg = await new Promise((resolve, reject) => {
      const i = new Image();
      i.onload = () => resolve(i);
      i.onerror = () => reject(new Error('signature image decode failed'));
      i.src = state.signer.sigImageDataUrl;
    });
  }

  const stampsArr = Array.isArray(stamps) ? stamps : [stamps];
  for (const stamp of stampsArr) {
    drawStampOnCanvas(ctx, stamp, signerName, dateStr, fingerprint8, sigImg);
  }

  return await new Promise((resolve, reject) => {
    canvas.toBlob(async (blob) => {
      if (!blob) return reject(new Error('canvas toBlob failed'));
      resolve(new Uint8Array(await blob.arrayBuffer()));
    }, mime, imageType === 'jpg' ? 0.92 : undefined);
  });
}

function drawStampOnCanvas(ctx, stamp, signerName, dateStr, fingerprint8, sigImg) {
  const { x, y, w, h } = stamp;
  const theme = state.signer.stampTheme || 'dark';
  const bandFill = theme === 'light' ? '#ffffff' : '#0b3a6a';
  const bandText = theme === 'light' ? '#0b3a6a' : '#ffffff';
  const bodyBg   = theme === 'light' ? 'rgba(255,255,255,0.92)' : 'rgba(11,58,106,0.03)';

  // Outer fill + border
  ctx.fillStyle = bodyBg;
  ctx.fillRect(x, y, w, h);
  ctx.strokeStyle = '#0b3a6a';
  ctx.lineWidth = Math.max(1, w / 200);
  ctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);

  // Header band: cobalt+white for dark theme, white+navy for light theme
  const bandH = h * 0.18;
  ctx.fillStyle = bandFill;
  ctx.fillRect(x, y, w, bandH);
  if (theme === 'light') {
    ctx.strokeStyle = '#0b3a6a';
    ctx.lineWidth = Math.max(0.5, w / 400);
    ctx.beginPath();
    ctx.moveTo(x, y + bandH);
    ctx.lineTo(x + w, y + bandH);
    ctx.stroke();
  }
  ctx.fillStyle = bandText;
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

async function buildStampedPdf(origBytes, stamps, signerName, dateStr, fingerprint8) {
  const PDFLib = await waitForPdfLib();
  const pdfDoc = await PDFLib.PDFDocument.load(origBytes);
  const font     = await pdfDoc.embedFont(PDFLib.StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(PDFLib.StandardFonts.HelveticaBold);
  const fontItal = await pdfDoc.embedFont(PDFLib.StandardFonts.TimesRomanItalic);
  const stampsArr = Array.isArray(stamps) ? stamps : [stamps];
  for (const stamp of stampsArr) {
    await drawOneStampOnPdf(pdfDoc, stamp, signerName, dateStr, fingerprint8, font, fontBold, fontItal, PDFLib);
  }
  return await pdfDoc.save();
}

async function drawOneStampOnPdf(pdfDoc, stamp, signerName, dateStr, fingerprint8, font, fontBold, fontItal, PDFLib) {
  const page = pdfDoc.getPages()[stamp.pageIndex];
  const navy  = PDFLib.rgb(0.043, 0.227, 0.416);
  const dim   = PDFLib.rgb(0.30, 0.30, 0.30);
  const white = PDFLib.rgb(1, 1, 1);
  const theme = state.signer.stampTheme || 'dark';
  const bandFill = theme === 'light' ? white : navy;
  const bandText = theme === 'light' ? navy  : white;

  // Outer border + faint fill (slightly more visible in light theme so the
  // stamp doesn't disappear against bright doc backgrounds).
  page.drawRectangle({
    x: stamp.x, y: stamp.y, width: stamp.w, height: stamp.h,
    borderColor: navy, borderWidth: 1.2,
    color: theme === 'light' ? white : navy,
    opacity: theme === 'light' ? 0.92 : 0.03,
  });

  // Branded top band: cobalt bar (dark) or white bar (light) with navy text
  const bandH = 16;
  page.drawRectangle({ x: stamp.x, y: stamp.y + stamp.h - bandH, width: stamp.w, height: bandH, color: bandFill });
  if (theme === 'light') {
    page.drawLine({
      start: { x: stamp.x, y: stamp.y + stamp.h - bandH },
      end:   { x: stamp.x + stamp.w, y: stamp.y + stamp.h - bandH },
      thickness: 0.6, color: navy,
    });
  }
  page.drawText('ParaMANT', { x: stamp.x + 8, y: stamp.y + stamp.h - 11, size: 9, font: fontBold, color: bandText });
  const badge = 'POST-QUANTUM SIGNED';
  const badgeW = fontBold.widthOfTextAtSize(badge, 6);
  page.drawText(badge, { x: stamp.x + stamp.w - badgeW - 8, y: stamp.y + stamp.h - 10.5, size: 6, font: fontBold, color: bandText });

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

    if (state.mode === 'pdf' || state.mode === 'image') {
      if (state.stamps.length === 0) {
        throw new Error('Place at least one signature stamp on the document before signing.');
      }
      $('ds-sign-status').textContent = state.mode === 'pdf' ? 'Stamping PDF...' : 'Stamping image...';
      stampedBytes = state.mode === 'pdf'
        ? await buildStampedPdf(state.doc.bytes, state.stamps, state.signer.name, dateStr, fingerprint)
        : await buildStampedImage(state.doc.bytes, state.stamps, state.signer.name, dateStr, fingerprint, state.imageType);
      const origHash = sha3_256(state.doc.bytes);
      const stampedHash = sha3_256(stampedBytes);
      // Sign-message commits to the FULL stamps array so adding/removing a
      // stamp invalidates the signature. Verify reconstructs the same bytes.
      const stampsForEnvelope = state.stamps.map(s => ({
        pageIndex: s.pageIndex,
        x: s.x, y: s.y, w: s.w, h: s.h,
        isImage: !!s.isImage,
        name: state.signer.name,
        date: dateStr,
      }));
      const stampsBytes = new TextEncoder().encode(JSON.stringify(stampsForEnvelope));
      messageBytes = new Uint8Array(origHash.length + stampedHash.length + stampsBytes.length);
      messageBytes.set(origHash, 0);
      messageBytes.set(stampedHash, origHash.length);
      messageBytes.set(stampsBytes, origHash.length + stampedHash.length);
      $('ds-sign-status').textContent = 'Signing in browser (ML-DSA-65)...';
      const signature = ml_dsa65.sign(state.signer.key.secretKey, messageBytes);
      const stampedName = state.mode === 'image' ? signedImageName() : 'signed-' + state.doc.name;
      envelope = {
        version: state.mode === 'pdf' ? 'parasign-visual-1' : 'parasign-image-1',
        algorithm: 'ML-DSA-65',
        hash_algorithm: 'SHA3-256',
        original_filename: state.doc.name,
        stamped_filename: stampedName,
        original_hash: toHex(origHash),
        stamped_hash:  toHex(stampedHash),
        stamps: stampsForEnvelope,
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

    // Multi-party envelope: if the user added recipients, create the envelope
    // on the relay with the (possibly stamped) document hash, then auto-sign
    // as party 0. The recipients then sign via /co-sign?env=...&p=<i>.
    // Requires an API key (the /v2/envelopes endpoint is auth-gated).
    if (state.recipients.length > 0) {
      if (!state.signer.apiKey) {
        throw new Error('Adding recipients requires your Paramant X-Api-Key. Open the Advanced section in step 4 and paste it there. You can find or create one at Dashboard > API Keys (https://paramant.app/dashboard#api-keys). Alternatively, remove the recipients to sign only for yourself.');
      }
      if (!/^pgp_[A-Za-z0-9_-]{16,}$/.test(state.signer.apiKey)) {
        throw new Error('The X-Api-Key you entered does not look like a Paramant API key (expected format: pgp_... with at least 16 chars after). Double-check the value at Dashboard > API Keys (https://paramant.app/dashboard#api-keys).');
      }
      $('ds-sign-status').textContent = 'Creating multi-party envelope on the relay...';
      const docHashForEnvelope = state.mode === 'pdf' || state.mode === 'image' ? envelope.stamped_hash : envelope.document_hash;
      const allParties = [{ label: state.signer.name + ' (sender)' }, ...state.recipients];
      let createR, createBody;
      try {
        createR = await fetch(RELAY + '/v2/envelopes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Api-Key': state.signer.apiKey },
          body: JSON.stringify({
            doc_hash: docHashForEnvelope,
            parties: allParties,
            original_filename: state.mode === 'pdf' ? 'signed-' + state.doc.name : state.doc.name,
            creator_public_key: envelope.signer_public_key,
          }),
        });
        createBody = await createR.json().catch(() => null);
      } catch (netErr) {
        throw new Error('Envelope creation aborted: the relay was unreachable (' + (netErr.message || netErr) + ').');
      }
      if (!createR.ok) {
        const reason = createR.status === 401
          ? 'the API key was not accepted by the relay. Verify the value at Dashboard > API Keys (https://paramant.app/dashboard#api-keys), or remove recipients to sign only for yourself'
          : createR.status === 429 ? 'the relay rate-limited envelope creation - try again in an hour'
          : 'the relay returned HTTP ' + createR.status + (createBody && createBody.error ? ' (' + createBody.error + ')' : '');
        throw new Error('Envelope creation aborted: ' + reason + '. No envelope was produced; recipients have not been notified.');
      }
      state.envelope = createBody.envelope;

      // Auto-sign as party 0 with the same ML-DSA-65 key
      $('ds-sign-status').textContent = 'Auto-signing as party 0 (sender)...';
      const envMsg = buildEnvelopeSignMessage(state.envelope.id, docHashForEnvelope, 0);
      const envSig = ml_dsa65.sign(state.signer.key.secretKey, envMsg);
      let signR, signBody;
      try {
        signR = await fetch(RELAY + '/v2/envelopes/' + state.envelope.id + '/sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            party_index: 0,
            signer_public_key: envelope.signer_public_key,
            signature: toB64(envSig),
          }),
        });
        signBody = await signR.json().catch(() => null);
      } catch (netErr) {
        throw new Error('Envelope ' + state.envelope.id + ' was created but auto-signing as party 0 failed (' + (netErr.message || netErr) + '). Recipients cannot proceed until this is resolved.');
      }
      if (!signR.ok) {
        throw new Error('Envelope ' + state.envelope.id + ' was created but auto-signing as party 0 returned HTTP ' + signR.status + (signBody && signBody.error ? ' (' + signBody.error + ')' : '') + '. Recipients cannot proceed.');
      }

      // Bake multi-party info into the .psign envelope so recipients of the
      // file can also see which envelope it belongs to.
      envelope.multiparty = {
        envelope_id: state.envelope.id,
        party_count: state.envelope.party_count,
        party_links: state.envelope.party_links,
        expires_at: state.envelope.expires_at,
        sender_signed_at: signBody.signed_count >= 1,
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
          r.status === 401 ? 'your API key is not in the relay allowlist. The website session (email + OTP) and the relay user database are managed separately - your account may need to be enrolled on this relay. Either contact the relay operator, or clear the API key in Advanced to sign locally without a relay counter-signature'
          : r.status === 403 ? 'the API key does not have notary permission on this relay'
          : r.status === 429 ? 'the relay rate-limited the notary endpoint - retry in a minute'
          : 'the relay returned HTTP ' + r.status + (body && body.error ? ' (' + body.error + ')' : '');
        throw new Error('Counter-sign aborted: ' + reason + '. No envelope was produced - the document was not signed.');
      }
      envelope.notary = body.envelope && body.envelope.notary ? body.envelope.notary : body.envelope;
    }

    state.result = { stampedBytes, envelope, fingerprint };
    showDone();
  } catch (e) {
    const msg = e.message || String(e);
    $('ds-sign-status').className = 'ds-banner err';
    // If this is an API-key issue, render a click-through link to the dashboard
    // and a button to re-open the Advanced section, so the user does not have
    // to read the URL out of the error and paste it manually.
    if (/API key|api.key/i.test(msg)) {
      $('ds-sign-status').innerHTML =
        escapeHtml(msg).replace(/\(https?:[^)]+\)/g, m => {
          const url = m.slice(1, -1);
          return '(<a href="' + escapeHtml(url) + '" target="_blank" rel="noopener" style="color:rgba(180,20,20,1);text-decoration:underline">' + escapeHtml(url) + '</a>)';
        }) +
        '<div class="ds-actions" style="margin-top:10px">' +
          '<a class="btn btn-primary" style="min-width:auto" href="/dashboard#api-keys" target="_blank" rel="noopener">Open Dashboard - API Keys</a>' +
          '<button class="btn btn-tertiary" type="button" style="min-width:auto" id="ds-go-edit-key">Edit key in Advanced</button>' +
        '</div>';
      const goBtn = document.getElementById('ds-go-edit-key');
      if (goBtn) goBtn.addEventListener('click', () => {
        setActive('step-identity');
        const adv = document.getElementById('ds-advanced-block');
        if (adv) adv.open = true;
        setTimeout(() => { const k = $('ds-api-key'); if (k) k.focus(); }, 100);
      });
    } else {
      $('ds-sign-status').textContent = msg;
    }
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
  $('ds-done-mode').textContent =
    state.mode === 'pdf'   ? describePdfStamps() :
    state.mode === 'image' ? state.stamps.length + ' stamp' + (state.stamps.length === 1 ? '' : 's') + ' baked into the image (' + (state.imageType || '').toUpperCase() + ')' :
                             'Hash-only attestation (SHA3-256)';

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
    notaryLine.textContent = r.envelope.notary
      ? 'Paramant\'s relay counter-signed the envelope, and the signature is logged in the public CT log - recipients see independent witness of when this signing happened.'
      : 'No relay witness on this signature - that is fine for self-attestation but means there is no independent third-party timestamp.';
  }

  // Multi-party: render share-links for the recipients (party 1..N).
  // Sender (party 0) is auto-signed; their link is not displayed.
  if (r.envelope.multiparty && r.envelope.multiparty.party_links) {
    renderPartyLinks(r.envelope.multiparty);
  }

  // Render the signed result so the user can see their stamp before downloading.
  renderSignedPreview().catch(() => {});
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

  // Status-page link points at the relay's redacted envelope view.
  const statusLink = $('ds-envelope-status-link');
  if (statusLink) {
    statusLink.href = RELAY + '/v2/envelopes/' + mp.envelope_id;
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
  // Show every page that has a stamp.
  const idxs = [...new Set(state.stamps.map(s => s.pageIndex))].sort((a, b) => a - b);
  if (idxs.length === 0) idxs.push(0);
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
  $('ds-place-continue').addEventListener('click', () => { setActive('step-recipients'); renderRecipients(); });
  $('ds-hash-only-continue').addEventListener('click', () => { setActive('step-recipients'); renderRecipients(); });
  $('ds-identity-back').addEventListener('click', () => setActive('step-recipients'));
  $('ds-place-back').addEventListener('click', () => setActive('step-doc'));
  $('ds-hash-only-back').addEventListener('click', () => setActive('step-doc'));
  $('ds-recipients-back').addEventListener('click', () => {
    commitRecipientsFromDom();
    setActive(state.mode === 'pdf' || state.mode === 'image' ? 'step-place' : 'step-hash-only');
  });
  $('ds-recipients-continue').addEventListener('click', () => {
    commitRecipientsFromDom();
    setActive('step-identity');
  });
  $('ds-add-recipient').addEventListener('click', addRecipientRow);
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
    empty.innerHTML = 'No recipients yet. Click <strong>+ Add recipient</strong> if this needs to be co-signed by someone else, or click <strong>Continue</strong> to sign only for yourself.';
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
  let pending = null;
  $('ds-signer-name').addEventListener('input', () => {
    if ((state.mode !== 'pdf' && state.mode !== 'image') || state.stamps.length === 0) return;
    // Debounce so we don't redraw on every keystroke
    if (pending) clearTimeout(pending);
    pending = setTimeout(async () => {
      const markers = document.querySelectorAll('.ds-stamp-marker');
      for (const m of markers) {
        const w = m.clientWidth, h = m.clientHeight;
        m.innerHTML = '';
        try {
          const c = await createStampPreviewCanvas(w, h);
          c.style.cssText = 'width:100%;height:100%;display:block';
          m.appendChild(c);
        } catch {}
      }
    }, 120);
  });
}

function init() {
  initStepDoc();
  initStepIdentity();
  wireNav();
  wireLiveStampUpdates();
  initApiKeyPersistence();
  wireThemeToggle();
  wireClearAllStamps();
  setActive('step-doc');
}

function wireClearAllStamps() {
  const btn = $('ds-place-clear-all');
  if (!btn) return;
  btn.addEventListener('click', () => {
    state.stamps = [];
    document.querySelectorAll('.ds-stamp-marker').forEach(el => el.remove());
    updatePlaceHint();
    $('ds-place-continue').disabled = true;
  });
}

function wireThemeToggle() {
  document.querySelectorAll('.ds-theme-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const theme = btn.dataset.theme;
      state.signer.stampTheme = theme;
      document.querySelectorAll('.ds-theme-btn').forEach(b => {
        const isActive = b.dataset.theme === theme;
        b.classList.toggle('active', isActive);
        b.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      });
      // Repaint any existing on-screen stamp markers with the new theme.
      const markers = document.querySelectorAll('.ds-stamp-marker');
      for (const m of markers) {
        const w = m.clientWidth, h = m.clientHeight;
        m.innerHTML = '';
        try {
          const c = await createStampPreviewCanvas(w, h);
          c.style.cssText = 'width:100%;height:100%;display:block';
          m.appendChild(c);
        } catch {}
      }
    });
  });
}

// The relay API key (pgp_...) is bound to the user's website session. We
// auto-fetch it via /api/user/account/key when the page loads, so logged-in
// users never have to paste anything. We also persist whatever ends up in
// the field per-tab in sessionStorage as a fallback.
function initApiKeyPersistence() {
  const input = $('ds-api-key');
  const clearBtn = $('ds-api-key-clear');
  if (!input) return;

  // Hydrate from sessionStorage first (fast, no network).
  try {
    const saved = sessionStorage.getItem('paramant_sign_api_key');
    if (saved) input.value = saved;
  } catch {}

  input.addEventListener('input', () => {
    const v = input.value.trim();
    try {
      if (v) sessionStorage.setItem('paramant_sign_api_key', v);
      else sessionStorage.removeItem('paramant_sign_api_key');
    } catch {}
  });
  if (clearBtn) clearBtn.addEventListener('click', () => {
    input.value = '';
    try { sessionStorage.removeItem('paramant_sign_api_key'); } catch {}
  });

  // Auto-fetch from the website session (paramant_user_session cookie).
  // If the user is logged in, /api/user/account/key returns { api_key: 'pgp_...' }
  // and we silently fill the field. If they are not logged in, or the
  // endpoint is unavailable, we leave the field empty for manual paste.
  autoFetchApiKey(input).catch(() => {});
}

async function autoFetchApiKey(input) {
  // Don't overwrite a value the user has already typed.
  if (input.value.trim()) return;
  try {
    const r = await fetch('/api/user/account/key', { credentials: 'include' });
    if (!r.ok) return;
    const d = await r.json().catch(() => null);
    const key = d && d.api_key;
    if (key && /^pgp_/.test(key)) {
      input.value = key;
      try { sessionStorage.setItem('paramant_sign_api_key', key); } catch {}
      // Surface that this happened so users understand why the field is filled.
      const adv = document.getElementById('ds-advanced-block');
      if (adv && !adv.open) adv.dataset.autofilled = '1';
      const status = document.getElementById('ds-api-key-status');
      if (status) {
        status.hidden = false;
        status.textContent = 'API key auto-loaded from your account session.';
        status.className = 'ds-hint ds-api-status ok';
      }
    }
  } catch {}
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
