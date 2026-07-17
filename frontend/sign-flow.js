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
import { LocalVaultSigner, buildDocSignMessage, createSigningEnvelope, requestSignActivation, submitSignature, resolvePasskeySigningKey, ensureSigningKey, enrolEphemeralSigningKeyWithTotp } from '/js/parasign-signer.js?v=12';
import { promptTotp } from '/js/totp-prompt.js?v=1';

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
// PDF placement view state for zoom + page-nav (PDF mode only).
let placeState = null;        // { pdf, pages:[{page,baseViewport,wrap,canvas,task}], zoom }
let placeRenderToken = 0;     // guards overlapping re-renders on fast zooming
let _pageNavObserver = null;  // IntersectionObserver for the "page X of N" indicator
let _placeCurrentPage = 0;    // most-visible page index (for where a new text/date lands)
let _drag = null;             // active stamp drag-reposition gesture
let _reviewZoom = 1;          // zoom factor of the review document preview

const state = {
  signingMode: null,     // 'alone' | 'cosign' | 'invite' (chosen on step-mode)
  mode: null,            // 'pdf' | 'image' | 'hash'
  imageType: null,       // 'png' | 'jpg' (only when mode === 'image')
  doc:  null,            // { bytes (Uint8Array), name, size }
  stamp: null,           // PDF mode: bottom-left PDF points. Image mode: top-left image pixels.
  extras: [],            // PDF mode only. Types (all baked as pdf-lib vectors):
                         //   text/date : { id, type, pageIndex, x, y, size, text }        x,y = box bottom-left (points)
                         //   highlight : { id, type, pageIndex, x, y, w, h }              translucent rect over content
                         //   note      : { id, type, pageIndex, x, yTop, w, size, text }  anchored at its TOP edge (height follows the wrapped text)
                         //   draw      : { id, type, pageIndex, points:[{x,y}], width }   one freehand pen stroke
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

let __firstStepRender = true;
function setActive(stepId) {
  document.querySelectorAll('.ds-step').forEach(s => s.hidden = (s.id !== stepId));
  // Move focus to the new step's heading so keyboard + screen-reader users land
  // on the freshly revealed content (skip the very first render at page load).
  if (!__firstStepRender) {
    const stepEl = document.getElementById(stepId);
    const heading = stepEl && stepEl.querySelector('h2');
    if (heading) {
      if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
      try { heading.focus({ preventScroll: false }); } catch (e) { heading.focus(); }
    }
  }
  __firstStepRender = false;
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

// Supersampling factor for canvas rendering: the screen's devicePixelRatio,
// capped at 3 so a 4K/retina display gets crisp output without exploding the
// backing-store memory on very large PDF pages.
function hiDpiScale() {
  return Math.max(1, Math.min(window.devicePixelRatio || 1, 3));
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
  // Keyboard activation: the dropzone is role="button" tabindex="0", so Enter
  // and Space must open the file picker the same way a click does.
  dz.addEventListener('keydown', e => {
    if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
      e.preventDefault();
      inp.click();
    }
  });
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
  state.extras = [];        // fresh document: drop any text/date objects from a prior file

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
  teardownPageNav();                                  // single image: no page-nav
  { const et = $('ds-edit-tools'); if (et) et.hidden = true; }   // text/date tools are PDF-only
  { const eh = $('ds-edit-tools-hint'); if (eh) eh.hidden = false; }  // tell the user WHY the editor is absent
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

  // Zoom + drag work for images too (page-nav is multi-page-PDF only).
  placeState = { isImage: true, wrap, zoom: 1 };
  { const zb = $('ds-zoom'); if (zb) zb.hidden = false; }
  const zo = $('ds-zoom-out'), zi = $('ds-zoom-in'), zf = $('ds-zoom-fit');
  if (zo) zo.onclick = () => setPlaceZoom(placeState.zoom / 1.25);
  if (zi) zi.onclick = () => setPlaceZoom(placeState.zoom * 1.25);
  if (zf) zf.onclick = () => setPlaceZoom(1);
  applyPlaceZoom();

  $('ds-place-page-count').textContent = '1 image (' + img.naturalWidth + ' x ' + img.naturalHeight + ' pixels)';
}

// ====================================================================
// Step 2 (PDF): render + click to place stamp
// ====================================================================

async function renderPdfForPlacement() {
  $('ds-place-continue').disabled = true;
  teardownPageNav();
  { const zb = $('ds-zoom'); if (zb) zb.hidden = false; }
  { const et = $('ds-edit-tools'); if (et) et.hidden = false; }   // text/date tools: PDF only
  { const eh = $('ds-edit-tools-hint'); if (eh) eh.hidden = true; }
  const pdfjs = await waitForPdfjs();
  const copy = new Uint8Array(state.doc.bytes);
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;

  const container = $('ds-pdf-canvas-list');
  container.innerHTML = '';
  const maxPages = Math.min(pdf.numPages, MAX_PREVIEW_PAGES);
  const pages = [];
  for (let i = 1; i <= maxPages; i++) {
    const page = await pdf.getPage(i);
    const baseViewport = page.getViewport({ scale: 1 });
    const wrap = document.createElement('div');
    wrap.className = 'ds-page-wrap';
    wrap.dataset.pageIndex = String(i - 1);
    wrap._pdfPage = { width: baseViewport.width, height: baseViewport.height, index: i - 1 };
    const canvas = document.createElement('canvas');
    wrap.appendChild(canvas);
    wrap.appendChild(buildPageBar(i - 1));
    container.appendChild(wrap);
    wrap.addEventListener('click', onPlaceClick);
    wrap.addEventListener('pointerdown', onPenDown);
    wrap.addEventListener('pointermove', onPenMove);
    wrap.addEventListener('pointerup', onPenUp);
    wrap.addEventListener('pointercancel', onPenUp);
    pages.push({ page, baseViewport, wrap, canvas, task: null });
  }
  placeState = { pdf, pages, zoom: 1 };

  $('ds-place-page-count').textContent =
    pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's') +
    (pdf.numPages > maxPages ? ' (showing first ' + maxPages + ')' : '');

  const zo = $('ds-zoom-out'), zi = $('ds-zoom-in'), zf = $('ds-zoom-fit');
  if (zo) zo.onclick = () => setPlaceZoom(placeState.zoom / 1.25);
  if (zi) zi.onclick = () => setPlaceZoom(placeState.zoom * 1.25);
  if (zf) zf.onclick = () => setPlaceZoom(1);

  await applyPlaceZoom();                 // initial render == fit-to-width (zoom 1)
  setupPageNav(container, maxPages);
}

// Fit-to-width base scale (the original targetWidth logic), times the zoom factor.
function fitScaleFor(baseViewport) {
  const targetWidth = Math.min(820, Math.floor(window.innerWidth * 0.88));
  return targetWidth / baseViewport.width;
}

function setPlaceZoom(z) {
  if (!placeState) return;
  placeState.zoom = Math.max(0.4, Math.min(4, z));
  applyPlaceZoom();
}

// (Re)render every page at the current zoom. state.stamp (PDF points) is never
// touched; only the displayed canvas size changes and the marker is repainted.
async function applyPlaceZoom() {
  if (!placeState) return;
  const z = placeState.zoom;
  const pctEl = $('ds-zoom-pct'); if (pctEl) pctEl.textContent = Math.round(z * 100) + '%';
  if (placeState.isImage) {
    // Image: canvas is at natural resolution, CSS width:100% scales it; zoom =
    // set the wrap width. No re-render needed.
    const fit = Math.min(820, Math.floor(window.innerWidth * 0.88));
    placeState.wrap.style.width = Math.floor(fit * z) + 'px';
    reflowStampMarker();
    return;
  }
  const token = ++placeRenderToken;
  // Render at devicePixelRatio so the backing store has real pixels behind every
  // CSS pixel. The canvas is shown at the CSS width (wrap width + canvas{width:100%}),
  // but drawn at cssWidth*dpr, so it stays razor sharp on HiDPI/retina screens.
  const dpr = hiDpiScale();
  for (const p of placeState.pages) {
    const cssScale = fitScaleFor(p.baseViewport) * z;
    const cssW = Math.floor(p.baseViewport.width * cssScale);
    const viewport = p.page.getViewport({ scale: cssScale * dpr });
    p.wrap.style.width = cssW + 'px';                 // CSS size drives layout + coords
    p.canvas.width = Math.floor(viewport.width);      // backing store = cssW * dpr
    p.canvas.height = Math.floor(viewport.height);
    if (p.task) { try { p.task.cancel(); } catch (e) {} }
    p.task = p.page.render({ canvasContext: p.canvas.getContext('2d'), viewport });
    try { await p.task.promise; }
    catch (e) { if (e && e.name === 'RenderingCancelledException') return; }
    if (token !== placeRenderToken) return;   // a newer zoom superseded this pass
  }
  reflowStampMarker();
  reflowExtras();                             // text/date objects follow the new scale too
}

// Re-derive the marker's pixel box from the PDF-point state.stamp at the current
// display width. Never mutates state.stamp.
function reflowStampMarker() {
  document.querySelectorAll('.ds-stamp-marker').forEach(el => el.remove());
  if (!state.stamp || !placeState) return;
  let wrap;
  if (placeState.isImage) wrap = placeState.wrap;
  else { const p = placeState.pages.find(pp => pp.wrap._pdfPage.index === state.stamp.pageIndex); wrap = p && p.wrap; }
  if (!wrap) return;
  const rect = wrap.querySelector('canvas').getBoundingClientRect();
  const ratio = wrap._pdfPage.width / rect.width;            // natural units per CSS px
  const w = state.stamp.w / ratio, h = state.stamp.h / ratio;
  const left = state.stamp.x / ratio;
  const top = state.stamp.isImage
    ? state.stamp.y / ratio                                   // image: top-left origin
    : (wrap._pdfPage.height - state.stamp.y - state.stamp.h) / ratio;  // pdf: bottom-left flip
  renderStampMarker(wrap, left, top, w, h);
}

// ====================================================================
// Edit layer: free text + date annotations (PDF mode). Additive - the seal
// (state.stamp) and the whole signing/envelope path are untouched. Each extra
// is baked as pdf-lib vector text, so the output stays sharp and selectable.
// ====================================================================

const TEXT_LINE_H = 1.35;            // box height = font size * this
let _extraSeq = 0;

// Height of a text box in PDF points for a given font size.
function extraBoxH(size) { return size * TEXT_LINE_H; }

// The page the user is currently looking at (updated by the page-nav observer),
// so a new text/date object lands on the page in view, not always page 1.
function addExtra(type) {
  if (!placeState || placeState.isImage) return;
  const pageIdx = Math.max(0, Math.min(_placeCurrentPage, placeState.pages.length - 1));
  const p = placeState.pages[pageIdx];
  const pageW = p.wrap._pdfPage.width, pageH = p.wrap._pdfPage.height;
  const size = Math.round(Math.max(12, Math.min(pageW, pageH) * 0.035));   // sane default per page size
  const h = extraBoxH(size);
  const text = type === 'date' ? new Date().toISOString().slice(0, 10) : 'Text';
  const extra = {
    id: ++_extraSeq, type, pageIndex: pageIdx,
    x: Math.round(pageW * 0.12),                 // a little in from the left
    y: Math.round(pageH * 0.82 - h),             // near the top of the page
    size, text,
  };
  state.extras.push(extra);
  const el = renderExtraMarker(extra);
  // Continue stays gated on the SEAL (the signature) being placed - extras are
  // optional additions, not a substitute for signing.
  if (el && type === 'text') beginEditExtra(el, extra);   // let the user type straight away
}

// A highlight starts as a translucent bar near the top of the visible page;
// drag it over the passage, corner-resize to fit.
function addHighlight() {
  if (!placeState || placeState.isImage) return;
  const pageIdx = Math.max(0, Math.min(_placeCurrentPage, placeState.pages.length - 1));
  const p = placeState.pages[pageIdx];
  const pageW = p.wrap._pdfPage.width, pageH = p.wrap._pdfPage.height;
  const w = Math.round(pageW * 0.36);
  const h = Math.round(Math.max(14, pageH * 0.028));
  const extra = {
    id: ++_extraSeq, type: 'highlight', pageIndex: pageIdx,
    x: Math.round(pageW * 0.32), y: Math.round(pageH * 0.72), w, h,
  };
  state.extras.push(extra);
  renderExtraMarker(extra);
}

// A sticky note: filled box, text wraps to the box width, anchored at its top
// edge so the box can grow downward while you type without drifting.
function addNote() {
  if (!placeState || placeState.isImage) return;
  const pageIdx = Math.max(0, Math.min(_placeCurrentPage, placeState.pages.length - 1));
  const p = placeState.pages[pageIdx];
  const pageW = p.wrap._pdfPage.width, pageH = p.wrap._pdfPage.height;
  const size = Math.round(Math.max(9, Math.min(pageW, pageH) * 0.022));
  const extra = {
    id: ++_extraSeq, type: 'note', pageIndex: pageIdx,
    x: Math.round(pageW * 0.58), yTop: Math.round(pageH * 0.85),
    w: Math.round(pageW * 0.28), size, text: 'Note',
  };
  state.extras.push(extra);
  const el = renderExtraMarker(extra);
  if (el) beginEditExtra(el, extra);
}

function extraWrapFor(pageIndex) {
  if (!placeState || placeState.isImage) return null;
  const p = placeState.pages.find(pp => pp.wrap._pdfPage.index === pageIndex);
  return p && p.wrap;
}

// Build the on-page marker for one extra from its PDF-point geometry at the
// current display scale. Never mutates the extra; reflowExtras re-derives on zoom.
function renderExtraMarker(extra) {
  if (extra.type === 'draw') return renderDrawMarker(extra);
  const wrap = extraWrapFor(extra.pageIndex);
  if (!wrap) return null;
  const rect = wrap.querySelector('canvas').getBoundingClientRect();
  const ratio = wrap._pdfPage.width / rect.width;      // pdf points per CSS px
  const pageH = wrap._pdfPage.height;
  const el = document.createElement('div');
  el.className = 'ds-anno';
  el.dataset.type = extra.type;
  el.dataset.id = String(extra.id);
  if (extra.type === 'highlight') {
    el.style.cssText = `left:${extra.x / ratio}px;top:${(pageH - extra.y - extra.h) / ratio}px;width:${extra.w / ratio}px;height:${extra.h / ratio}px`;
  } else if (extra.type === 'note') {
    el.style.cssText = `left:${extra.x / ratio}px;top:${(pageH - extra.yTop) / ratio}px;width:${extra.w / ratio}px;font-size:${extra.size / ratio}px`;
    el.textContent = extra.text;
  } else {
    const h = extraBoxH(extra.size);
    el.style.cssText = `left:${extra.x / ratio}px;top:${(pageH - extra.y - h) / ratio}px;height:${h / ratio}px;font-size:${extra.size / ratio}px`;
    el.textContent = extra.text;
  }

  const del = document.createElement('button');
  del.className = 'ds-anno-del'; del.type = 'button'; del.textContent = '×';
  del.title = 'Remove'; del.setAttribute('aria-label', 'Remove this object');
  del.addEventListener('pointerdown', e => { e.stopPropagation(); });
  del.addEventListener('click', e => { e.stopPropagation(); removeExtra(extra.id); });
  el.appendChild(del);

  const grip = document.createElement('div');
  grip.className = 'ds-anno-resize';
  el.appendChild(grip);

  wrap.appendChild(el);
  wireExtraMarker(el, extra, grip);
  return el;
}

function removeExtra(id) {
  state.extras = state.extras.filter(e => e.id !== id);
  document.querySelectorAll(`.ds-anno[data-id="${id}"]`).forEach(el => el.remove());
}

// Drag to move, corner to resize (scales font size), double-click to edit text.
function wireExtraMarker(el, extra, grip) {
  let drag = null, rez = null;

  el.addEventListener('pointerdown', (e) => {
    if (el.classList.contains('editing')) return;         // editing: let the caret work
    if (e.target === grip) return;                        // resize handled below
    const wrap = el.parentElement;
    const rect = wrap.querySelector('canvas').getBoundingClientRect();
    drag = { rect, grabX: e.clientX - (rect.left + parseFloat(el.style.left)), grabY: e.clientY - (rect.top + parseFloat(el.style.top)) };
    try { el.setPointerCapture(e.pointerId); } catch (_) {}
    el.style.cursor = 'grabbing';
    e.preventDefault(); e.stopPropagation();
  });
  el.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const left = Math.max(0, Math.min(drag.rect.width - el.offsetWidth, e.clientX - drag.rect.left - drag.grabX));
    const top = Math.max(0, Math.min(drag.rect.height - el.offsetHeight, e.clientY - drag.rect.top - drag.grabY));
    el.style.left = left + 'px'; el.style.top = top + 'px';
  });
  const dragUp = (e) => {
    if (!drag) return; drag = null;
    try { el.releasePointerCapture(e.pointerId); } catch (_) {}
    el.style.cursor = 'grab';
    swallowNextWrapClick(el.parentElement);   // don't let this land as a new seal
    commitExtraFromMarker(el, extra);
  };
  el.addEventListener('pointerup', dragUp);
  el.addEventListener('pointercancel', dragUp);

  if (grip) {
  grip.addEventListener('pointerdown', (e) => {
    e.preventDefault(); e.stopPropagation();
    rez = { x0: e.clientX, y0: e.clientY, w0: el.offsetWidth, h0: el.offsetHeight, size0: extra.size };
    try { grip.setPointerCapture(e.pointerId); } catch (_) {}
  });
  grip.addEventListener('pointermove', (e) => {
    if (!rez) return;
    // What the corner grip means depends on the type: a highlight resizes its
    // box in both dimensions, a note resizes its width (text re-wraps), and
    // text/date scale their font size.
    if (extra.type === 'highlight') {
      el.style.width  = Math.max(12, rez.w0 + (e.clientX - rez.x0)) + 'px';
      el.style.height = Math.max(8,  rez.h0 + (e.clientY - rez.y0)) + 'px';
      return;
    }
    if (extra.type === 'note') {
      el.style.width = Math.max(60, rez.w0 + (e.clientX - rez.x0)) + 'px';
      return;
    }
    const factor = Math.max(0.35, (rez.h0 + (e.clientY - rez.y0)) / rez.h0);
    const wrap = el.parentElement;
    const ratio = wrap._pdfPage.width / wrap.querySelector('canvas').getBoundingClientRect().width;
    const newSize = Math.max(6, Math.min(96, rez.size0 * factor));
    el.style.fontSize = (newSize / ratio) + 'px';
    el.style.height = (extraBoxH(newSize) / ratio) + 'px';
    el.dataset.pendingSize = String(newSize);
  });
  const rezUp = (e) => {
    if (!rez) return; rez = null;
    try { grip.releasePointerCapture(e.pointerId); } catch (_) {}
    swallowNextWrapClick(el.parentElement);
    if (el.dataset.pendingSize) { extra.size = parseFloat(el.dataset.pendingSize); delete el.dataset.pendingSize; }
    commitExtraFromMarker(el, extra);
  };
  grip.addEventListener('pointerup', rezUp);
  grip.addEventListener('pointercancel', rezUp);
  }   // if (grip): draw markers have no resize grip

  if (extra.type !== 'highlight' && extra.type !== 'draw') {
    // Both clicks of the double-click bubble to the wrap; swallow them so the
    // seal is never placed while the user just wants to edit the text (QA #9).
    el.addEventListener('click', () => swallowNextWrapClick(el.parentElement));
    el.addEventListener('dblclick', (e) => { e.preventDefault(); e.stopPropagation(); swallowNextWrapClick(el.parentElement); beginEditExtra(el, extra); });
  }
}

// Inline text editing via contentEditable. On blur/Enter the text is saved back
// to the extra and the box re-fits.
function beginEditExtra(el, extra) {
  el.classList.add('editing');
  el.contentEditable = 'true';
  // Drop the child controls from the editable text, restore them after.
  const del = el.querySelector('.ds-anno-del'), grip = el.querySelector('.ds-anno-resize');
  if (del) del.remove(); if (grip) grip.remove();
  el.textContent = extra.text;
  el.focus();
  try { const r = document.createRange(); r.selectNodeContents(el); const s = getSelection(); s.removeAllRanges(); s.addRange(r); } catch (_) {}
  const finish = () => {
    el.contentEditable = 'false';
    el.classList.remove('editing');
    extra.text = (el.textContent || '').replace(/\n/g, ' ').trim()
      || (extra.type === 'date' ? new Date().toISOString().slice(0, 10) : extra.type === 'note' ? 'Note' : 'Text');
    el.removeEventListener('blur', finish);
    el.removeEventListener('keydown', onKey);
    // Rebuild the marker so delete/resize handles + geometry are consistent.
    el.remove();
    renderExtraMarker(extra);
  };
  const onKey = (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); el.blur(); }
    else if (ev.key === 'Escape') { ev.preventDefault(); el.blur(); }
  };
  el.addEventListener('blur', finish);
  el.addEventListener('keydown', onKey);
}

// Write a marker's pixel box back into the extra's PDF-point geometry.
function commitExtraFromMarker(el, extra) {
  const wrap = el.parentElement;
  const ratio = wrap._pdfPage.width / wrap.querySelector('canvas').getBoundingClientRect().width;
  const pageH = wrap._pdfPage.height;
  const left = parseFloat(el.style.left), top = parseFloat(el.style.top);
  if (extra.type === 'highlight') {
    extra.x = left * ratio;
    extra.w = el.offsetWidth * ratio;
    extra.h = el.offsetHeight * ratio;
    extra.y = pageH - (top * ratio) - extra.h;
    return;
  }
  if (extra.type === 'note') {
    extra.x = left * ratio;
    extra.w = el.offsetWidth * ratio;
    extra.yTop = pageH - (top * ratio);
    return;
  }
  if (extra.type === 'draw') {
    // Dragging translated the bounding box; shift every stroke point by the
    // same delta (the origin at render time is remembered on the element).
    const o = el._drawOrigin || { minX: 0, maxY: 0 };
    const dx = left * ratio - o.minX;
    const dy = (pageH - top * ratio) - o.maxY;
    for (const pt of extra.points) { pt.x += dx; pt.y += dy; }
    el._drawOrigin = { minX: o.minX + dx, maxY: o.maxY + dy };
    return;
  }
  const h = extraBoxH(extra.size);
  extra.x = left * ratio;
  extra.y = pageH - (top * ratio) - h;
}

// Re-render every extra marker from state (used after a zoom re-render, which
// wipes the overlay divs). PDF-point geometry is the source of truth.
function reflowExtras() {
  document.querySelectorAll('.ds-anno').forEach(el => el.remove());
  if (placeState && placeState.isImage) return;
  for (const extra of state.extras) renderExtraMarker(extra);
}

// ====================================================================
// Pen tool: freehand strokes, stored as PDF-point polylines and baked as
// round-capped vector line segments. One stroke = one extra (deletable,
// draggable as a whole).
// ====================================================================

const SVGNS = 'http://www.w3.org/2000/svg';
const PEN_STROKE_PT = 2;             // stroke width in PDF points
let _penMode = false;
let _penStroke = null;               // live stroke: { wrap, ratio, pts:[{px,py}], svg, poly }

function setPenMode(on) {
  _penMode = !!on;
  const b = $('ds-tool-pen');
  if (b) { b.classList.toggle('active', _penMode); b.setAttribute('aria-pressed', String(_penMode)); }
  const list = $('ds-pdf-canvas-list');
  if (list) list.classList.toggle('pen-mode', _penMode);
}

function onPenDown(e) {
  if (!_penMode || !placeState || placeState.isImage || _penStroke) return;
  const wrap = e.currentTarget;
  if (e.target.closest('.ds-anno') || e.target.closest('.ds-page-bar') || e.target.closest('.ds-stamp-marker')) return;
  const canvas = wrap.querySelector('canvas');
  const rect = canvas.getBoundingClientRect();
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('class', 'ds-pen-live');
  const poly = document.createElementNS(SVGNS, 'polyline');
  poly.setAttribute('fill', 'none');
  poly.setAttribute('stroke', '#0b3a6a');
  poly.setAttribute('stroke-width', String(PEN_STROKE_PT * (rect.width / wrap._pdfPage.width)));
  poly.setAttribute('stroke-linecap', 'round');
  poly.setAttribute('stroke-linejoin', 'round');
  svg.appendChild(poly);
  wrap.appendChild(svg);
  _penStroke = { wrap, rect, pts: [{ px: e.clientX - rect.left, py: e.clientY - rect.top }], svg, poly };
  try { wrap.setPointerCapture(e.pointerId); } catch (_) {}
  e.preventDefault(); e.stopPropagation();
}

function onPenMove(e) {
  const s = _penStroke;
  if (!s) return;
  const px = e.clientX - s.rect.left, py = e.clientY - s.rect.top;
  const last = s.pts[s.pts.length - 1];
  if (Math.hypot(px - last.px, py - last.py) < 1.5) return;   // decimate micro-moves
  s.pts.push({ px, py });
  s.poly.setAttribute('points', s.pts.map(p => p.px + ',' + p.py).join(' '));
}

function onPenUp(e) {
  const s = _penStroke;
  if (!s) return;
  _penStroke = null;
  try { s.wrap.releasePointerCapture(e.pointerId); } catch (_) {}
  s.svg.remove();
  if (s.pts.length < 2) return;                               // a bare tap is not a stroke
  const ratio = s.wrap._pdfPage.width / s.rect.width;         // pdf points per CSS px
  const pageH = s.wrap._pdfPage.height;
  const points = s.pts.map(p => ({ x: p.px * ratio, y: pageH - p.py * ratio }));
  const extra = { id: ++_extraSeq, type: 'draw', pageIndex: s.wrap._pdfPage.index, points, width: PEN_STROKE_PT };
  state.extras.push(extra);
  renderExtraMarker(extra);
}

// A draw marker is an absolutely positioned SVG over the stroke's bounding box.
// Dragging moves the whole stroke (commitExtraFromMarker shifts the points).
function renderDrawMarker(extra) {
  const wrap = extraWrapFor(extra.pageIndex);
  if (!wrap || !extra.points.length) return null;
  const rect = wrap.querySelector('canvas').getBoundingClientRect();
  const ratio = wrap._pdfPage.width / rect.width;
  const pageH = wrap._pdfPage.height;
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (const p of extra.points) {
    if (p.x < minX) minX = p.x; if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y; if (p.y > maxY) maxY = p.y;
  }
  const padPt = extra.width * 2;                              // room for the round caps
  minX -= padPt; maxX += padPt; minY -= padPt; maxY += padPt;
  const wPx = Math.max(8, (maxX - minX) / ratio), hPx = Math.max(8, (maxY - minY) / ratio);
  const el = document.createElement('div');
  el.className = 'ds-anno ds-anno-draw';
  el.dataset.type = 'draw';
  el.dataset.id = String(extra.id);
  el.style.cssText = `left:${minX / ratio}px;top:${(pageH - maxY) / ratio}px;width:${wPx}px;height:${hPx}px`;
  el._drawOrigin = { minX, maxY };
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${wPx} ${hPx}`);
  const poly = document.createElementNS(SVGNS, 'polyline');
  poly.setAttribute('fill', 'none');
  poly.setAttribute('stroke', '#0b3a6a');
  poly.setAttribute('stroke-width', String(extra.width / ratio));
  poly.setAttribute('stroke-linecap', 'round');
  poly.setAttribute('stroke-linejoin', 'round');
  poly.setAttribute('points', extra.points.map(p => ((p.x - minX) / ratio) + ',' + ((maxY - p.y) / ratio)).join(' '));
  svg.appendChild(poly);
  el.appendChild(svg);

  const del = document.createElement('button');
  del.className = 'ds-anno-del'; del.type = 'button'; del.textContent = '×';
  del.title = 'Remove'; del.setAttribute('aria-label', 'Remove this drawing');
  del.addEventListener('pointerdown', e => { e.stopPropagation(); });
  del.addEventListener('click', e => { e.stopPropagation(); removeExtra(extra.id); });
  el.appendChild(del);

  wrap.appendChild(el);
  wireExtraMarker(el, extra, null);                           // drag + delete, no resize grip
  return el;
}

// ====================================================================
// Page manager: delete / rotate / reorder per page, merge another PDF,
// export a page range. Every op transforms state.doc.bytes via the pure
// ParasignPdfOps module, remaps or clears the placed objects, and re-renders.
// The bytes that get hashed + signed later are exactly these bytes.
// ====================================================================

let _pageOpBusy = false;

function setPlaceHint(msg) {
  const h = $('ds-place-hint');
  if (h) h.textContent = msg;
}

async function runPageOp(fn) {
  if (_pageOpBusy || !placeState || placeState.isImage) return;
  _pageOpBusy = true;
  try {
    const PDFLib = await waitForPdfLib();
    const out = await fn(PDFLib, window.ParasignPdfOps);
    if (out) {
      state.doc.bytes = new Uint8Array(out);
      state.doc.size = state.doc.bytes.length;
      await renderPdfForPlacement();
      // The seal gate: re-disable Continue when the op removed the stamp.
      $('ds-place-continue').disabled = !state.stamp;
    }
  } catch (err) {
    setPlaceHint('Page operation failed: ' + err.message);
  } finally {
    _pageOpBusy = false;
  }
}

// Drop placed objects that lived on a removed/rotated page; tell the user.
function clearObjectsOnPage(idx, why) {
  const hadExtras = state.extras.some(e => e.pageIndex === idx);
  const hadStamp = !!(state.stamp && !state.stamp.isImage && state.stamp.pageIndex === idx);
  state.extras = state.extras.filter(e => e.pageIndex !== idx);
  if (hadStamp) state.stamp = null;
  if (hadExtras || hadStamp) {
    setPlaceHint('Page ' + (idx + 1) + ' was ' + why + '; the objects placed on it were removed' +
      (hadStamp ? ' (place the signature stamp again)' : '') + '.');
  }
  return hadExtras || hadStamp;
}

function remapAfterDelete(idx) {
  clearObjectsOnPage(idx, 'deleted');
  state.extras.forEach(e => { if (e.pageIndex > idx) e.pageIndex--; });
  if (state.stamp && !state.stamp.isImage && state.stamp.pageIndex > idx) state.stamp.pageIndex--;
}

function remapAfterMove(from, to) {
  const map = i => {
    if (i === from) return to;
    if (from < to)  return (i > from && i <= to) ? i - 1 : i;
    return (i >= to && i < from) ? i + 1 : i;
  };
  state.extras.forEach(e => { e.pageIndex = map(e.pageIndex); });
  if (state.stamp && !state.stamp.isImage) state.stamp.pageIndex = map(state.stamp.pageIndex);
}

function pageOpDelete(idx) {
  runPageOp(async (PDFLib, Ops) => {
    if (!confirm('Delete page ' + (idx + 1) + ' from the document?')) return null;
    const out = await Ops.deletePage(PDFLib, state.doc.bytes, idx);
    remapAfterDelete(idx);
    return out;
  });
}

function pageOpMove(idx, to) {
  runPageOp(async (PDFLib, Ops) => {
    const n = await Ops.pageCount(PDFLib, state.doc.bytes);
    if (to < 0 || to >= n) return null;
    const out = await Ops.movePage(PDFLib, state.doc.bytes, idx, to);
    remapAfterMove(idx, to);
    return out;
  });
}

// Rotation changes the page's render coordinate system; remapping every placed
// object through the rotation is not worth the risk of a silently misbaked
// seal, so objects on the rotated page are cleared with a visible notice.
function pageOpRotate(idx) {
  runPageOp(async (PDFLib, Ops) => {
    const out = await Ops.rotatePage(PDFLib, state.doc.bytes, idx, 90);
    clearObjectsOnPage(idx, 'rotated');
    return out;
  });
}

// Small always-available action bar in the corner of every rendered page.
function buildPageBar(idx) {
  const bar = document.createElement('div');
  bar.className = 'ds-page-bar';
  bar.addEventListener('pointerdown', e => e.stopPropagation());
  bar.addEventListener('click', e => e.stopPropagation());
  const mk = (label, title, fn) => {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = label; b.title = title; b.setAttribute('aria-label', title);
    b.addEventListener('click', fn);
    bar.appendChild(b);
  };
  mk('↑', 'Move page ' + (idx + 1) + ' up',   () => pageOpMove(idx, idx - 1));
  mk('↓', 'Move page ' + (idx + 1) + ' down', () => pageOpMove(idx, idx + 1));
  mk('⟳', 'Rotate page ' + (idx + 1) + ' 90°', () => pageOpRotate(idx));
  mk('×', 'Delete page ' + (idx + 1),         () => pageOpDelete(idx));
  return bar;
}

function wirePageTools() {
  const mergeBtn = $('ds-page-merge'), mergeFile = $('ds-page-merge-file'), splitBtn = $('ds-page-split');
  if (mergeBtn && mergeFile) {
    mergeBtn.addEventListener('click', () => mergeFile.click());
    mergeFile.addEventListener('change', async () => {
      const f = mergeFile.files && mergeFile.files[0];
      mergeFile.value = '';
      if (!f) return;
      const other = new Uint8Array(await f.arrayBuffer());
      runPageOp(async (PDFLib, Ops) => {
        const out = await Ops.appendPdf(PDFLib, state.doc.bytes, other);
        setPlaceHint('Appended the pages of ' + f.name + ' to the end of the document.');
        return out;
      });
    });
  }
  if (splitBtn) {
    splitBtn.addEventListener('click', () => {
      runPageOp(async (PDFLib, Ops) => {
        const n = await Ops.pageCount(PDFLib, state.doc.bytes);
        const raw = prompt('Export which pages as a new PDF? (e.g. 3 or 2-5, of ' + n + ' total)');
        if (raw === null) return null;
        const r = Ops.parsePageRange(raw, n);
        if (!r) { setPlaceHint('Could not read that page range.'); return null; }
        const out = await Ops.extractRange(PDFLib, state.doc.bytes, r.from, r.to);
        const base = (state.doc.name || 'document.pdf').replace(/\.pdf$/i, '');
        downloadBytes(out, base + '-pages-' + (r.from + 1) + '-' + (r.to + 1) + '.pdf', 'application/pdf');
        setPlaceHint('Exported pages ' + (r.from + 1) + ' to ' + (r.to + 1) + ' as a separate PDF. The document here is unchanged.');
        return null;                                          // export only
      });
    });
  }
}

function teardownPageNav() {
  if (_pageNavObserver) { _pageNavObserver.disconnect(); _pageNavObserver = null; }
  const nav = $('ds-page-nav'); if (nav) nav.hidden = true;
}

// Sticky "Page X of N" that follows the most-visible page; jump/prev/next.
function setupPageNav(container, total) {
  teardownPageNav();
  const nav = $('ds-page-nav'), label = $('ds-page-nav-label');
  if (!nav || !label) return;
  const wraps = Array.from(container.querySelectorAll('.ds-page-wrap'));
  if (wraps.length <= 1) { nav.hidden = true; return; }
  nav.hidden = false;
  const ratios = new Map(wraps.map(w => [w, 0]));
  let current = 0;
  const render = () => { label.textContent = 'Page ' + (current + 1) + ' of ' + total; };
  _pageNavObserver = new IntersectionObserver((entries) => {
    for (const e of entries) ratios.set(e.target, e.intersectionRatio);
    let best = wraps[0], bestR = -1;
    for (const w of wraps) { const r = ratios.get(w) || 0; if (r > bestR) { bestR = r; best = w; } }
    const idx = Number(best.dataset.pageIndex) || 0;
    _placeCurrentPage = idx;                 // new text/date objects land on the visible page
    if (idx !== current) { current = idx; render(); }
  }, { root: null, rootMargin: '-45% 0px -45% 0px', threshold: [0, 0.25, 0.5, 0.75, 1] });
  wraps.forEach(w => _pageNavObserver.observe(w));
  render();
  const goTo = (i) => {
    const w = container.querySelector('.ds-page-wrap[data-page-index="' + i + '"]');
    if (w) w.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };
  const jump = $('ds-page-nav-jump');
  if (jump && !jump._wired) {
    jump._wired = true; jump.max = String(total);
    const go = () => { const n = Math.max(1, Math.min(total, parseInt(jump.value, 10) || 1)); goTo(n - 1); };
    jump.addEventListener('change', go);
    jump.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); go(); } });
  }
  const prev = $('ds-page-nav-prev'), next = $('ds-page-nav-next');
  if (prev && !prev._wired) { prev._wired = true; prev.addEventListener('click', () => goTo(Math.max(0, current - 1))); }
  if (next && !next._wired) { next._wired = true; next.addEventListener('click', () => goTo(Math.min(total - 1, current + 1))); }
}

// After a drag/resize/edit on ANY placed object the browser fires a click that
// bubbles to the wrap. Without this guard that click reaches onPlaceClick and
// silently re-places the seal at the cursor (QA: stamp-resize, edit-object drag,
// dblclick all corrupted the seal). Every interaction handler calls
// swallowNextWrapClick(wrap) so exactly the next wrap click is eaten.
function swallowNextWrapClick(wrap) {
  if (!wrap) return;
  wrap.addEventListener('click', (ev) => { ev.stopPropagation(); ev.preventDefault(); }, { capture: true, once: true });
}

function onPlaceClick(e) {
  if (_penMode) return;                 // pen mode: pointer gestures draw, they don't place the seal
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
  m.addEventListener('pointerdown', onStampPointerDown);   // drag to reposition
  addStampResizeHandle(m, wrap);                           // corner grip to scale
  wrap.appendChild(m);
}

// Write a marker's current pixel box (left/top/width/height in CSS px on the
// wrap) back into state.stamp in the page's natural units. Shared by drag and
// resize so the two can never drift on the coordinate math.
function commitStampFromMarker(marker, wrap) {
  const ratio = wrap._pdfPage.width / wrap.querySelector('canvas').getBoundingClientRect().width;
  const left = parseFloat(marker.style.left), top = parseFloat(marker.style.top);
  const w = parseFloat(marker.style.width) * ratio, h = parseFloat(marker.style.height) * ratio;
  const natX = left * ratio, natYTop = top * ratio;
  if (wrap._pdfPage.isImage) {
    state.stamp = { pageIndex: 0, x: natX, y: natYTop, w, h, isImage: true };
  } else {
    state.stamp = { pageIndex: wrap._pdfPage.index, x: natX, y: wrap._pdfPage.height - natYTop - h, w, h };
  }
}

// A bottom-right corner grip that scales the seal uniformly (keeps its aspect
// ratio). The screen top-left stays pinned, so only width/height - and, for a
// PDF, the bottom-left y - change. Min 60px wide, capped at the page width.
function addStampResizeHandle(marker, wrap) {
  const grip = document.createElement('div');
  grip.className = 'ds-stamp-resize';
  marker.appendChild(grip);
  let rs = null;
  grip.addEventListener('pointerdown', (e) => {
    e.preventDefault(); e.stopPropagation();               // never start a reposition drag
    const w0 = parseFloat(marker.style.width), h0 = parseFloat(marker.style.height);
    rs = { x0: e.clientX, w0, aspect: h0 / w0, maxW: wrap.getBoundingClientRect().width - parseFloat(marker.style.left) };
    try { grip.setPointerCapture(e.pointerId); } catch (_) {}
  });
  grip.addEventListener('pointermove', (e) => {
    if (!rs) return;
    const w = Math.max(60, Math.min(rs.maxW, rs.w0 + (e.clientX - rs.x0)));
    marker.style.width = w + 'px';
    marker.style.height = (w * rs.aspect) + 'px';
  });
  const up = (e) => {
    if (!rs) return; rs = null;
    try { grip.releasePointerCapture(e.pointerId); } catch (_) {}
    swallowNextWrapClick(wrap);   // QA #1: resizing the seal used to re-place it at the cursor
    commitStampFromMarker(marker, wrap);
  };
  grip.addEventListener('pointerup', up);
  grip.addEventListener('pointercancel', up);
}

// ── Drag the placed stamp to reposition (coexists with click-to-place) ──────
function onStampPointerDown(e) {
  if (e.button !== 0 && e.pointerType === 'mouse') return;
  const marker = e.currentTarget, wrap = marker.parentElement;
  const rect = wrap.querySelector('canvas').getBoundingClientRect();
  _drag = {
    marker, wrap, rect,
    grabX: e.clientX - (rect.left + parseFloat(marker.style.left)),
    grabY: e.clientY - (rect.top + parseFloat(marker.style.top)),
    w: parseFloat(marker.style.width), h: parseFloat(marker.style.height), moved: false,
  };
  try { marker.setPointerCapture(e.pointerId); } catch (_) {}
  marker.style.cursor = 'grabbing';
  marker.addEventListener('pointermove', onStampPointerMove);
  marker.addEventListener('pointerup', onStampPointerUp);
  marker.addEventListener('pointercancel', onStampPointerUp);
  e.preventDefault(); e.stopPropagation();
}

function onStampPointerMove(e) {
  if (!_drag) return;
  _drag.moved = true;
  const left = Math.max(0, Math.min(_drag.rect.width - _drag.w, e.clientX - _drag.rect.left - _drag.grabX));
  const top = Math.max(0, Math.min(_drag.rect.height - _drag.h, e.clientY - _drag.rect.top - _drag.grabY));
  _drag.marker.style.left = left + 'px';
  _drag.marker.style.top = top + 'px';
}

function onStampPointerUp(e) {
  if (!_drag) return;
  const { marker, wrap, moved } = _drag;
  marker.removeEventListener('pointermove', onStampPointerMove);
  marker.removeEventListener('pointerup', onStampPointerUp);
  marker.removeEventListener('pointercancel', onStampPointerUp);
  try { marker.releasePointerCapture(e.pointerId); } catch (_) {}
  marker.style.cursor = 'grab';
  if (moved) {
    commitStampFromMarker(marker, wrap);
    // Swallow the click the browser fires after pointerup so onPlaceClick on the
    // wrap does not ALSO re-place the stamp at the cursor.
    wrap.addEventListener('click', ev => { ev.stopPropagation(); ev.preventDefault(); }, { capture: true, once: true });
  }
  _drag = null;
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

  // Signature style tabs: click to select, plus full keyboard tablist support
  // (Left/Right/Home/End move and select per the WAI-ARIA tabs pattern).
  const tabs = Array.from(document.querySelectorAll('.ds-sig-tabs .ds-tab'));
  tabs.forEach((tab, i) => {
    tab.addEventListener('click', () => selectSigStyle(tab.dataset.sig));
    tab.addEventListener('keydown', e => {
      let next = -1;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = (i + 1) % tabs.length;
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = (i - 1 + tabs.length) % tabs.length;
      else if (e.key === 'Home') next = 0;
      else if (e.key === 'End') next = tabs.length - 1;
      if (next < 0) return;
      e.preventDefault();
      selectSigStyle(tabs[next].dataset.sig);
      tabs[next].focus();
    });
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
        ? 'You\'ll sign with your sign-in passkey. Signing keys live in the browser where you create them, so this device sets one up the first time you sign — one Face ID / Touch ID tap. No passkey here? You can sign with your authenticator code instead.'
        : 'You\'ll sign with your sign-in passkey — this device sets up your signing key with one tap the first time you sign. No passkey here? You can sign with your authenticator code instead.');
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
    // Roving tabindex: only the selected tab is in the tab order.
    t.setAttribute('tabindex', active ? '0' : '-1');
  });
  for (const k of ['typed', 'drawn', 'image']) {
    $('ds-sig-panel-' + k).hidden = (k !== style);
  }
  refreshIdentityValid();
}

// ---- drawn-signature canvas (pointer + touch), HiDPI + smoothed ----
function initDrawCanvas() {
  const cv = $('ds-sig-canvas');
  // Supersample the backing store well past the CSS box (500x160, aspect 25:8)
  // so strokes stay smooth on HiDPI screens AND survive being embedded + scaled
  // inside the PDF seal. Keeping the 25:8 ratio lets CSS height:auto stay correct.
  const DENSITY = Math.max(2, Math.ceil(hiDpiScale() * 1.5));   // dpr1->2, dpr2->3
  const BASE_W = 500, BASE_H = 160;
  cv.width = BASE_W * DENSITY;
  cv.height = BASE_H * DENSITY;
  const ctx = cv.getContext('2d');

  // Reset to a clean white sheet with the ink style. White (not transparent) so
  // the seal reads clearly on any document and the on-screen marker matches.
  const paint = () => {
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, cv.width, cv.height);
    ctx.strokeStyle = '#0b3a6a';
    ctx.lineWidth = 2.4 * DENSITY;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
  };
  paint();

  let drawing = false;
  let last = null;          // previous raw point (backing-store coords)
  let mid = null;           // previous midpoint the curve passed through
  let ink = null;           // drawn bounding box, for a tight crop on export

  function pos(ev) {
    const r = cv.getBoundingClientRect();
    const cx = ev.clientX ?? (ev.touches && ev.touches[0].clientX);
    const cy = ev.clientY ?? (ev.touches && ev.touches[0].clientY);
    return { x: (cx - r.left) * (cv.width / r.width), y: (cy - r.top) * (cv.height / r.height) };
  }
  function grow(p) {
    if (!ink) ink = { minX: p.x, minY: p.y, maxX: p.x, maxY: p.y };
    else {
      ink.minX = Math.min(ink.minX, p.x); ink.minY = Math.min(ink.minY, p.y);
      ink.maxX = Math.max(ink.maxX, p.x); ink.maxY = Math.max(ink.maxY, p.y);
    }
  }

  function start(ev) {
    ev.preventDefault();
    drawing = true;
    last = pos(ev); mid = last; grow(last);
    // A filled dot so a single tap leaves a mark (a lone quadratic never strokes).
    ctx.beginPath();
    ctx.fillStyle = '#0b3a6a';
    ctx.arc(last.x, last.y, ctx.lineWidth / 2, 0, Math.PI * 2);
    ctx.fill();
  }
  function move(ev) {
    if (!drawing) return;
    ev.preventDefault();
    const p = pos(ev);
    // Quadratic curve through the running midpoint: smooth, ink-like strokes
    // instead of the visibly faceted straight lineTo segments used before.
    const m = { x: (last.x + p.x) / 2, y: (last.y + p.y) / 2 };
    ctx.beginPath();
    ctx.moveTo(mid.x, mid.y);
    ctx.quadraticCurveTo(last.x, last.y, m.x, m.y);
    ctx.stroke();
    last = p; mid = m; grow(p);
  }
  async function end(ev) {
    if (!drawing) return;
    drawing = false;
    await exportSignature();
  }

  // Export a TIGHTLY CROPPED PNG of just the ink (+ small padding) so the seal
  // embeds a signature that fills its band, not a stamp-sized mostly-white image
  // with a tiny scribble. pdf-lib preserves aspect ratio when it scales this in.
  async function exportSignature() {
    if (!ink) { clearSig(); return; }
    const pad = ctx.lineWidth * 1.5;
    const x0 = Math.max(0, Math.floor(ink.minX - pad));
    const y0 = Math.max(0, Math.floor(ink.minY - pad));
    const x1 = Math.min(cv.width, Math.ceil(ink.maxX + pad));
    const y1 = Math.min(cv.height, Math.ceil(ink.maxY + pad));
    const w = Math.max(1, x1 - x0), h = Math.max(1, y1 - y0);
    const out = document.createElement('canvas');
    out.width = w; out.height = h;
    const octx = out.getContext('2d');
    octx.fillStyle = '#ffffff'; octx.fillRect(0, 0, w, h);
    octx.drawImage(cv, x0, y0, w, h, 0, 0, w, h);
    const blob = await new Promise((resolve) => out.toBlob(resolve, 'image/png'));
    if (!blob) return;
    const bytes = new Uint8Array(await blob.arrayBuffer());
    state.signer.sigImageBytes = bytes;
    state.signer.sigImageType = 'png';
    state.signer.sigImageDataUrl = await bytesToDataUrl(bytes, 'image/png');
    refreshIdentityValid();
  }

  function clearSig() {
    state.signer.sigImageBytes = null;
    state.signer.sigImageType = null;
    state.signer.sigImageDataUrl = null;
    refreshIdentityValid();
  }

  // Pointer Events cover mouse, touch and pen on every modern browser (iOS 13+).
  // Using ONLY pointer events avoids the double-fire you get when touch* and
  // pointer* listeners both run on a touch device. touch-action:none on the
  // canvas keeps panning/zooming from hijacking a stroke.
  cv.addEventListener('pointerdown', start);
  cv.addEventListener('pointermove', move);
  cv.addEventListener('pointerup', end);
  cv.addEventListener('pointercancel', end);
  cv.addEventListener('pointerleave', end);

  $('ds-sig-clear').addEventListener('click', () => { paint(); ink = null; clearSig(); });
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

  _reviewZoom = 1;
  // A small zoom control so the signer can inspect the document + seal at the
  // last step before signing (DocuSign/Adobe keep the document interactive).
  // The whole zoomwrap (canvas/img + the stamp overlay) is CSS-scaled together,
  // so the stamp stays glued to its spot with no repositioning math.
  const buildReviewZoom = (zoomwrap) => {
    const bar = document.createElement('div');
    bar.className = 'ds-zoom ds-rv-zoom';
    bar.innerHTML = '<button type="button" aria-label="Zoom out" data-z="out">&minus;</button>' +
      '<span class="ds-rv-pct">100%</span><button type="button" aria-label="Zoom in" data-z="in">+</button>' +
      '<button type="button" data-z="fit">Fit</button>';
    const pct = bar.querySelector('.ds-rv-pct');
    const apply = () => { zoomwrap.style.transform = 'scale(' + _reviewZoom + ')'; pct.textContent = Math.round(_reviewZoom * 100) + '%'; };
    bar.addEventListener('click', (e) => {
      const z = e.target && e.target.dataset && e.target.dataset.z; if (!z) return;
      if (z === 'out') _reviewZoom = Math.max(1, _reviewZoom / 1.25);
      else if (z === 'in') _reviewZoom = Math.min(3, _reviewZoom * 1.25);
      else _reviewZoom = 1;
      apply();
    });
    pane.insertBefore(bar, pane.firstChild);
    apply();
  };

  if (state.mode === 'pdf') {
    pane.classList.add('has-pdf');
    const pdfjs = await waitForPdfjs();
    const copy = new Uint8Array(state.doc.bytes);
    const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
    const zoomwrap = document.createElement('div');
    zoomwrap.style.cssText = 'position:relative;width:100%;transform-origin:0 0';
    pane.appendChild(zoomwrap);
    // Review shows EVERY page (capped), each with its own annotations, and the
    // seal on its page. Only the seal page gets the heavy supersample; other
    // pages render at screen resolution to keep memory sane on long documents.
    const maxPages = Math.min(pdf.numPages, MAX_PREVIEW_PAGES);
    const targetW = Math.min(340, Math.floor(pane.clientWidth || 340));
    for (let p = 1; p <= maxPages; p++) {
      const page = await pdf.getPage(p);
      const baseViewport = page.getViewport({ scale: 1 });
      const isSealPage = (p - 1 === state.stamp.pageIndex);
      const superSample = isSealPage ? Math.max(2.5, hiDpiScale()) : Math.min(1.5, Math.max(1, hiDpiScale()));
      const viewport = page.getViewport({ scale: (targetW / baseViewport.width) * superSample });
      const wrap = document.createElement('div');
      wrap.style.cssText = 'position:relative;width:100%;margin-bottom:6px';
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      // The missing line behind the white-review bug: without an explicit CSS
      // width the supersampled canvas rendered at raw pixel size and the pane
      // showed only its blank top-left corner.
      canvas.style.cssText = 'display:block;width:100%;height:auto';
      wrap.appendChild(canvas);
      zoomwrap.appendChild(wrap);
      await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
      const ratio = baseViewport.width / (wrap.getBoundingClientRect().width || targetW);   // pdf pt per displayed px
      if (isSealPage) {
        const left = state.stamp.x / ratio;
        const top  = (baseViewport.height - state.stamp.y - state.stamp.h) / ratio;
        const mock = document.createElement('div');
        mock.className = 'ds-mockup-stamp';
        mock.style.cssText = `left:${left}px;top:${top}px;width:${state.stamp.w / ratio}px;height:${state.stamp.h / ratio}px`;
        mock.innerHTML = stampInnerHtml();
        wrap.appendChild(mock);
        makeReviewStampDraggable(mock, ratio, false, baseViewport.height, state.stamp.pageIndex);
      }
      for (const ex of state.extras) {
        if (ex.pageIndex !== p - 1) continue;
        const h = extraBoxH(ex.size);
        const a = document.createElement('div');
        a.className = 'ds-anno';
        a.dataset.type = ex.type;
        a.style.cssText = `left:${ex.x / ratio}px;top:${(baseViewport.height - ex.y - h) / ratio}px;` +
          `height:${h / ratio}px;font-size:${ex.size / ratio}px;pointer-events:none;border-style:solid;background:transparent`;
        a.textContent = ex.text;
        wrap.appendChild(a);
      }
    }
    if (pdf.numPages > maxPages) {
      const more = document.createElement('div');
      more.className = 'ds-ops-dim';
      more.style.cssText = 'font-size:11px;color:var(--ink-dim);padding:6px 0';
      more.textContent = '+ ' + (pdf.numPages - maxPages) + ' more pages not previewed here; all pages are in the signed file.';
      zoomwrap.appendChild(more);
    }
    buildReviewZoom(zoomwrap);
    return;
  }

  if (state.mode === 'image' && state.signer.docImageDataUrl && state.stamp) {
    pane.classList.add('has-pdf');
    const zoomwrap = document.createElement('div');
    zoomwrap.style.cssText = 'position:relative;display:block;width:100%;transform-origin:0 0';
    const img = document.createElement('img');
    img.src = state.signer.docImageDataUrl;
    img.alt = state.doc.name;
    img.style.cssText = 'display:block;width:100%;height:auto';
    zoomwrap.appendChild(img);
    pane.appendChild(zoomwrap);
    img.onload = () => {
      const rect = img.getBoundingClientRect();
      const ratio = img.naturalWidth / rect.width;
      const left = state.stamp.x / ratio, top = state.stamp.y / ratio;
      const mock = document.createElement('div');
      mock.className = 'ds-mockup-stamp';
      mock.style.cssText = `left:${left}px;top:${top}px;width:${state.stamp.w / ratio}px;height:${state.stamp.h / ratio}px`;
      mock.innerHTML = stampInnerHtml();
      zoomwrap.appendChild(mock);
      makeReviewStampDraggable(mock, ratio, true, 0, 0);
      buildReviewZoom(zoomwrap);
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

// Make the review preview's stamp draggable so the signer can reposition it on the
// last screen before signing (one interactive document, Adobe/DocuSign-style). The
// mockup lives in a CSS-scaled zoomwrap, so screen deltas are divided by _reviewZoom
// to map back to the un-scaled local px the mockup's left/top use. ratio = doc-unit
// per local px (computed at zoom 1), so on drop we convert local px -> doc units.
function makeReviewStampDraggable(mock, ratio, isImage, pageH, pageIndex) {
  mock.style.pointerEvents = 'auto';
  mock.style.cursor = 'grab';
  mock.style.touchAction = 'none';
  let d = null;
  mock.addEventListener('pointerdown', (e) => {
    if (e.button !== 0 && e.pointerType === 'mouse') return;
    d = { x0: e.clientX, y0: e.clientY, left0: parseFloat(mock.style.left), top0: parseFloat(mock.style.top) };
    try { mock.setPointerCapture(e.pointerId); } catch (_) {}
    mock.style.cursor = 'grabbing';
    e.preventDefault(); e.stopPropagation();
  });
  mock.addEventListener('pointermove', (e) => {
    if (!d) return;
    const z = _reviewZoom || 1;
    const w = parseFloat(mock.style.width), h = parseFloat(mock.style.height);
    const parent = mock.parentElement;
    const left = Math.max(0, Math.min(parent.clientWidth - w, d.left0 + (e.clientX - d.x0) / z));
    const top = Math.max(0, Math.min(parent.clientHeight - h, d.top0 + (e.clientY - d.y0) / z));
    mock.style.left = left + 'px'; mock.style.top = top + 'px';
  });
  const up = (e) => {
    if (!d) return; d = null;
    try { mock.releasePointerCapture(e.pointerId); } catch (_) {}
    mock.style.cursor = 'grab';
    const left = parseFloat(mock.style.left), top = parseFloat(mock.style.top);
    const natX = left * ratio, natYTop = top * ratio;
    const w = parseFloat(mock.style.width) * ratio, h = parseFloat(mock.style.height) * ratio;
    if (isImage) state.stamp = { pageIndex: 0, x: natX, y: natYTop, w, h, isImage: true };
    else state.stamp = { pageIndex, x: natX, y: pageH - natYTop - h, w, h };
  };
  mock.addEventListener('pointerup', up);
  mock.addEventListener('pointercancel', up);
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
  // Solid WHITE body so the seal is always legible on any document (dark text on
  // white), instead of a near-transparent fill that let busy/dark images bleed through.
  ctx.fillStyle = '#ffffff';
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

  // Outer border + SOLID WHITE body (always legible: dark text on white, not a
  // near-transparent fill that lets the document bleed through).
  page.drawRectangle({ x: stamp.x, y: stamp.y, width: stamp.w, height: stamp.h, borderColor: navy, borderWidth: 1.2, color: white, opacity: 1 });

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

  // Bake the edit layer (text, date, highlight, note, pen strokes) as real
  // vectors on their pages. Additive to the seal; sharp at any zoom.
  if (Array.isArray(state.extras) && state.extras.length) {
    const courier = await pdfDoc.embedFont(PDFLib.StandardFonts.Courier);
    const ink = PDFLib.rgb(0.1, 0.1, 0.1);
    const penInk = PDFLib.rgb(0.043, 0.227, 0.416);                    // same navy as the seal
    const hlYellow = PDFLib.rgb(1, 0.84, 0.24);
    const noteBg = PDFLib.rgb(1, 0.968, 0.788), noteEdge = PDFLib.rgb(0.83, 0.7, 0.2);
    const pages = pdfDoc.getPages();
    for (const ex of state.extras) {
      const pg = pages[ex.pageIndex];
      if (!pg) continue;
      if (ex.type === 'highlight') {
        pg.drawRectangle({ x: ex.x, y: ex.y, width: ex.w, height: ex.h, color: hlYellow, opacity: 0.35 });
      } else if (ex.type === 'note') {
        // Box height follows the wrapped text; the note is anchored at its top
        // edge (ex.yTop), matching the on-screen behaviour while typing.
        const pad = ex.size * 0.5;
        const lineH = ex.size * TEXT_LINE_H;
        const lines = wrapPdfText(font, ex.text, ex.size, Math.max(ex.size, ex.w - pad * 2));
        const boxH = lines.length * lineH + pad * 2;
        pg.drawRectangle({ x: ex.x, y: ex.yTop - boxH, width: ex.w, height: boxH, color: noteBg, borderColor: noteEdge, borderWidth: 0.8 });
        lines.forEach((ln, i) => pg.drawText(ln, {
          x: ex.x + pad,
          y: ex.yTop - pad - (i + 1) * lineH + ex.size * 0.32,         // line-bottom -> baseline
          size: ex.size, font, color: ink,
        }));
      } else if (ex.type === 'draw') {
        for (let i = 1; i < ex.points.length; i++) {
          pg.drawLine({
            start: ex.points[i - 1], end: ex.points[i],
            thickness: ex.width, color: penInk, lineCap: PDFLib.LineCapStyle.Round,
          });
        }
      } else {
        const f = ex.type === 'date' ? courier : font;
        pg.drawText(String(ex.text || ''), {
          x: ex.x + ex.size * 0.1,
          y: ex.y + ex.size * 0.35,        // box-bottom -> text baseline (matches the on-screen box)
          size: ex.size, font: f, color: ink,
        });
      }
    }
  }

  return await pdfDoc.save();
}

// Greedy word wrap against real font metrics; a word longer than the box gets
// its own (overflowing) line rather than an infinite loop.
function wrapPdfText(font, text, size, maxW) {
  const words = String(text || '').split(/\s+/).filter(Boolean);
  const lines = [];
  let cur = '';
  for (const w of words) {
    const candidate = cur ? cur + ' ' + w : w;
    if (!cur || font.widthOfTextAtSize(candidate, size) <= maxW) cur = candidate;
    else { lines.push(cur); cur = w; }
  }
  if (cur) lines.push(cur);
  return lines.length ? lines : [''];
}

async function doSign() {
  // STEP 2 of the two-step flow: this explicit action triggers the per-document
  // passkey-PRF activation (the Face ID / Touch ID / security-key prompt fires
  // here, bound to THIS document) — step 1 was the review/preview.
  $('ds-sign-now').disabled = true;
  $('ds-sign-status').hidden = false;
  $('ds-sign-status').className = 'ds-banner';
  // Progress updates are non-urgent: announce them politely.
  $('ds-sign-status').setAttribute('aria-live', 'polite');
  const status = (t) => { $('ds-sign-status').textContent = t; };

  let ephemeralSigner = null;   // hoisted so the catch can zeroize an unconsumed TOTP secret
  try {
    // The signing key is the account's PASSKEY-protected ML-DSA-65 key. Read ONLY
    // its public half from vault metadata here (for the stamp fingerprint); the
    // secret is unlocked solely by the per-document PRF activation below.
    status('Locating your signing key...');
    // Resolve the account's signing key, or set one up inline. Happy path is one
    // passkey tap (PRF). If one-tap passkey signing isn't available — the provider
    // can't do PRF (e.g. Proton Pass), or there's no passkey at all — we fall back
    // to a TOTP-gated ephemeral signing key: a 6-digit authenticator code authorises
    // a fresh key bound to the account, used for this one signing session only.
    let signKey;
    try {
      signKey = await ensureSigningKey({ rpId: location.hostname, label: state.signer.name || 'Signing key', onStatus: status });
    } catch (e) {
      if (!e || (e.code !== 'prf_unsupported' && e.code !== 'no_passkey')) throw e;
      const code = await promptTotp('ds-pass');
      if (code == null) { const c = new Error('cancelled'); c.code = 'cancelled'; throw c; }
      status('Setting up your signing key…');
      ({ signKey, signer: ephemeralSigner } = await enrolEphemeralSigningKeyWithTotp({ label: state.signer.name || 'Signing key', totp: code, onStatus: status }));
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
    // PRF key: unlock with one passkey tap. TOTP fallback: the signer was already
    // produced (in memory) when the code was entered, so just use it.
    const signer = ephemeralSigner || await new LocalVaultSigner().activate({ vaultId: signKey.vaultId, rpId: location.hostname });
    ephemeralSigner = null;   // consumed — `signer` owns it now and disposes below
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
        extras: (state.mode === 'pdf' && state.extras.length)
          ? state.extras.map(e => ({ type: e.type, pageIndex: e.pageIndex, x: Math.round(e.x), y: Math.round(e.y), size: e.size, text: e.text }))
          : undefined,
        signature_style: state.signer.sigStyle,
        signature_image_hash: state.signer.sigImageBytes ? toHex(sha3_256(state.signer.sigImageBytes)) : null,
        signer_public_key: signKey.pk_b64, signer_pk_fingerprint: fingerprint,
        party_email_hash: act.email_hash || '',
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
        party_email_hash: act.email_hash || '',
        signature: sigB64, signed_at: dateStr, multiparty: mp,
        disclaimer: 'Post-quantum, zero-knowledge. Not eIDAS-qualified.',
      };
    }

    state.result = { stampedBytes, envelope, fingerprint };
    showDone();
  } catch (e) {
    // Zeroize any unconsumed ephemeral secret (error before it was handed to the signer).
    if (ephemeralSigner) { try { ephemeralSigner.dispose(); } catch { /* best-effort */ } ephemeralSigner = null; }
    $('ds-sign-status').className = 'ds-banner err';
    // A failed signing attempt is urgent and actionable: announce it assertively.
    $('ds-sign-status').setAttribute('aria-live', 'assertive');
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
    else if (e && (e.code === 'totp_invalid' || e.code === 'totp_required')) msg = 'That authenticator code didn’t match. Tap Sign now and enter the current 6-digit code.';
    else if (e && e.code === 'totp_unavailable') msg = 'Set up an authenticator app on your account first (Account → Two-factor), then sign with its code.';
    else if (e && (e.code === 'prf_unsupported' || e.code === 'need_passkey')) msg = 'Your passkey can’t do one-tap signing here. Tap Sign now to sign with your authenticator code instead.';
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

  // Best-effort: the signature is done and the result (stamped bytes + envelope)
  // is what the page now uses. The raw source document bytes and any drawn/
  // uploaded signature-image bytes are no longer needed, so clear them from
  // memory rather than leaving them resident until the next GC.
  clearSensitiveDocState();
}

// Zero/null the in-memory document + signature-image bytes once they are no
// longer needed (success path). Best-effort: never throws.
function clearSensitiveDocState() {
  try {
    if (state.doc && state.doc.bytes instanceof Uint8Array) { state.doc.bytes.fill(0); }
    if (state.doc) { state.doc.bytes = null; }
    if (state.signer && state.signer.sigImageBytes instanceof Uint8Array) { state.signer.sigImageBytes.fill(0); }
    if (state.signer) {
      state.signer.sigImageBytes = null;
      state.signer.sigImageDataUrl = null;
      state.signer.docImageDataUrl = null;
    }
  } catch (e) { /* best-effort */ }
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
    const dpr = hiDpiScale();
    const cssScale = targetWidth / baseViewport.width;
    const viewport = page.getViewport({ scale: cssScale * dpr });
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);        // backing store = cssW * dpr
    canvas.height = Math.floor(viewport.height);
    canvas.style.width = targetWidth + 'px';          // shown at CSS width -> crisp
    canvas.style.height = Math.floor(baseViewport.height * cssScale) + 'px';
    canvas.style.display = 'block';
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
    // Audit 1.1: every envelope is email-bound, so every co-signer needs a
    // valid email or their invite is a guaranteed dead end. Block here.
    const rErr = validateRecipients();
    if (rErr) { showRecipientsHint(rErr, true); return; }
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
  const n = idx + 1;
  row.innerHTML =
    `<input class="ds-input" type="text" data-field="label" maxlength="80" placeholder="Recipient name (required)" aria-label="Recipient ${n} name (required)" value="${escapeHtml(data.label || '')}">` +
    `<input class="ds-input" type="email" data-field="email" maxlength="200" placeholder="Email (required)" aria-label="Recipient ${n} email (required, invite is bound to it)" value="${escapeHtml(data.email || '')}">` +
    `<button class="ds-rm" type="button" data-action="remove" aria-label="Remove recipient ${n}">Remove</button>`;
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

// Audit 1.1: the co-sign invite is cryptographically bound to each recipient's
// email, so an empty/malformed address yields a slot that can never be signed.
// Returns an error string (shown to the sender) or null when every recipient
// row has a name and a syntactically valid email.
const RECIPIENT_EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function validateRecipients() {
  for (let i = 0; i < state.recipients.length; i++) {
    const r = state.recipients[i] || {};
    const n = i + 1;
    if (!r.label) return `Recipient ${n} needs a name.`;
    if (!r.email) return `Recipient ${n} needs an email address. The invite is cryptographically bound to it.`;
    if (!RECIPIENT_EMAIL_RE.test(r.email)) return `Recipient ${n}: \u201c${r.email}\u201d is not a valid email address.`;
  }
  return null;
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
  wireEditTools();
  setActive('step-mode');
}

// Edit toolbar (step-place, PDF mode): text, date, highlight, note, pen,
// plus the page tools (merge/export). Additive to the seal.
function wireEditTools() {
  const t = $('ds-add-text'), d = $('ds-add-date');
  if (t) t.addEventListener('click', () => addExtra('text'));
  if (d) d.addEventListener('click', () => addExtra('date'));
  const h = $('ds-add-highlight'), n = $('ds-add-note'), p = $('ds-tool-pen');
  if (h) h.addEventListener('click', addHighlight);
  if (n) n.addEventListener('click', addNote);
  if (p) p.addEventListener('click', () => setPenMode(!_penMode));
  wirePageTools();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();
