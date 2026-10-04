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
// Several people sign one document (2026-10-04, a paying customer: "ieder een
// paraaf op elke pagina en een handtekening op de laatste"). So:
//   - every party gets a spot of its own (js/cosign-layout.js), never the same
//     box as the others, and the paraafs stand side by side in the margin;
//   - a party may place a paraaf on every page AND a signature on one page:
//     two seal fields in one manifest, the paraaf being the one with all_pages;
//   - the signature is the signer's own: drawn with a finger or mouse, or the
//     typed name in a handwriting face, encrypted for the other parties
//     (js/parasign-ink.js) so everybody's final PDF shows it;
//   - when everyone has signed, the same link keeps working as the place to
//     download the complete PDF and the proof, for every party and the sender.
//
// The manifest itself did not change: type, page and coordinates, hashed byte
// for byte as before (relay/envelope.js normaliseAppearance).
import { sha3_256 } from '/vendor/paramant-pqc.js';
import { LocalVaultSigner, buildDocSignMessage, normaliseSigningAppearance, requestSignActivation, submitSignature, resolvePasskeySigningKey, ensureSigningKey, enrolEphemeralSigningKeyWithTotp } from '/js/parasign-signer.js?v=20';
import { promptTotp } from '/js/totp-prompt.js?v=2';
import { vaultDelete } from '/vendor/vault.js?v=5';
import { decryptDocumentCapsule, parseDocumentKeyFragment, documentKeyFragment } from '/js/parasign-document-capsule.js?v=2';
import { textBoxesFromItems, inkBoxesFromImageData, initialsFrom, normaliseRotation, userBoxesToView, viewSize, viewToUserMatrix, isIdentityGeom, geomFromBoxes } from '/js/paraaf-place.js?v=3';
import { signatureGrid, partySignatureSpot, partyParaafSpot, paraafSpotsForParties, autoSignaturePlace, textBoxesToFractions, strokesToInk } from '/js/cosign-layout.js?v=3';
import { sealInk, openInk, joinKey, parseKeyShareFragment } from '/js/parasign-ink.js?v=3';
import { makeTextKit } from '/js/pdf-text-kit.js?v=1';

const RELAY_PUBLIC = 'https://health.paramant.app';

// One file for /co-sign (Dutch, the default) and /en/co-sign. Every sentence a
// person reads goes through L(dutch, english); the page's lang attribute picks.
const EN = document.documentElement.lang === 'en';
const L = (nl, en) => (EN ? en : nl);

// The language link has to carry the query (which envelope, which party, the
// invite token) and the #fragment (the document key). A fragment never leaves
// the browser, so a plain link with it is as safe as the address bar.
{
  const langLink = document.getElementById('lang-switch-link');
  if (langLink) langLink.href = (EN ? '/co-sign' : '/en/co-sign') + location.search + location.hash;
}

// ---------- helpers ----------
function $(id) { return document.getElementById(id); }
function showStep(id) { document.querySelectorAll('.step').forEach((s) => s.classList.remove('active')); $(id).classList.add('active'); }

function showError(m) { $('error-msg').textContent = m; showStep('step-error'); }
function toHex(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s; }
function toB64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }
function escapeHtml(s) { return String(s || '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
function show(id, on) { const el = $(id); if (el) el.hidden = !on; }

// A date a person reads: "11 oktober 2026", not "2026-10-11T10:26:53.489Z".
function humanDate(iso) {
  const t = Date.parse(iso || '');
  if (!Number.isFinite(t)) return '-';
  try { return new Date(t).toLocaleDateString(EN ? 'en-GB' : 'nl-NL', { day: 'numeric', month: 'long', year: 'numeric' }); }
  catch { return new Date(t).toISOString().slice(0, 10); }
}
// The day in the reader's own time zone, as YYYY-MM-DD (a UTC slice put a
// signature made at 00:30 in Amsterdam on the day before).
function isoDay(iso) {
  const t = Date.parse(iso || '');
  if (!Number.isFinite(t)) return String(iso || '').slice(0, 10);
  const d = new Date(t);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}

// CSP here allows img-src 'self' data: (no blob:), so image previews go through a
// data: URL. PDFs render to <canvas> via the self-hosted pdf.js (worker-src 'self').
// Pages are drawn when they scroll into view, so a 120-page contract can be
// signed on page 87 without rendering all of it up front.
const MAX_PREVIEW_PAGES = 300;
function bytesToDataUrl(bytes, mime) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result);
    r.onerror = () => reject(new Error(L('het bestand kon niet worden gelezen', 'FileReader error')));
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
  // Sticky signal, so it does not matter whether the loader module ran before
  // or after this file. See js/ready.js.
  return window.ready.within('pdfjs', 10000, 'PDF.js');
}

// ---------- state ----------
let __envelope = null;
let __partyIndex = -1;
let __inviteToken = '';
let __ownerMode = false;    // the sender's result page (?result=<ref> or ?owner=<id>)
let __session = null;       // { email } when logged in as the invited recipient
let __signKey = null;       // { vaultId, pk_b64, fingerprint, hasPrf } — PUBLIC metadata only
let __ephemeralSigner = null; // set when signing via the TOTP fallback (in-memory key, no vault)
let __hashMatches = null;   // null = no file opened yet, true/false after a local hash check
let __documentBytes = null; // verified source bytes, retained only for this page session
let __docKey = null;        // the 32-byte document key, for the other parties' inks
let __appearanceTool = '';
let __appearance = { version: 1, fields: [] };
// True while __appearance is still exactly what was ASKED for (by the sender,
// or the free spot this page found) and the signer has not touched it. It is
// what tells the overlay to draw dashed "requested spots" instead of placed
// marks, and it goes false the moment the signer places, moves or clears.
let __appearanceIsSeed = false;
// The sender asked for a paraaf on every page (a paraaf field in the request
// for this party, retest T5-4): then this party cannot leave it out. UI only;
// the request already carries the field, nothing new on the wire.
let __requiredParaaf = null;
let __signedPdfBytes = null;
// The pdf.js document of the preview: page sizes and the text layer.
let __previewPdf = null;
let __pageSizes = [];       // [{width,height}] in PDF points, every page
let __pageNote = '';        // said out loud when a requested page does not exist
// The signer's own handwriting: { kind:'type', text } or { kind:'draw', path, w, h }.
let __ink = null;
const __inks = new Map();   // party index -> decrypted ink of a party that signed
let __lazyObserver = null;

function appearanceDraftKey() {
  return __envelope ? 'paramant.cosign.appearance.v2:' + __envelope.id + ':' + __partyIndex : '';
}

// null means "this signer has no draft of their own", which is what lets the
// requested position seed the editor without ever overwriting a real draft.
function loadAppearanceDraft() {
  try {
    const raw = sessionStorage.getItem(appearanceDraftKey());
    if (!raw) return null;
    const draft = normaliseSigningAppearance(JSON.parse(raw));
    return draft.fields.length ? draft : null;
  } catch { return null; }
}

function saveAppearanceDraft() {
  try {
    const key = appearanceDraftKey();
    if (!key) return;
    if (__appearance.fields.length) sessionStorage.setItem(key, JSON.stringify(__appearance));
    else sessionStorage.removeItem(key);
  } catch { /* session storage unavailable */ }
}

function withRequiredParaaf(fields) {
  if (!__requiredParaaf || fields.some(isParaaf)) return fields;
  return fields.concat({ ...__requiredParaaf });
}

function setAppearance(fields) {
  fields = withRequiredParaaf(fields);
  __appearance = normaliseSigningAppearance({ version: fields.some((f) => f.all_pages) ? 2 : 1, fields });
  __appearanceIsSeed = false;
  { const note = $('requested-note'); if (note) note.hidden = true; }
  saveAppearanceDraft();
  syncParaafBox();
}

// The paraaf is the seal with all_pages; the signature is a seal on one page.
const isParaaf = (f) => f.type === 'seal' && !!f.all_pages;
const isSignature = (f) => f.type === 'seal' && !f.all_pages;

function syncParaafBox() {
  const box = $('appearance-allpages');
  if (box) {
    box.checked = (__appearance.fields || []).some(isParaaf);
    box.disabled = !!__requiredParaaf;
  }
  const label = $('appearance-allpages-label');
  if (label) label.title = __requiredParaaf ? L('De afzender vraagt een paraaf op elke pagina.', 'The sender asks for initials on every page.') : '';
  const req = $('appearance-allpages-required');
  if (req) req.hidden = !__requiredParaaf;
}

// ---------- status: what a person reads at the top ----------
// One sentence per state, in their language, and one date: the day signing
// closes. "STATUS: VOID" and a raw ISO time told nobody anything.
function envelopeState(e) {
  if (!e) return 'unknown';
  if (e.status === 'complete') return 'complete';
  if (e.status === 'void') return e.void_reason === 'declined' ? 'declined' : 'cancelled';
  if (e.sign_expires_at && Date.parse(e.sign_expires_at) < Date.now()) return 'expired';
  return 'open';
}

function statusText(state, e) {
  switch (state) {
    case 'complete': return L('Door iedereen getekend', 'Signed by everyone');
    case 'declined': return L('Geweigerd: dit verzoek is gestopt', 'Declined: this request has stopped');
    case 'cancelled': return L('Ingetrokken door de afzender', 'Withdrawn by the sender');
    case 'expired': return L('Verlopen: ondertekenen kan niet meer', 'Expired: signing is closed');
    default: return L('Wacht op handtekeningen', 'Waiting for signatures');
  }
}

function closedExplanation(state) {
  if (state === 'declined') return L('Een ondertekenaar heeft geweigerd te tekenen. Daarmee is dit verzoek gestopt en kan niemand er nog op tekenen. Vraag de afzender om een nieuw verzoek als dat nodig is.', 'A signer declined to sign, so this request has stopped and nobody can sign it any more. Ask the sender for a new request if needed.');
  if (state === 'cancelled') return L('De afzender heeft dit verzoek ingetrokken. U hoeft niets te doen en kunt hier niet meer tekenen.', 'The sender withdrew this request. There is nothing for you to do and it can no longer be signed.');
  if (state === 'expired') return L('De termijn om te tekenen is voorbij. Vraag de afzender om een nieuw verzoek.', 'The signing period has ended. Ask the sender for a new request.');
  return '';
}

// ---------- boot ----------
async function init() {
  const params = new URLSearchParams(location.search);
  const resultRef = (params.get('result') || '').trim();
  const ownerId = (params.get('owner') || '').trim();
  if (resultRef || ownerId) return initOwner(resultRef, ownerId);

  const envId = (params.get('env') || '').trim();
  const partyIndex = parseInt(params.get('p') || '', 10);
  __inviteToken = (params.get('t') || '').trim();
  if (!envId || !Number.isInteger(partyIndex) || partyIndex < 0) {
    return showError(L('Deze link is onvolledig. De gegevens van het verzoek ontbreken of kloppen niet.', 'This link is incomplete: the request details are missing or wrong.'));
  }
  if (!/^[A-Za-z0-9_-]{20,64}$/.test(envId)) {
    return showError(L('De link bevat geen geldig verzoek.', 'The link does not contain a valid request.'));
  }
  __partyIndex = partyIndex;

  showStep('step-loading');
  $('loading-msg').textContent = L('Het verzoek wordt opgehaald...', 'Fetching the request...');

  try {
    // Ask as this party, not as a passer-by. The invite token is what entitles
    // this page to the document hash, the filename and the other parties.
    const partyQuery = '?p=' + encodeURIComponent(partyIndex) + '&t=' + encodeURIComponent(__inviteToken);
    const r = await fetch(RELAY_PUBLIC + '/v2/envelopes/' + encodeURIComponent(envId) + partyQuery);
    if (r.status === 404) return showError(L('Dit verzoek bestaat niet, is verlopen of is al gebruikt.', 'This request does not exist, has expired, or was already used.'));
    if (r.status === 429) return showError(L('Te veel verzoeken vanaf dit adres. Probeer het over een minuut opnieuw.', 'Too many requests from this address. Try again in a minute.'));
    if (!r.ok) return showError(L('Het verzoek kon nu niet worden opgehaald door een storing bij ons. Er is niets mis met uw link. Probeer het over een paar minuten opnieuw.', 'The request could not be fetched right now because of a fault on our side. Nothing is wrong with your link. Please try again in a few minutes.'));
    const data = await r.json();
    __envelope = data.envelope;
    if (__partyIndex >= __envelope.party_count) return showError(L('Deze link verwijst naar een ondertekenaar die niet in dit verzoek staat.', 'This link points to a signer who is not part of this request.'));

    const state = envelopeState(__envelope);
    const me = __envelope.parties[__partyIndex] || {};
    // Best-effort viewed-receipt, only while there is still something to view
    // for: a closed request should not get a fresh "viewed" stamp.
    if (state === 'open' && me.status !== 'signed') {
      try {
        await fetch(RELAY_PUBLIC + '/v2/envelopes/' + encodeURIComponent(envId) + '/view', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ party_index: partyIndex, token: __inviteToken }),
        });
      } catch {}
    }

    renderEnvelope();
    showStep('step-cosign');
    __session = await loadSession();

    if (state === 'declined' || state === 'cancelled' || (state === 'expired' && me.status !== 'signed')) {
      return showClosed(state);
    }
    if (state === 'complete' || me.status === 'signed') {
      return showResultForParty(envId, partyIndex);
    }
    await prepareSigning();
    if (__session) await loadDeliveredDocument(envId, partyIndex);
    else setDeliveryStatus('warn', L('Log in met het uitgenodigde e-mailadres om dit versleutelde document te openen.', 'Sign in with the invited email address to open this encrypted document.'));
  } catch (e) {
    showError(e.message || L('Er is geen verbinding. Controleer uw internet en probeer het opnieuw.', 'No connection. Check your internet and try again.'));
  }
}

function renderEnvelope() {
  const e = __envelope;
  const state = envelopeState(e);
  $('env-id').textContent = e.id;
  $('env-hash').textContent = e.doc_hash;
  $('env-filename').textContent = e.original_filename || L('(niet opgegeven)', '(not provided)');
  $('env-created').textContent = humanDate(e.created_at);
  // The one date that matters to a signer: when signing closes. The 30-day
  // retention of the record (expires_at) is not a signing deadline.
  $('env-expires').textContent = humanDate(e.sign_expires_at || e.expires_at);
  $('env-progress').textContent = e.signed_count + ' / ' + e.party_count + L(' getekend', ' signed');
  $('env-status').textContent = statusText(state, e);
  const dot = $('env-status-dot');
  dot.className = 'dot ' + (state === 'complete' ? '' : state === 'open' ? 'amber' : 'red');

  const list = $('parties-list');
  list.innerHTML = '';
  for (const p of e.parties) {
    const row = document.createElement('div');
    row.className = 'party-row' + (p.index === __partyIndex ? ' me' : '');
    const label = escapeHtml(p.label || (L('Ondertekenaar ', 'Signer ') + (p.index + 1)));
    // Allowlist the status to a known enum before putting it in the class attr
    // (and the visible label) so a hostile relay value can't break out of the
    // attribute. Unknown -> 'pending'.
    const statusClass = ['signed', 'viewed', 'declined'].includes(p.status) ? p.status : 'pending';
    const statusLabel = statusClass === 'signed' ? L('GETEKEND', 'SIGNED')
      : statusClass === 'viewed' ? L('BEKEKEN', 'VIEWED')
      : statusClass === 'declined' ? L('GEWEIGERD', 'DECLINED')
      : L('WACHT', 'PENDING');
    const idx = Number(p.index);
    row.innerHTML =
      '<div class="party-idx">' + (Number.isFinite(idx) ? idx + 1 : '') + '</div>' +
      '<div class="party-label">' + label + (p.index === __partyIndex ? L(' (u)', ' (you)') : '') + '</div>' +
      '<div class="party-status ' + statusClass + '">' + statusLabel + '</div>';
    list.appendChild(row);
  }

  const me = e.parties[__partyIndex] || {};
  $('me-label').textContent = (me.label || L('ondertekenaar ', 'signer ') + (__partyIndex + 1));
  $('verify-file').onchange = onVerifyFile;
  const go = $('requested-note-go');
  if (go) go.onclick = () => scrollToRequestedSpot('smooth');
  $('appearance-seal').onclick = () => armAppearanceTool('seal');
  $('appearance-date').onclick = () => armAppearanceTool('date');
  $('appearance-clear').onclick = () => {
    __appearance = normaliseSigningAppearance({ version: __requiredParaaf ? 2 : 1, fields: withRequiredParaaf([]) });
    __appearanceIsSeed = false;
    { const note = $('requested-note'); if (note) note.hidden = true; }
    saveAppearanceDraft();
    syncParaafBox();
    __appearanceTool = '';
    setAppearanceHelp(L('Uw zichtbare velden zijn gewist. U kunt ze opnieuw plaatsen of tekenen zonder zichtbare stempel.', 'Your visible fields were cleared. You can place them again or sign without a visible mark.'), false);
    renderAppearanceOverlays();
  };
  // The paraaf on every page is ADDED to the signature, never instead of it:
  // a contract asks for initials on every sheet and a signature on the last.
  const allPages = $('appearance-allpages');
  if (allPages) allPages.onchange = async () => {
    const on = !!allPages.checked;
    if (!__documentBytes || !isPdfBytes(__documentBytes) || !__hashMatches) {
      setAppearanceHelp(L('Open eerst het document.', 'Open the document first.'), true);
      allPages.checked = !on;
      return;
    }
    const current = __appearance.fields || [];
    let fields;
    if (on) {
      const spot = await paraafSpotForMe();
      if (!allPages.checked) return;   // unticked while the text layer was read
      fields = current.filter((f) => !isParaaf(f)).concat({ type: 'seal', page_index: 0, ...spot, all_pages: true });
    } else {
      fields = current.filter((f) => !isParaaf(f));
    }
    setAppearance(fields);
    setAppearanceHelp(on
      ? L('Op elke pagina staat nu uw paraaf in de marge, naast die van de anderen. Uw handtekening blijft op haar eigen plek.', 'Every page now has your initials in the margin, next to the others. Your signature stays where it is.')
      : L('De paraaf op elke pagina is weg. Uw handtekening blijft staan.', 'The initials on every page are gone. Your signature stays.'), false);
    renderAppearanceOverlays();
  };
  wireInkControls(me);
}

// ---------- the signer's own handwriting ----------
function wireInkControls(me) {
  const nameInput = $('ink-name');
  if (nameInput && !nameInput.value) nameInput.value = me.label || '';
  const setTyped = () => {
    const text = (nameInput && nameInput.value || '').trim() || me.label || '';
    __ink = text ? { kind: 'type', text } : null;
    renderAppearanceOverlays();
  };
  const radios = document.querySelectorAll('input[name="ink-style"]');
  const pane = (style) => {
    show('ink-type-pane', style === 'type');
    show('ink-draw-pane', style === 'draw');
  };
  radios.forEach((radio) => radio.addEventListener('change', () => {
    if (!radio.checked) return;
    pane(radio.value);
    if (radio.value === 'type') setTyped();
    else { __ink = drawPad.ink(); renderAppearanceOverlays(); }
  }));
  if (nameInput) nameInput.addEventListener('input', setTyped);
  const drawPad = initDrawPad($('ink-pad'), (ink) => { __ink = ink; renderAppearanceOverlays(); });
  const clear = $('ink-clear');
  if (clear) clear.onclick = () => { drawPad.clear(); __ink = null; renderAppearanceOverlays(); };
  pane('type');
  setTyped();
}

// A small signature pad: pointer events, so a finger, a pen and a mouse all
// work. The strokes are kept as points and turned into a vector path, which is
// what goes (encrypted) to the other parties and into the PDF.
function initDrawPad(canvas, onInk) {
  const api = { ink: () => null, clear: () => {} };
  if (!canvas) return api;
  const ctx = canvas.getContext('2d');
  let strokes = [];
  let current = null;
  const fit = () => {
    const w = canvas.clientWidth || 300, h = canvas.clientHeight || 120;
    // The same WebKit ceiling as the page canvases (cappedScale).
    const dpr = cappedScale(w, h, Math.max(1, Math.min(window.devicePixelRatio || 1, 3)));
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    redraw();
  };
  const redraw = () => {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = '#1D4ED8'; ctx.lineWidth = 2.2; ctx.lineCap = 'round'; ctx.lineJoin = 'round';
    for (const s of strokes) {
      ctx.beginPath();
      s.forEach((p, i) => (i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y)));
      if (s.length === 1) ctx.lineTo(s[0].x + 0.5, s[0].y);
      ctx.stroke();
    }
  };
  const pos = (ev) => { const r = canvas.getBoundingClientRect(); return { x: ev.clientX - r.left, y: ev.clientY - r.top }; };
  canvas.addEventListener('pointerdown', (ev) => {
    ev.preventDefault();
    try { canvas.setPointerCapture(ev.pointerId); } catch {}
    current = [pos(ev)]; strokes.push(current); redraw();
  });
  canvas.addEventListener('pointermove', (ev) => {
    if (!current) return;
    ev.preventDefault();
    const pts = (typeof ev.getCoalescedEvents === 'function' ? ev.getCoalescedEvents() : null) || [ev];
    for (const e of (pts.length ? pts : [ev])) current.push(pos(e));
    redraw();
  });
  const end = () => {
    if (!current) return;
    current = null;
    onInk(api.ink());
  };
  canvas.addEventListener('pointerup', end);
  canvas.addEventListener('pointercancel', end);
  canvas.addEventListener('pointerleave', end);
  api.ink = () => {
    // Thin the points: every third is plenty at 1000 units wide, and keeps the
    // encrypted ink well under its 32 KiB ceiling.
    const thin = strokes.map((s) => s.filter((_, i) => i % 2 === 0 || i === s.length - 1));
    const out = strokesToInk(thin);
    return out ? { kind: 'draw', ...out } : null;
  };
  api.clear = () => { strokes = []; current = null; redraw(); };
  api.drawStrokes = (list) => { strokes = list; redraw(); onInk(api.ink()); };
  window.addEventListener('resize', fit);
  requestAnimationFrame(fit);
  canvas.__pad = api;   // for the browser tests: draw without a real finger
  return api;
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

// Inline sign-quota notice on the done step (free: second signature used;
// Firm: last included signature used). The quota block is optional in the 200
// response -- an older backend sends none and nothing is shown.
function renderQuotaNote(quota) {
  const q = window.paQuotaUpgrade;
  const html = q && q.signNotice ? q.signNotice(quota) : '';
  if (!html) return;
  const host = document.getElementById('step-done');
  if (!host) return;
  let div = document.getElementById('cs-quota-note');
  if (!div) {
    div = document.createElement('div');
    div.id = 'cs-quota-note';
    const sub = host.querySelector('.sub');
    if (sub && sub.nextSibling) host.insertBefore(div, sub.nextSibling);
    else host.appendChild(div);
  }
  div.innerHTML = html;
}

async function refreshEnvelopeStatus() {
  try {
    const response = await fetch(RELAY_PUBLIC + '/v2/envelopes/' + encodeURIComponent(__envelope.id)
      + '?p=' + encodeURIComponent(__partyIndex) + '&t=' + encodeURIComponent(__inviteToken), { cache: 'no-store' });
    if (response.ok) __envelope = (await response.json()).envelope || __envelope;
  } catch { /* the accepted sign result remains authoritative */ }
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

function loginCtaHtml() {
  // Preserve the fragment: it holds (half of) the document key, and is sent to
  // neither Paramant nor the identity provider.
  const ret = encodeURIComponent(location.pathname + location.search + location.hash);
  return '<a class="btn" href="/auth/login?return=' + ret + '">' + L('Inloggen om verder te gaan', 'Sign in to continue') + '</a>'
    + '<p class="cta-note">' + L('Nog geen account? <a href="/signup">Maak er gratis een</a> met het e-mailadres waarop u deze uitnodiging kreeg. Open daarna deze link opnieuw.', 'No account yet? <a href="/en/signup">Create one for free</a> with the email address this invitation was sent to, then open this link again.') + '</p>';
}

function showClosed(state) {
  document.body.classList.add('request-closed');
  setStatus('err', closedExplanation(state));
  $('sign-confirm').disabled = true;
  show('decline-wrap', false);
}

async function prepareSigning() {
  // GATE 1 — logged in. The activation endpoint enforces (server-side) that the
  // session email equals THIS party's bound email; here we only route an invitee
  // with no session to sign in first.
  if (!__session) {
    // One step at a time: .needs-login hides the review card, the disabled sign
    // button and the authenticator panel, so signing in is the only thing on
    // screen. It comes off the moment a session resolves.
    document.body.classList.add('needs-login');
    setStatus('warn', L('Log in als de ontvanger aan wie deze uitnodiging is gestuurd. Kom daarna hier terug om te tekenen.', 'Sign in as the recipient this invite was sent to, then return here to sign.'));
    showCta(loginCtaHtml());
    return;
  }
  document.body.classList.remove('needs-login');
  $('sign-cta').hidden = true;

  // GATE 2: a signing key. If this device has none, doSign() sets one up
  // inline. Resolve now only to SHOW the fingerprint.
  try {
    __signKey = await resolvePasskeySigningKey();
  } catch (e) {
    if (e && e.code === 'no_signing_passkey') {
      __signKey = null;   // doSign() will set it up with one tap before signing
    } else {
      setStatus('err', e.message || L('Uw ondertekensleutel kon niet worden gecontroleerd.', 'Could not check your signing key.'));
      return;
    }
  }

  if (__signKey) {
    setStatus('', L('Ingelogd als ', 'Signed in as ') + (__session.email || L('uw account', 'your account')) + L('. U tekent met uw ondertekensleutel (vingerafdruk ', '. You\'ll sign with your signing key (fingerprint ') + __signKey.fingerprint + ').');
  } else {
    setStatus('', L('Ingelogd als ', 'Signed in as ') + (__session.email || L('uw account', 'your account')) + L('. U tekent met de passkey waarmee u inlogt. Die zet u met één tik klaar als u tekent. Geen passkey op dit apparaat? Dan tekent u met de code uit uw authenticator-app.', '. You\'ll sign with your sign-in passkey. It is set up with one tap when you sign. No passkey here? You can sign with your authenticator code instead.'));
  }
  $('sign-confirm').onclick = doSign;
  const decline = $('decline-btn');
  if (decline) { show('decline-wrap', true); decline.onclick = doDecline; }
  refreshSignGate();   // stays disabled until the document has been opened and checked
}

async function onVerifyFile(ev) {
  const f = ev.target.files && ev.target.files[0];
  if (!f) return;
  const buf = new Uint8Array(await f.arrayBuffer());
  await verifyAndRenderDocument(buf, 'manual');
}

function setDeliveryStatus(kind, msg) {
  const b = $('document-delivery-status');
  if (!b) return;
  b.hidden = false;
  b.className = 'banner' + (kind ? ' ' + kind : '');
  b.textContent = msg;
  // "Choose the document yourself" is an escape hatch, not a step. It appears
  // only once automatic delivery has actually failed.
  const cta = $('verify-file-cta');
  if (cta) cta.hidden = kind !== 'err';
}

// The document key, from whichever link this is: the sender's own complete
// link ('#doc=', the whole key) or the invitation mail ('#ks=', one half; the
// other half comes from the relay with the ciphertext, to this mailbox only).
function keyFromFragment() {
  const whole = parseDocumentKeyFragment(location.hash);
  if (whole) return { whole };
  const share = parseKeyShareFragment(location.hash);
  return share ? { share } : null;
}

async function fetchAndOpenCapsule(url, envId) {
  let key;
  try { key = keyFromFragment(); }
  catch (e) { throw new Error(e.message); }
  if (!key) {
    const err = new Error(L('In deze link zit geen sleutel voor het versleutelde document. Vraag de afzender om de volledige link, of kies het document hieronder zelf.', 'This link carries no key for the encrypted document. Ask the sender for the complete link, or choose the document below.'));
    err.noKey = true;
    throw err;
  }
  const r = await fetch(url, { credentials: 'include', cache: 'no-store', signal: AbortSignal.timeout(60000) });
  if (r.status === 401) throw new Error(L('Log in met het uitgenodigde e-mailadres om dit document te openen.', 'Sign in with the invited email address to open this document.'));
  if (r.status === 403) throw new Error(L('Deze uitnodiging hoort bij een ander e-mailadres. Log in met het uitgenodigde adres.', 'This invitation belongs to a different email address. Sign in with the invited address.'));
  if (r.status === 404) throw new Error(L('Het versleutelde document is niet beschikbaar. Misschien is het een ouder verzoek, of is de link onvolledig.', 'The encrypted document is unavailable. It may be an older request or the link may be incomplete.'));
  if (r.status === 410) throw new Error(L('Dit verzoek of het document is verlopen. Vraag de afzender om een nieuw verzoek.', 'This signing request or its document has expired. Ask the sender for a new request.'));
  if (r.status === 429) throw new Error(L('Het is even te druk. Probeer het over een minuut opnieuw.', 'It is busy right now. Try again in a minute.'));
  if (!r.ok) throw new Error(L('Het versleutelde document kon nu niet worden opgehaald door een storing bij ons. Probeer het over een paar minuten opnieuw.', 'The encrypted document could not be fetched right now because of a fault on our side. Please try again in a few minutes.'));
  let docKey;
  if (key.whole) docKey = key.whole;
  else {
    const other = parseKeyShareFragment('#ks=v1.' + (r.headers.get('X-Document-Key-Share') || ''));
    if (!other) throw new Error(L('De tweede helft van de sleutel ontbreekt. Vraag de afzender om de volledige link.', 'The second half of the key is missing. Ask the sender for the complete link.'));
    docKey = joinKey(key.share, other);
    key.share.fill(0); other.fill(0);
  }
  const capsule = new Uint8Array(await r.arrayBuffer());
  try {
    const delivered = await decryptDocumentCapsule({ capsule, fragment: documentKeyFragment(docKey), envelopeId: envId, docHash: __envelope.doc_hash });
    __docKey = docKey;
    return delivered;
  } finally {
    capsule.fill(0);
  }
}

async function loadDeliveredDocument(envId, partyIndex) {
  setDeliveryStatus('', L('Het versleutelde document wordt gedownload...', 'Downloading the encrypted document...'));
  try {
    const url = '/api/user/envelopes/' + encodeURIComponent(envId) + '/document?p=' + encodeURIComponent(partyIndex) + '&t=' + encodeURIComponent(__inviteToken);
    const delivered = await fetchAndOpenCapsule(url, envId);
    await verifyAndRenderDocument(delivered.bytes, 'delivery');
    if (__hashMatches) {
      setDeliveryStatus('ok', L('Het document is geopend en klopt met dit verzoek.', 'The document is open and matches this request.'));
    }
  } catch (e) {
    setDeliveryStatus('err', (e.message || L('Het document kon niet vanzelf worden geladen.', 'Automatic document loading failed.')) + (e && e.noKey ? '' : L(' Kies het document hieronder zelf.', ' Choose the document manually below.')));
  }
}

async function verifyAndRenderDocument(buf, source) {
  const h = toHex(sha3_256(buf));
  __hashMatches = (h === __envelope.doc_hash);
  __documentBytes = __hashMatches ? new Uint8Array(buf) : null;
  __appearanceTool = '';
  const b = $('verify-result');
  b.hidden = false;
  if (__hashMatches) {
    b.className = 'banner ok';
    b.textContent = source === 'delivery'
      ? L('De controle klopt. Dit is precies het document dat bij dit verzoek hoort.', 'The check matches. This is exactly the document of this request.')
      : L('De controle klopt. Dit is precies het document uit dit verzoek. Wat u hieronder ziet, is wat u ondertekent.', 'The check matches. This is exactly the document in this request: what you see below is what you sign.');
  } else {
    b.className = 'banner err';
    b.textContent = L('Dit bestand is niet het document uit dit verzoek. Onderteken het niet. Berekend: ', 'This file is not the document in this request. Do not sign it. Computed: ') + h.slice(0, 16) + L('... Verwacht: ', '... Expected: ') + __envelope.doc_hash.slice(0, 16) + '...';
  }
  await renderDocPreview(buf);
  await decryptPriorInks();
  const editor = $('appearance-editor');
  const editorOn = __hashMatches && isPdfBytes(buf) && Number(__envelope.recipe_version) >= 5 && !__ownerMode && !isResultMode();
  if (editor) editor.hidden = !editorOn;
  let seeded = false;
  if (editorOn) {
    const draft = loadAppearanceDraft();
    const seed = draft ? null : await computeSeed();
    __requiredParaaf = requiredParaafOfRequest();
    __appearance = draft ? clampToPages(draft).appearance : (seed || { version: 1, fields: [] });
    if (__requiredParaaf && !__appearance.fields.some(isParaaf)) __appearance = normaliseSigningAppearance({ version: 2, fields: withRequiredParaaf(__appearance.fields) });
    __appearanceIsSeed = !!seed;
    seeded = !!seed;
    syncParaafBox();
    if (seed) {
      setAppearanceHelp((__pageNote ? __pageNote + ' ' : '') + L('De gemarkeerde plekken zijn voor u: niemand anders tekent daar. Kies Plaats mijn handtekening om de handtekening te verplaatsen. Uw handtekening geldt voor de plek waar u echt tekent.', 'The marked spots are yours: nobody else signs there. Choose Place my signature to move the signature. Your signature binds where you actually sign.'), false);
    } else if (__pageNote) {
      setAppearanceHelp(__pageNote, true);
    }
  }
  renderAppearanceOverlays();
  // The requested spot can be on page three of a long agreement, so pointing at
  // it is not enough: take the reader there, and leave a way back to it.
  const note = $('requested-note');
  if (note) { note.hidden = !(seeded && editorOn); delete note.dataset.scrolled; }
  if (seeded && editorOn) {
    // One frame later: the canvases have only just been sized. The marker is
    // what the browser test waits for, so "we took the reader there" is
    // observed rather than timed.
    requestAnimationFrame(() => {
      scrollToRequestedSpot('instant');
      if (note) note.dataset.scrolled = '1';
    });
  }
  refreshSignGate();
}

// ---------- where this party signs, when it has not decided itself ----------
// Every spot on this page is a fraction of the page as pdf.js SHOWS it (its
// view: the visible box, turned by /Rotate). pdf.js hands the text in the PDF's
// own space, so the boxes go through the same view mapping as /sign
// (js/paraaf-place.js) before they are judged; on a turned or cropped page the
// free place under the text was otherwise computed on the wrong axis.
function geomOfPdfjsPage(page) {
  return { view: Array.from(page.view), rotate: normaliseRotation(page.rotate) };
}
function viewTextBoxes(page, items) {
  return userBoxesToView(textBoxesFromItems(items), geomOfPdfjsPage(page));
}

// The text of one page in view space, PDF points, bottom-left origin. A page
// without any text (a scan) is looked at instead of read: dark pixels on a
// small render count as text (js/paraaf-place.js inkBoxesFromImageData), so a
// paraaf or a signature never lands on the page number of a scanned contract.
const __pageBoxCache = new Map();
async function boxesOfPdfjsPage(page) {
  const key = page.pageNumber;
  if (__pageBoxCache.has(key)) return __pageBoxCache.get(key);
  let boxes = null;
  try {
    const items = (await page.getTextContent()).items;
    boxes = viewTextBoxes(page, items);
    if (!boxes.length) {
      const vp1 = page.getViewport({ scale: 1 });
      const scale = 360 / vp1.width;
      const vp = page.getViewport({ scale });
      const c = document.createElement('canvas');
      c.width = Math.round(vp.width); c.height = Math.round(vp.height);
      const ctx = c.getContext('2d');
      ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, c.width, c.height);
      await page.render({ canvasContext: ctx, viewport: vp }).promise;
      boxes = inkBoxesFromImageData(ctx.getImageData(0, 0, c.width, c.height).data, c.width, c.height, vp1.width, vp1.height);
    }
  } catch { boxes = null; }
  __pageBoxCache.set(key, boxes);
  return boxes;
}

async function textBoxesOfPage(pageIndex) {
  try {
    const page = await __previewPdf.getPage(pageIndex + 1);
    const vp = page.getViewport({ scale: 1 });
    const boxes = await boxesOfPdfjsPage(page);
    return boxes ? textBoxesToFractions(boxes, vp.width, vp.height) : null;
  } catch { return null; }
}

// The parafen of all parties, read against the text of every page: each
// party a spot of its own, none over text, none over a signature
// (js/cosign-layout.js paraafSpotsForParties). Every party computes the same
// spots from the same document, so nobody lands on somebody else.
async function textOfAllPages() {
  const pages = [], boxes = [];
  try {
    const pdf = __previewPdf;
    const n = pdf ? pdf.numPages : 0;
    for (let i = 1; i <= n; i++) {
      const page = await pdf.getPage(i);
      const vp = page.getViewport({ scale: 1 });
      pages.push({ width: vp.width, height: vp.height });
      boxes.push(await boxesOfPdfjsPage(page));
    }
  } catch { /* fall through: no text layer, bottom right */ }
  return { pages, boxes: pages.length ? boxes : null };
}

// Where party `index` signs when nobody pointed at a spot: under the text of
// the last page if all signatures fit there free of text, else on a signature
// sheet after the last page. The same answer for every party.
async function autoSignatureField(index, count) {
  const lastPage = Math.max(0, __pageSizes.length - 1);
  const boxes = await textBoxesOfPage(lastPage);
  const placed = autoSignaturePlace({ index, count, pageCount: __pageSizes.length, textBoxes: boxes });
  return { type: 'seal', page_index: placed.page_index, ...placed.spot };
}

// The signature boxes of every party on the document's own pages, so a paraaf
// never covers one (acceptance test: with three signers the third signature
// lay over the parafen of the first two). Deterministic from the envelope and
// the document alone.
async function signatureBoxesOfAllParties() {
  const e = __envelope || {};
  const count = Math.max(1, Number(e.party_count) || 1);
  let req = null;
  try { req = e.requested_appearance ? normaliseSigningAppearance(e.requested_appearance) : null; } catch { req = null; }
  const sig = req && req.fields ? req.fields.find(isSignature) : null;
  const out = [];
  if (sig) for (let i = 0; i < count; i++) out.push(partySignatureSpot({ anchor: sig, index: i, count }));
  else for (let i = 0; i < count; i++) { const f = await autoSignatureField(i, count); if (f.page_index < __pageSizes.length) out.push(f); }
  for (const f of (__appearance && __appearance.fields) || []) if (isSignature(f) && f.page_index < __pageSizes.length) out.push(f);
  for (const party of (e.parties || [])) for (const f of ((party.appearance && party.appearance.fields) || [])) if (isSignature(f) && f.page_index < __pageSizes.length) out.push(f);
  return out;
}

async function paraafSpotForMe() {
  const { pages, boxes } = await textOfAllPages();
  const count = Math.max(1, Number(__envelope.party_count) || 1);
  const spots = paraafSpotsForParties({ pages, textBoxesPerPage: boxes, count, avoid: await signatureBoxesOfAllParties() });
  return spots[Math.max(0, Math.min(count - 1, __partyIndex))];
}

function cornerNameOf(box) {
  return (box.x + box.w / 2 > 0.5 ? 'rechts' : 'links') + (box.y + box.h / 2 > 0.5 ? 'onder' : 'boven');
}

// A field on a page this document does not have is not dropped in silence:
// it moves to the last page, and the signer is told.
function clampToPages(appearance) {
  const last = Math.max(0, __pageSizes.length - 1);
  let moved = 0;
  const fields = (appearance.fields || []).map((f) => {
    // last + 1 is the signature sheet after the document (autoSignaturePlace).
    if (f.all_pages || f.page_index <= last || f.page_index === last + 1) return f;
    moved = Math.max(moved, f.page_index + 1);
    return { ...f, page_index: last };
  });
  if (moved) {
    __pageNote = L('De afzender vroeg een handtekening op pagina ' + moved + ', maar dit document heeft ' + (last + 1) + (last === 0 ? ' pagina' : " pagina's") + '. De plek staat nu op de laatste pagina.',
      'The sender asked for a signature on page ' + moved + ', but this document has ' + (last + 1) + ' page' + (last === 0 ? '' : 's') + '. The spot is now on the last page.');
  }
  return { appearance: normaliseSigningAppearance({ version: fields.some((f) => f.all_pages) ? 2 : 1, fields }), moved };
}

// The paraaf the sender asked of THIS party, or null.
function requiredParaafOfRequest() {
  const e = __envelope || {};
  if (!e.requested_for_party || !e.requested_appearance) return null;
  let req = null;
  try { req = normaliseSigningAppearance(e.requested_appearance); } catch { return null; }
  const par = (req.fields || []).find(isParaaf);
  return par ? { type: 'seal', page_index: 0, x: par.x, y: par.y, w: par.w, h: par.h, all_pages: true } : null;
}

async function computeSeed() {
  const e = __envelope;
  const count = Math.max(1, Number(e.party_count) || 1);
  const index = __partyIndex;
  const lastPage = Math.max(0, __pageSizes.length - 1);
  let requested = null;
  try { requested = e.requested_appearance ? normaliseSigningAppearance(e.requested_appearance) : null; } catch { requested = null; }
  if (requested && !requested.fields.length) requested = null;

  // 1. The sender chose a spot for THIS party: take it as it is. A request
  //    with only the paraaf (the sender asked for initials but pointed at no
  //    spot) gets a free place for the signature, as in case 3.
  if (requested && e.requested_for_party) {
    const clamped = clampToPages(requested).appearance;
    if (clamped.fields.some(isSignature)) return clamped;
    const sig = await autoSignatureField(index, count);
    return normaliseSigningAppearance({ version: 2, fields: [sig, ...clamped.fields] });
  }

  const fields = [];
  if (requested) {
    // 2. One box for everybody (an older request, or the API): the box is
    //    where the signatures go, and each party takes its own slot from it.
    const clamped = clampToPages(requested).appearance;
    const sig = clamped.fields.find(isSignature);
    const par = clamped.fields.find(isParaaf);
    if (sig) fields.push({ type: 'seal', page_index: sig.page_index, ...partySignatureSpot({ anchor: sig, index, count }) });
    if (par) {
      // The parafen are placed against the text of every page, not slid
      // along a row from one corner (with 3+ parties that row ran over text).
      const { pages, boxes } = await textOfAllPages();
      const avoid = await signatureBoxesOfAllParties();
      const spot = pages.length
        ? paraafSpotsForParties({ pages, textBoxesPerPage: boxes, count, avoid })[index]
        : partyParaafSpot({ corner: { ...par, corner: cornerNameOf(par) }, index, count });
      fields.push({ type: 'seal', page_index: 0, x: spot.x, y: spot.y, w: spot.w, h: spot.h, all_pages: true });
    }
    if (!sig && !par) return clamped;
    if (!sig) fields.unshift(await autoSignatureField(index, count));
  } else {
    // 3. Nothing asked: a free place under the text of the last page, a slot
    //    per party so nobody lands on somebody else.
    fields.push(await autoSignatureField(index, count));
  }
  return normaliseSigningAppearance({ version: fields.some((f) => f.all_pages) ? 2 : 1, fields });
}

// ---------- document preview (zero-knowledge: the bytes the signer holds, never the relay) ----------
async function renderDocPreview(bytes) {
  const host = $('doc-preview');
  host.hidden = false;
  host.innerHTML = '<div class="doc-preview-meta">' + L('Het document wordt getoond...', 'Rendering document...') + '</div>';
  try {
    if (isPdfBytes(bytes)) {
      await renderPdfPreview(bytes, host);
    } else {
      const mime = guessMimeFromMagic(bytes);
      if (mime && mime.startsWith('image/')) {
        await renderImagePreview(bytes, mime, host);
      } else {
        host.innerHTML = '<div class="doc-preview-meta">' + L('Dit soort bestand kan de browser niet tonen. De controle hierboven bewijst al dat dit precies het document uit dit verzoek is. Open het in uw eigen programma en lees het voordat u tekent.', 'This file type cannot be shown in the browser. The check above already proves it is the exact document in this request: open it in your own app to read it before you sign.') + '</div>';
      }
    }
  } catch (e) {
    host.innerHTML = '<div class="doc-preview-meta">' + L('Er kan geen voorbeeld worden getoond (', 'Could not render a preview (') + escapeHtml(e.message || L('fout', 'error')) + L('). De controle hierboven zegt nog steeds of dit het juiste bestand is.', '). The check above still tells you whether this is the right file.') + '</div>';
  }
}

// WebKit (every browser on an iPhone) silently draws NOTHING into a canvas
// wider or taller than 4096 px, or larger than about 16.7 million pixels: no
// error, just an empty page. devicePixelRatio 3 on a wide page gets there. So
// the backing store is capped, and after drawing we look whether anything
// landed; a blank canvas is retried at screen resolution and otherwise said
// out loud instead of showing an empty page as if it were the document.
const CANVAS_MAX_SIDE = 4096;
const CANVAS_MAX_AREA = 16_000_000;
export function cappedScale(cssW, cssH, dpr) {
  let k = Math.max(1, dpr || 1);
  if (cssW * k > CANVAS_MAX_SIDE) k = CANVAS_MAX_SIDE / cssW;
  if (cssH * k > CANVAS_MAX_SIDE) k = Math.min(k, CANVAS_MAX_SIDE / cssH);
  if (cssW * cssH * k * k > CANVAS_MAX_AREA) k = Math.min(k, Math.sqrt(CANVAS_MAX_AREA / (cssW * cssH)));
  return Math.max(0.1, k);
}

// True when nothing at all was drawn: pdf.js paints the page white first, so
// a rendered page is opaque; WebKit's refused canvas reads back fully clear.
function canvasLooksBlank(canvas) {
  try {
    const ctx = canvas.getContext('2d');
    const w = canvas.width, h = canvas.height;
    for (let gy = 1; gy < 8; gy++) {
      for (let gx = 1; gx < 8; gx++) {
        const px = ctx.getImageData(Math.floor(w * gx / 8), Math.floor(h * gy / 8), 1, 1).data;
        if (px[3] !== 0) return false;
      }
    }
    return true;
  } catch { return false; }
}

async function renderPdfPage(wrap) {
  if (wrap.dataset.rendered) return;
  wrap.dataset.rendered = '1';
  const i = Number(wrap.dataset.pageIndex) + 1;
  const page = await __previewPdf.getPage(i);
  const dpr = Math.max(1, Math.min(window.devicePixelRatio || 1, 3));
  const targetWidth = parseFloat(wrap.style.maxWidth) || 600;
  const base = page.getViewport({ scale: 1 });
  const cssScale = targetWidth / base.width;
  const canvas = wrap.querySelector('canvas');
  const draw = async (k) => {
    const viewport = page.getViewport({ scale: cssScale * k });
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  };
  await draw(cappedScale(targetWidth, base.height * cssScale, dpr));
  if (canvasLooksBlank(canvas)) {
    await draw(1);
    if (canvasLooksBlank(canvas)) {
      wrap.dataset.blank = '1';
      const note = document.createElement('div');
      note.className = 'doc-preview-meta page-blank';
      note.textContent = L('Deze pagina kan dit apparaat niet tonen. Het document zelf is in orde en de controle hierboven klopt; open het op een ander apparaat om deze pagina te lezen voordat u tekent.', 'This device cannot display this page. The document itself is fine and the check above matches; open it on another device to read this page before you sign.');
      wrap.appendChild(note);
    }
  }
}

async function renderPdfPreview(bytes, host) {
  const pdfjs = await waitForPdfjs();
  const copy = new Uint8Array(bytes);   // pdf.js detaches the buffer it is handed
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;
  __previewPdf = pdf;
  host.innerHTML = '';
  const maxPages = Math.min(pdf.numPages, MAX_PREVIEW_PAGES);
  __pageSizes = [];
  if (__lazyObserver) { try { __lazyObserver.disconnect(); } catch {} }
  __lazyObserver = typeof IntersectionObserver === 'function'
    ? new IntersectionObserver((entries) => {
      for (const entry of entries) if (entry.isIntersecting) renderPdfPage(entry.target).catch(() => {});
    }, { root: host, rootMargin: '600px 0px' })
    : null;
  for (let i = 1; i <= maxPages; i++) {
    const page = await pdf.getPage(i);
    const base = page.getViewport({ scale: 1 });
    __pageSizes.push({ width: base.width, height: base.height });
    // Fit to width. Wrapper, canvas and .appearance-layer are one and the same
    // box, so a click fraction is exactly a fraction of the PDF page.
    const contentWidth = Math.max(200, (host.clientWidth || window.innerWidth) - 16);
    const targetWidth = Math.min(820, contentWidth);
    const wrap = document.createElement('div');
    wrap.className = 'doc-page appearance-page';
    wrap.dataset.pageIndex = String(i - 1);
    wrap.style.maxWidth = targetWidth + 'px';
    const canvas = document.createElement('canvas');
    // The page's shape before it is drawn, so the layout (and the requested
    // spot three pages down) is right before anything renders.
    canvas.width = Math.round(base.width); canvas.height = Math.round(base.height);
    canvas.style.width = '100%';
    canvas.style.height = 'auto';
    canvas.style.aspectRatio = base.width + ' / ' + base.height;
    canvas.style.display = 'block';
    wrap.appendChild(canvas);
    const layer = document.createElement('div');
    layer.className = 'appearance-layer';
    wrap.appendChild(layer);
    wrap.addEventListener('click', placeAppearanceField);
    host.appendChild(wrap);
    // The first pages at once, the rest when they come near the view.
    if (i <= 3 || !__lazyObserver) await renderPdfPage(wrap);
    else __lazyObserver.observe(wrap);
  }
  const meta = document.createElement('div');
  meta.className = 'doc-preview-meta';
  meta.textContent = pdf.numPages + (EN ? (' page' + (pdf.numPages === 1 ? '' : 's')) : (pdf.numPages === 1 ? ' pagina' : " pagina's")) +
    (pdf.numPages > maxPages ? L(' (de eerste ', ' (showing first ') + maxPages + L(' worden getoond)', ')') : '');
  host.appendChild(meta);
}

async function renderImagePreview(bytes, mime, host) {
  const url = await bytesToDataUrl(bytes, mime);
  host.innerHTML = '';
  const wrap = document.createElement('div');
  wrap.className = 'doc-page';
  const img = document.createElement('img');
  img.alt = L('Document om te ondertekenen', 'Document to sign');
  img.src = url;
  wrap.appendChild(img);
  host.appendChild(wrap);
}

// Bring the requested box into view. scrollIntoView walks every scrollable
// ancestor, so this moves the preview's own scroller AND the page.
function scrollToRequestedSpot(behavior) {
  const node = document.querySelector('.appearance-field.requested.seal:not(.paraaf)') || document.querySelector('.appearance-field.requested');
  if (!node) return false;
  const wrap = node.closest('.doc-page');
  if (wrap) renderPdfPage(wrap).catch(() => {});
  try { node.scrollIntoView({ behavior: behavior || 'smooth', block: 'center', inline: 'center' }); }
  catch { node.scrollIntoView(true); }
  return true;
}

function setAppearanceHelp(message, active) {
  const help = $('appearance-help');
  if (!help) return;
  help.textContent = message;
  help.classList.toggle('active', !!active);
}

function armAppearanceTool(type) {
  if (!__documentBytes || !isPdfBytes(__documentBytes)) return;
  __appearanceTool = type;
  setAppearanceHelp(type === 'seal'
    ? L('Handtekening gekozen. Klik op de plek in het document waar uw handtekening moet komen.', 'Signature selected. Click the spot in the document where your signature should go.')
    : L('Datum gekozen. Klik op de plek in het document waar de datum van ondertekening moet komen.', 'Date selected. Click the spot in the document where the signing date should go.'), true);
}

function placeAppearanceField(event) {
  if (!__appearanceTool || !__hashMatches) return;
  if (event.target.closest('.appearance-remove')) return;
  const page = event.currentTarget;
  const rect = page.getBoundingClientRect();
  if (!rect.width || !rect.height) return;
  const grid = signatureGrid(__envelope.party_count);
  const size = __appearanceTool === 'seal' ? { w: grid.w, h: grid.h } : { w: 0.16, h: 0.03 };
  const px = (event.clientX - rect.left) / rect.width;
  const py = (event.clientY - rect.top) / rect.height;
  const field = {
    type: __appearanceTool,
    page_index: Number(page.dataset.pageIndex),
    x: Math.max(0, Math.min(1 - size.w, px - size.w / 2)),
    y: Math.max(0, Math.min(1 - size.h, py - size.h / 2)),
    w: size.w,
    h: size.h,
  };
  // Placing makes this the signer's own manifest. What was asked stays where
  // it was (a placed signature does not take the paraaf away), the field of
  // the same kind moves.
  const base = __appearance.fields || [];
  const fields = base.filter((item) => field.type === 'seal' ? !isSignature(item) : item.type !== field.type).concat(field);
  setAppearance(fields);
  __appearanceTool = '';
  setAppearanceHelp(field.type === 'seal'
    ? L('Uw handtekening staat. Kies opnieuw Plaats mijn handtekening om hem te verplaatsen.', 'Your signature is placed. Choose Place my signature again to move it.')
    : L('De datum staat. Kies opnieuw Plaats datum om hem te verplaatsen.', 'The signing date is placed. Choose Place date again to move it.'), false);
  renderAppearanceOverlays();
}

// ---------- how a mark looks (screen and PDF share these words) ----------
function partyName(party) {
  return String((party && party.label) || L('Ondertekenaar', 'Signer'));
}
function captionFor(party, dateIso) {
  return partyName(party) + (dateIso ? ' · ' + isoDay(dateIso) : '');
}
function inkFor(party, current) {
  if (current) return __ink || { kind: 'type', text: partyName(party) };
  return __inks.get(party.index) || { kind: 'type', text: partyName(party) };
}

function inkSvg(ink) {
  return '<svg viewBox="-8 -8 ' + (ink.w + 16) + ' ' + (ink.h + 16) + '" preserveAspectRatio="xMidYMid meet" aria-hidden="true"><path d="' + escapeHtml(ink.path) + '" fill="none" stroke="#1D4ED8" stroke-width="' + Math.max(6, ink.w / 110) + '" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

function addAppearanceNode(layer, field, party, current, requested) {
  const node = document.createElement('div');
  const paraaf = isParaaf(field);
  node.className = 'appearance-field ' + field.type + (paraaf ? ' paraaf' : '') + (requested ? ' requested' : current ? ' mine' : ' prior');
  node.style.left = (field.x * 100) + '%';
  node.style.top = (field.y * 100) + '%';
  node.style.width = (field.w * 100) + '%';
  node.style.height = (field.h * 100) + '%';
  if (requested) {
    // A requested box names nobody and carries no date: nothing has been
    // signed there yet.
    // Text sits in a child: container units size against the box, and a box
    // cannot query its own size.
    const lbl = document.createElement('span');
    lbl.className = 'lbl';
    lbl.textContent = paraaf ? L('Uw paraaf', 'Your initials') : field.type === 'date' ? L('Datum', 'Date') : L('Uw handtekening komt hier', 'Your signature goes here');
    node.appendChild(lbl);
  } else if (field.type === 'date') {
    const lbl = document.createElement('span');
    lbl.className = 'lbl';
    lbl.textContent = current ? isoDay(new Date().toISOString()) : isoDay(party.signed_at);
    node.appendChild(lbl);
  } else {
    const ink = inkFor(party, current);
    const mark = document.createElement('div');
    mark.className = 'ink';
    if (paraaf) {
      if (ink.kind === 'draw') mark.innerHTML = inkSvg(ink);
      else mark.textContent = initialsFrom(ink.text || partyName(party)) || '·';
    } else if (ink.kind === 'draw') {
      mark.innerHTML = inkSvg(ink);
    } else {
      mark.textContent = ink.text;
    }
    // A long name shrinks to fit the width instead of running out of the box.
    if (ink.kind !== 'draw') mark.style.setProperty('--len', String(Math.max(4, (paraaf ? (initialsFrom(ink.text) || '·') : ink.text).length)));
    node.appendChild(mark);
    if (!paraaf) {
      const cap = document.createElement('div');
      cap.className = 'cap';
      cap.textContent = captionFor(party, current ? new Date().toISOString() : party.signed_at);
      node.appendChild(cap);
    }
  }
  if (current && !requested && !(paraaf && __requiredParaaf)) {
    // The × gets room of its own, so it never covers the name (retest T5-12b).
    node.classList.add('has-remove');
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'appearance-remove';
    remove.setAttribute('aria-label', paraaf ? L('Verwijder de paraaf op elke pagina', 'Remove the initials on every page') : field.type === 'date' ? L('Verwijder het datumveld', 'Remove the date field') : L('Verwijder het handtekeningveld', 'Remove the signature field'));
    remove.textContent = '×';
    remove.addEventListener('click', (event) => {
      event.stopPropagation();
      setAppearance((__appearance.fields || []).filter((item) => !(item.type === field.type && !!item.all_pages === !!field.all_pages)));
      renderAppearanceOverlays();
    });
    node.appendChild(remove);
  }
  layer.appendChild(node);
}

// The signature sheet after the last page, shown when any signature sits on
// it (autoSignaturePlace puts them there when the last page has no room free
// of text). It is a page of the readable copy only: the signed document is the
// original, unchanged.
function sheetNeeded() {
  const n = __pageSizes.length;
  if (!n) return false;
  const on = (f) => !f.all_pages && Number(f.page_index) === n;
  if ((__appearance.fields || []).some(on)) return true;
  return (__envelope?.parties || []).some((p) => p.status === 'signed' && p.appearance && (p.appearance.fields || []).some(on));
}

function syncSheetPreview() {
  const host = $('doc-preview');
  if (!host) return;
  const existing = host.querySelector('.doc-page.sheet-page');
  if (!sheetNeeded()) { if (existing) existing.remove(); return; }
  if (existing) return;
  const n = __pageSizes.length;
  const last = __pageSizes[n - 1];
  const lastWrap = host.querySelector('.doc-page[data-page-index="' + (n - 1) + '"]');
  const wrap = document.createElement('div');
  wrap.className = 'doc-page appearance-page sheet-page';
  wrap.dataset.pageIndex = String(n);
  if (lastWrap) wrap.style.maxWidth = lastWrap.style.maxWidth;
  wrap.style.aspectRatio = last.width + ' / ' + last.height;
  const head = document.createElement('div');
  head.className = 'sheet-head';
  head.textContent = L('Handtekeningen bij ', 'Signatures for ') + String(__envelope?.original_filename || 'document');
  wrap.appendChild(head);
  const layer = document.createElement('div');
  layer.className = 'appearance-layer';
  wrap.appendChild(layer);
  wrap.addEventListener('click', placeAppearanceField);
  if (lastWrap && lastWrap.nextSibling) host.insertBefore(wrap, lastWrap.nextSibling); else host.appendChild(wrap);
}

function renderAppearanceOverlays() {
  syncSheetPreview();
  const pages = Array.from(document.querySelectorAll('#doc-preview .doc-page[data-page-index]'));
  if (!pages.length) return;
  const docPages = pages.filter((node) => !node.classList.contains('sheet-page'));
  for (const page of pages) {
    const layer = page.querySelector('.appearance-layer');
    if (layer) layer.innerHTML = '';
  }
  // A field with all_pages is one signed instruction, drawn once per page: the
  // preview has to show every repeat.
  const add = (field, party, current, requested) => {
    const targets = field.all_pages
      ? docPages
      : pages.filter((node) => Number(node.dataset.pageIndex) === Math.min(Number(field.page_index), pages.length - 1));
    for (const page of targets) {
      const layer = page.querySelector('.appearance-layer');
      if (layer) addAppearanceNode(layer, field, party, current, requested);
    }
  };
  for (const party of (__envelope?.parties || [])) {
    if ((party.index === __partyIndex && !isResultMode()) || party.status !== 'signed' || !party.appearance) continue;
    for (const field of (party.appearance.fields || [])) add(field, party, false);
  }
  if (isResultMode() || __ownerMode) return;
  const me = (__envelope?.parties || [])[__partyIndex] || {};
  for (const field of (__appearance.fields || [])) add(field, me, true, __appearanceIsSeed);
}

async function decryptPriorInks() {
  if (!__docKey || !__envelope) return;
  for (const party of (__envelope.parties || [])) {
    if (party.status !== 'signed' || !party.ink || __inks.has(party.index)) continue;
    const ink = await openInk({ sealed: party.ink, documentKey: __docKey, envelopeId: __envelope.id, partyIndex: party.index });
    if (ink) __inks.set(party.index, ink);
  }
}

function downloadBytes(bytes, filename, type) {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// The standard PDF fonts speak WinAnsi only. A character outside it (a name
// in Greek, a stray emoji) becomes '?' instead of failing the whole PDF.

// The complete PDF: every party that signed, each at its own spots, with its
// own handwriting. No white box over the text any more: the ink, a hairline
// and a small caption, the way a signature sits on paper.
export async function buildSignedPdf(currentResult) {
  if (!__documentBytes || !isPdfBytes(__documentBytes) || !window.PDFLib) return null;
  const records = [];
  for (const party of (__envelope.parties || [])) {
    if (party.status !== 'signed' || !party.appearance) continue;
    if (currentResult && party.index === __partyIndex) continue;
    records.push({ party, appearance: party.appearance, ink: __inks.get(party.index) || null });
  }
  if (currentResult) {
    const currentParty = (__envelope.parties || [])[__partyIndex] || {};
    records.push({
      party: { ...currentParty, signed_at: currentResult.signed_at, signer_pk_hash: (__signKey?.fingerprint || '') },
      appearance: currentResult.appearance || __appearance,
      ink: __ink,
    });
  }
  return renderPdfWithRecords(records);
}

// The view geometry of every page, as pdf.js showed it in the preview; a page
// pdf.js did not read falls back to pdf-lib's boxes under the same rule
// (geomFromBoxes), the way /sign does it.
async function pageGeoms(pdfLibPages) {
  const out = [];
  for (let i = 0; i < pdfLibPages.length; i++) {
    let g = null;
    if (__previewPdf && i < __previewPdf.numPages) {
      try { g = geomOfPdfjsPage(await __previewPdf.getPage(i + 1)); } catch { g = null; }
    }
    if (!g) {
      const pg = pdfLibPages[i];
      const box = (b) => { try { const r = b(); return [r.x, r.y, r.x + r.width, r.y + r.height]; } catch { return null; } };
      let rot = 0; try { rot = pg.getRotation().angle; } catch { /* unturned */ }
      g = geomFromBoxes(box(() => pg.getMediaBox()), box(() => pg.getCropBox()), rot);
    }
    out.push(g);
  }
  return out;
}

async function renderPdfWithRecords(records) {
  const { PDFDocument, StandardFonts, rgb, LineCapStyle, pushGraphicsState, popGraphicsState, concatTransformationMatrix } = window.PDFLib;
  const pdf = await PDFDocument.load(__documentBytes, { ignoreEncryption: false });
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const script = await pdf.embedFont(StandardFonts.TimesRomanItalic);
  const inkColor = rgb(0.114, 0.306, 0.847);     // #1D4ED8, the preview's ink
  const capColor = rgb(0.05, 0.11, 0.2);
  const dimColor = rgb(0.35, 0.42, 0.5);
  const docPageCount = pdf.getPageCount();
  // A signature on page index docPageCount sits on the signature sheet: one
  // extra page at the end of this readable copy, the size of the last page.
  const onSheet = records.some((r) => (r.appearance.fields || []).some((f) => !f.all_pages && Number(f.page_index) === docPageCount));
  // Names in any script: Noto Sans through fontkit, as /sign does
  // (js/pdf-text-kit.js). "Ayşe Yılmaz" used to come out as "Ay?e Y?lmaz".
  const kit = makeTextKit(window.PDFLib, pdf, { regular, bold: regular, italic: script, mono: regular });
  const texts = [String(__envelope.original_filename || '')];
  for (const r of records) {
    texts.push(partyName(r.party), captionFor(r.party, r.party.signed_at), isoDay(r.party.signed_at));
    if (r.ink && r.ink.kind === 'type') texts.push(r.ink.text, initialsFrom(r.ink.text));
    texts.push(initialsFrom(partyName(r.party)));
  }
  await kit.prepare(texts.filter(Boolean));
  if (onSheet) {
    const lastSize = pdf.getPage(docPageCount - 1).getSize();
    const sheet = pdf.addPage([lastSize.width, lastSize.height]);
    const title = L('Handtekeningen', 'Signatures');
    await kit.draw(sheet, title, { x: lastSize.width * 0.07, y: lastSize.height * 0.93, size: 16, role: 'bold', color: capColor });
    const sub = L('Bij: ', 'For: ') + String(__envelope.original_filename || 'document') + ' (' + docPageCount + (docPageCount === 1 ? L(' pagina', ' page') : L(" pagina's", ' pages')) + ')';
    await kit.draw(sheet, sub.slice(0, 120), { x: lastSize.width * 0.07, y: lastSize.height * 0.93 - 18, size: 9, color: dimColor });
  }
  const pages = pdf.getPages();
  // Every field is a fraction of the page as the signer SAW it (pdf.js view:
  // the visible box turned by /Rotate). On a turned or cropped page that view
  // is mapped onto the PDF's own space with one matrix, and everything (the
  // signature, the paraaf, the drawn ink, the caption) is drawn upright in it.
  // An ordinary page is the identity and is drawn exactly as before.
  const geoms = await pageGeoms(pages);
  const inViewAsync = async (page, fn) => {
    const g = geoms[pages.indexOf(page)];
    if (!g || isIdentityGeom(g)) { await fn(page); return; }
    page.pushOperators(pushGraphicsState(), concatTransformationMatrix(...viewToUserMatrix(g)));
    try { await fn(page); } finally { page.pushOperators(popGraphicsState()); }
  };

  const drawInk = async (page, ink, box, fallbackText) => {
    if (ink && ink.kind === 'draw') {
      const scale = Math.min(box.w / (ink.w + 16), box.h / (ink.h + 16));
      const w = ink.w * scale, h = ink.h * scale;
      page.drawSvgPath(ink.path, {
        x: box.x + (box.w - w) / 2,
        y: box.y + box.h - (box.h - h) / 2,
        scale,
        borderColor: inkColor,
        borderWidth: Math.max(0.8, Math.min(1.6, box.h / 22)) / scale,
        borderLineCap: LineCapStyle ? LineCapStyle.Round : undefined,
      });
      return;
    }
    const text = String((ink && ink.text) || fallbackText || '').replace(/[\r\n\t]+/g, ' ').slice(0, 80);
    const size = kitFit(text, 'italic', box.w, Math.min(26, box.h * 0.9), 5);
    const tw = kit.width(text, size, 'italic');
    await kit.draw(page, text, { x: box.x + Math.max(0, (box.w - tw) / 2), y: box.y + Math.max(1, (box.h - size) / 2 + size * 0.18), size, role: 'italic', color: inkColor });
  };
  const kitFit = (text, role, maxW, maxSize, minSize) => {
    let size = maxSize;
    while (size > minSize && kit.width(text, size, role) > maxW) size -= 0.5;
    return size;
  };

  for (const record of records) {
    for (const field of (record.appearance.fields || [])) {
      // all_pages repeats one signed field at the same relative spot on every
      // page. A page this document does not have moves to the last page, as
      // the preview showed it, instead of vanishing.
      const targets = field.all_pages ? pages.slice(0, docPageCount) : [pages[Math.min(field.page_index, pages.length - 1)]];
      for (const target of targets) {
        if (!target) continue;
        await inViewAsync(target, async (page) => {
          const g = geoms[pages.indexOf(page)];
          const { width, height } = g ? viewSize(g) : page.getSize();
          const x = field.x * width;
          const y = height - ((field.y + field.h) * height);
          const w = field.w * width;
          const h = field.h * height;
          if (field.type === 'date') {
            const text = isoDay(record.party.signed_at);
            await kit.draw(page, text, { x: x + 2, y: y + Math.max(2, h * 0.25), size: Math.max(7, Math.min(11, h * 0.6)), color: capColor });
          } else if (field.all_pages) {
            // The paraaf: initials (or the drawn mark, small) over a hairline.
            const ink = record.ink && record.ink.kind === 'draw' ? record.ink : { kind: 'type', text: initialsFrom((record.ink && record.ink.text) || partyName(record.party)) || '·' };
            await drawInk(page, ink, { x, y: y + h * 0.18, w, h: h * 0.8 }, '·');
            page.drawLine({ start: { x: x + w * 0.08, y: y + h * 0.16 }, end: { x: x + w * 0.92, y: y + h * 0.16 }, thickness: 0.4, color: inkColor, opacity: 0.5 });
          } else {
            // The signature: handwriting on top, a line, and under it who and when.
            await drawInk(page, record.ink, { x: x + 2, y: y + h * 0.4, w: w - 4, h: h * 0.58 }, partyName(record.party));
            page.drawLine({ start: { x, y: y + h * 0.37 }, end: { x: x + w, y: y + h * 0.37 }, thickness: 0.6, color: capColor, opacity: 0.55 });
            const capSize = Math.max(5, Math.min(8, h * 0.15));
            const cap = String(captionFor(record.party, record.party.signed_at) || '').replace(/[\r\n\t]+/g, ' ').slice(0, 90);
            await kit.draw(page, cap, { x, y: y + h * 0.37 - capSize - 1.5, size: kitFit(cap, 'regular', w, capSize, 4), color: capColor });
            const fp = String(record.party.signer_pk_hash || '').slice(0, 8);
            const proof = 'Paramant ParaSign' + (fp ? ' · PQ ' + fp : '');
            page.drawText(proof, { x, y: y + 1, size: Math.max(4, capSize - 1.5), font: regular, color: dimColor });
          }
        });
      }
    }
  }
  return new Uint8Array(await pdf.save());
}

// ---------- after: the complete PDF and the proof, for whoever may have them ----------
function isResultMode() {
  if (__ownerMode) return true;
  if (!__envelope) return false;
  const me = (__envelope.parties || [])[__partyIndex] || {};
  return __envelope.status === 'complete' || me.status === 'signed';
}

function fileBase() {
  return (__envelope.original_filename || 'document.pdf').replace(/\.pdf$/i, '');
}

async function showResultForParty(envId, partyIndex) {
  document.body.classList.add('result-mode');
  const complete = __envelope.status === 'complete';
  setStatus('ok', complete
    ? L('Iedereen heeft getekend. Hieronder downloadt u het complete document met alle handtekeningen, en het bewijs.', 'Everyone has signed. Below you can download the complete document with every signature, and the proof.')
    : L('U heeft getekend. Zodra iedereen heeft getekend, opent deze zelfde link het complete document.', 'You have signed. Once everyone has signed, this same link opens the complete document.'));
  $('sign-confirm').hidden = true;
  if (!__session) { showCta(loginCtaHtml()); return; }
  await loadDeliveredDocument(envId, partyIndex);
  wireResultCard({
    proofUrl: complete ? '/api/user/envelopes/' + encodeURIComponent(envId) + '/receipt?p=' + encodeURIComponent(partyIndex) + '&t=' + encodeURIComponent(__inviteToken) : '',
  });
}

function wireResultCard({ proofUrl }) {
  const card = $('result-card');
  if (!card) return;
  card.hidden = false;
  const complete = __envelope.status === 'complete';
  $('result-title').textContent = complete ? L('Het getekende document', 'The signed document') : L('Getekend tot nu toe', 'Signed so far');
  const pdfBtn = $('result-download-pdf');
  const proof = $('result-download-proof');
  const note = $('result-note');
  if (pdfBtn) {
    pdfBtn.hidden = !__documentBytes;
    pdfBtn.textContent = complete ? L('Download het getekende document (pdf)', 'Download the signed document (pdf)') : L('Download de pdf met de handtekeningen tot nu toe', 'Download the pdf with the signatures so far');
    pdfBtn.onclick = async () => {
      pdfBtn.disabled = true;
      try {
        const bytes = await buildSignedPdf(null);
        if (bytes) downloadBytes(bytes, fileBase() + (complete ? L('-getekend.pdf', '-signed.pdf') : L('-deels-getekend.pdf', '-partly-signed.pdf')), 'application/pdf');
      } finally { pdfBtn.disabled = false; }
    };
  }
  if (proof) {
    proof.hidden = !proofUrl;
    if (proofUrl) proof.href = proofUrl;
  }
  const orig = $('result-download-original');
  if (orig) {
    orig.hidden = !__documentBytes;
    orig.onclick = () => { if (__documentBytes) downloadBytes(__documentBytes, String(__envelope.original_filename || (fileBase() + '.pdf')), isPdfBytes(__documentBytes) ? 'application/pdf' : 'application/octet-stream'); };
  }
  if (note) {
    note.hidden = false;
    note.textContent = complete
      ? L('Het bewijs (.psign) toont aan wie waar heeft getekend. Controleer het op /verify samen met het originele document: de pdf met handtekeningen is een leesbare kopie daarvan.', 'The proof (.psign) shows who signed where. Check it on /verify together with the original document: the pdf with signatures is a readable copy of it.')
      : L('Het bewijs komt beschikbaar zodra iedereen heeft getekend.', 'The proof becomes available once everyone has signed.');
  }
}

// The sender's own result page. The mail "Iedereen heeft getekend" links here
// with an opaque reference (?result=), never the envelope id.
async function initOwner(resultRef, ownerId) {
  __ownerMode = true;
  document.body.classList.add('result-mode', 'owner-mode');
  showStep('step-loading');
  $('loading-msg').textContent = L('Het getekende document wordt opgehaald...', 'Fetching the signed document...');
  try {
    let envId = ownerId;
    if (resultRef) {
      const r = await fetch('/api/user/results/' + encodeURIComponent(resultRef), { credentials: 'include', cache: 'no-store' });
      if (r.status === 401) {
        showStep('step-cosign');
        setStatus('warn', L('Log in met het account waarmee u het verzoek verstuurde.', 'Sign in with the account you sent the request from.'));
        showCta(loginCtaHtml());
        document.body.classList.add('needs-login');
        return;
      }
      if (!r.ok) return showError(L('Deze link werkt niet (meer). Open uw documenten in het dashboard.', 'This link no longer works. Open your documents in the dashboard.'));
      envId = (await r.json()).envelope_id;
    }
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(String(envId || ''))) return showError(L('De link bevat geen geldig verzoek.', 'The link does not contain a valid request.'));
    const v = await fetch('/api/user/envelopes/' + encodeURIComponent(envId) + '/owner-view', { credentials: 'include', cache: 'no-store' });
    if (v.status === 401) return showError(L('Log in met het account waarmee u het verzoek verstuurde.', 'Sign in with the account you sent the request from.'));
    if (!v.ok) return showError(L('Dit verzoek is niet gevonden bij uw account.', 'This request was not found on your account.'));
    __envelope = (await v.json()).envelope;
    __partyIndex = -1;
    renderEnvelope();
    showStep('step-cosign');
    $('sign-confirm').hidden = true;
    const state = envelopeState(__envelope);
    setStatus(state === 'complete' ? 'ok' : state === 'open' ? '' : 'err', state === 'complete'
      ? L('Iedereen heeft getekend. Download hieronder het complete document en het bewijs.', 'Everyone has signed. Download the complete document and the proof below.')
      : (closedExplanation(state) || L('Nog niet iedereen heeft getekend.', 'Not everyone has signed yet.')));
    // The whole key was kept on this device when the request was sent. On
    // another device the sender opens their own original file instead.
    let fragment = '';
    try { fragment = localStorage.getItem('paramant.cosign.key.v1:' + envId) || ''; } catch {}
    if (fragment && parseDocumentKeyFragment(fragment)) {
      try {
        const r = await fetch('/api/user/envelopes/' + encodeURIComponent(envId) + '/owner-document', { credentials: 'include', cache: 'no-store' });
        if (r.ok) {
          const capsule = new Uint8Array(await r.arrayBuffer());
          const delivered = await decryptDocumentCapsule({ capsule, fragment, envelopeId: envId, docHash: __envelope.doc_hash });
          __docKey = parseDocumentKeyFragment(fragment);
          await verifyAndRenderDocument(delivered.bytes, 'delivery');
        }
      } catch { /* fall back to the original file */ }
    }
    if (!__documentBytes) {
      setDeliveryStatus('err', L('Kies het originele document dat u liet tekenen. Het blijft in uw browser; daar wordt de pdf met alle handtekeningen gemaakt.', 'Choose the original document you sent for signing. It stays in your browser, where the pdf with every signature is made.'));
      $('verify-file').onchange = async (ev) => { await onVerifyFile(ev); wireResultCard({ proofUrl: state === 'complete' ? '/api/user/documents/' + encodeURIComponent(envId) + '/receipt' : '' }); };
    } else {
      setDeliveryStatus('ok', L('Het document is geopend.', 'The document is open.'));
    }
    wireResultCard({ proofUrl: state === 'complete' ? '/api/user/documents/' + encodeURIComponent(envId) + '/receipt' : '' });
  } catch (e) {
    showError(e.message || L('Er is geen verbinding. Controleer uw internet en probeer het opnieuw.', 'No connection. Check your internet and try again.'));
  }
}

// ---------- the gate: open the document before you sign ----------
// There is no "sign the hash blind" any more. It was a way out for a document
// that did not load, and the people who took it signed something they never
// saw (tester report 5, finding 3). The invitation link now opens the
// document; without the document there is nothing to sign.
function refreshSignGate() {
  const btn = $('sign-confirm');
  const gate = $('review-gate');
  if (!__session) { btn.disabled = true; gate.hidden = true; return; }
  btn.disabled = __hashMatches !== true;
  gate.hidden = false;
  if (__hashMatches === true) {
    gate.innerHTML = '<span class="gate-ok">' + L('U heeft het document hierboven geopend en gecontroleerd.', 'You have opened and verified the document above.') + '</span>';
  } else if (__hashMatches === false) {
    gate.textContent = L('Het bestand dat u opende hoort niet bij dit verzoek, dus ondertekenen kan niet. Open het juiste document.', 'The file you opened does not match this request, so signing is blocked. Open the correct document.');
  } else {
    gate.textContent = L('Ondertekenen kan zodra het document hierboven open is.', 'Signing is possible once the document above is open.');
  }
}

// ---------- saying no ----------
async function doDecline() {
  if (!confirm(L('Weet u zeker dat u niet tekent? Het verzoek stopt dan voor iedereen, en de afzender krijgt bericht.', 'Are you sure you will not sign? The request then stops for everyone, and the sender is told.'))) return;
  const btn = $('decline-btn');
  btn.disabled = true;
  try {
    const r = await fetch('/api/user/envelopes/' + encodeURIComponent(__envelope.id) + '/decline', {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ party_index: __partyIndex, token: __inviteToken }),
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.error === 'signed' ? L('U heeft al getekend; weigeren kan dan niet meer.', 'You have already signed, so you can no longer decline.')
        : r.status === 403 ? L('Log in met het e-mailadres waarop u bent uitgenodigd.', 'Sign in with the invited email address.')
        : L('Weigeren lukte niet. Probeer het zo opnieuw.', 'Declining did not work. Please try again.'));
    }
    __envelope.status = 'void';
    __envelope.void_reason = 'declined';
    const me = (__envelope.parties || [])[__partyIndex]; if (me) me.status = 'declined';
    renderEnvelope();
    showClosed('declined');
    setStatus('ok', L('U heeft geweigerd. Het verzoek is gestopt en de afzender krijgt bericht.', 'You declined. The request has stopped and the sender is told.'));
    show('review-card', false);
  } catch (e) {
    setStatus('err', e.message);
    btn.disabled = false;
  }
}

// ---------- the v3 passkey-PRF signing chain (same gate as /sign doSign) ----------
async function doSign() {
  // The gate keeps this button disabled until the document is verified; re-check
  // here as defence in depth.
  if (__hashMatches !== true) {
    setStatus('err', L('Open en bekijk het document hierboven voordat u tekent.', 'Open and review the document above before signing.'));
    refreshSignGate();
    return;
  }
  if (__documentBytes && isPdfBytes(__documentBytes) && Number(__envelope.recipe_version) >= 5 && __appearance.fields.length === 0) {
    if (!confirm(L('Ondertekenen zonder zichtbare handtekening in het document? Uw cryptografische handtekening wordt wel vastgelegd.', 'Sign without a visible mark on the PDF? Your cryptographic signature will still be recorded.'))) return;
  }
  $('sign-confirm').disabled = true;
  $('sign-cta').hidden = true;

  try {
    // 0) Make sure this device has a signing key, and set one up inline if not.
    if (!__signKey || (__signKey.ephemeral && !__ephemeralSigner)) {
      try {
        __signKey = await ensureSigningKey({ rpId: location.hostname, onStatus: (m) => setStatus('', m) });
      } catch (e) {
        // No one-tap passkey here (no passkey, a provider without PRF, a
        // browser without WebAuthn or key storage): sign with the
        // authenticator code, a key that is never stored.
        if (!e || !['prf_unsupported', 'no_passkey', 'no_webauthn', 'vault_unavailable'].includes(e.code)) throw e;
        const code = await promptTotp('cs-pass');
        if (code == null) { const c = new Error('cancelled'); c.code = 'cancelled'; throw c; }
        setStatus('', L('Uw ondertekensleutel wordt klaargezet...', 'Setting up your signing key…'));
        ({ signKey: __signKey, signer: __ephemeralSigner } = await enrolEphemeralSigningKeyWithTotp({ totp: code, onStatus: (m) => setStatus('', m) }));
      }
    }

    // 1) Per-document activation (authorize -> one-shot token).
    setStatus('', L('Toestemming om te ondertekenen wordt gevraagd...', 'Requesting signing authorization...'));
    const act = await requestSignActivation({
      envelopeId: __envelope.id,
      partyIndex: __partyIndex,
      docHash: __envelope.doc_hash,
      inviteToken: __inviteToken,
    });

    // 2) Passkey-PRF unlock + sign of the v3 domain-prefixed message.
    setStatus('', L('Bevestig om te ondertekenen (Face ID, Touch ID of beveiligingssleutel)...', 'Confirm to sign (Face ID / Touch ID / security key)...'));
    const signer = __ephemeralSigner || await new LocalVaultSigner().activate({ vaultId: __signKey.vaultId, rpId: location.hostname });
    __ephemeralSigner = null;   // consumed — `signer` owns it now and disposes below
    const appearance = normaliseSigningAppearance(__appearance);
    let sigB64;
    try {
      const message = buildDocSignMessage({
        envelopeId: __envelope.id,
        docHash: __envelope.doc_hash,
        partyIndex: __partyIndex,
        emailHash: act.email_hash,
        recipeVersion: act.recipe_version,
        signerPublicKey: __signKey.pk_b64,
        appearance,
      });
      sigB64 = toB64(await signer.sign(message));
    } finally {
      signer.dispose();   // zeroize — the secret never outlives this block
    }

    // 3) Submit, with the handwriting encrypted for the other parties.
    setStatus('', L('Uw handtekening wordt vastgelegd...', 'Recording your signature...'));
    let ink = '';
    try { ink = await sealInk({ ink: __ink, documentKey: __docKey, envelopeId: __envelope.id, partyIndex: __partyIndex }); } catch { ink = ''; }
    const data = await submitSignature({ activationId: act.activation_id, signerPublicKey: signer.publicKey, signature: sigB64, appearance, ink });

    $('done-env-id').textContent = __envelope.id;
    $('done-status').textContent = data.status === 'complete' ? L('Door iedereen getekend', 'Signed by everyone') : L('Wacht op de anderen', 'Waiting for the others');
    $('done-progress').textContent = (data.signed_count != null ? data.signed_count : '?') + ' / ' + (data.party_count != null ? data.party_count : __envelope.party_count) + L(' getekend', ' signed');
    $('done-pk').textContent = __signKey.fingerprint;
    renderQuotaNote(data.quota);
    await refreshEnvelopeStatus();
    await decryptPriorInks();
    __signedPdfBytes = await buildSignedPdf(data).catch(() => null);
    const download = $('done-download-pdf');
    const note = $('done-download-note');
    if (__signedPdfBytes && download) {
      download.hidden = false;
      download.textContent = data.status === 'complete' ? L('Download het getekende document (pdf)', 'Download the signed document (pdf)') : L('Download de pdf met de handtekeningen tot nu toe', 'Download the pdf with the signatures so far');
      if (note) note.hidden = false;
      download.onclick = () => downloadBytes(__signedPdfBytes, fileBase() + (data.status === 'complete' ? L('-getekend.pdf', '-signed.pdf') : L('-deels-getekend.pdf', '-partly-signed.pdf')), 'application/pdf');
    }
    // The original as well: the stamped pdf never turns green on /verify, the
    // original with the .psign does, and the invitee never had it as a file
    // (retest A8/T5-7).
    const orig = $('done-download-original');
    if (orig && __documentBytes) {
      orig.hidden = false;
      const name = String(__envelope.original_filename || (fileBase() + '.pdf'));
      orig.onclick = () => downloadBytes(__documentBytes, name, isPdfBytes(__documentBytes) ? 'application/pdf' : 'application/octet-stream');
    }
    const proof = $('done-download-proof');
    const proofWait = $('done-proof-wait');
    if (data.status === 'complete' && proof) {
      proof.hidden = false;
      proof.href = '/api/user/envelopes/' + encodeURIComponent(__envelope.id) + '/receipt?p=' + encodeURIComponent(__partyIndex) + '&t=' + encodeURIComponent(__inviteToken);
      if (proofWait) proofWait.hidden = true;
    } else if (proofWait) {
      proofWait.hidden = false;
    }
    try { sessionStorage.removeItem(appearanceDraftKey()); } catch { /* unavailable */ }
    showStep('step-done');
  } catch (e) {
    if (__ephemeralSigner) { try { __ephemeralSigner.dispose(); } catch { /* best-effort */ } __ephemeralSigner = null; }
    // The sender's monthly allowance, not the signer's (relay 402
    // sender_sign_quota_reached): nothing for the signer to buy, so no upgrade
    // pitch, just what is going on and who can fix it.
    if (e && e.status === 402 && e.data && e.data.error === 'sender_sign_quota_reached') {
      setStatus('err', L('Het tegoed van de afzender voor deze maand is op. Uw handtekening is niet gezet. Laat de afzender weten dat het verzoek daarop wacht.', 'The sender has used up this month\'s allowance. Your signature was not recorded. Let the sender know the request is waiting on it.'));
      $('sign-confirm').disabled = false;
      return;
    }
    if (e && e.status === 402 && window.paQuotaUpgrade && window.paQuotaUpgrade.isQuota402(e.status, e.data)) {
      setStatus('err', L('U heeft uw gratis handtekeningen voor deze maand gebruikt.', 'Free monthly signing limit reached.'));
      showCta(window.paQuotaUpgrade.html(e.data));
      $('sign-confirm').disabled = false;
      return;
    }
    let msg;
    const reason = e && e.data && e.data.error;
    if (e && e.code === 'no_passkey') msg = L('Voeg eerst een passkey toe aan uw account (Account, Inloggen met passkey) en open daarna deze link opnieuw. De passkey waarmee u inlogt wordt dan uw ondertekensleutel.', 'Add a passkey to your account first (Account → Passkey sign-in), then return to this link. Your sign-in passkey becomes your signing key.');
    else if (e && (e.code === 'vault_unavailable' || e.code === 'no_webauthn')) msg = e.message;
    else if (e && e.name === 'NotAllowedError') msg = L('De bevestiging met uw passkey is geannuleerd of duurde te lang. Tik op Ondertekenen om het opnieuw te proberen.', 'Passkey confirmation was cancelled or timed out. Tap Sign to try again.');
    else if (e && e.status === 401) msg = L('Uw sessie is verlopen. Log opnieuw in als de uitgenodigde ontvanger en probeer het nog eens.', 'Your session expired. Sign in again as the invited recipient, then retry.');
    else if (e && e.status === 429) {
      const wait = Number(e.data && (e.data.retry_after || e.data.retryAfter)) || 0;
      msg = wait > 0
        ? L('Het is even te druk. Probeer het over ' + Math.ceil(wait) + ' seconden opnieuw.', 'It is busy right now. Try again in ' + Math.ceil(wait) + ' seconds.')
        : L('Het is even te druk. Probeer het over een minuut opnieuw.', 'It is busy right now. Try again in a minute.');
    }
    else if (e && e.status === 403 && (reason === 'signer_not_enrolled' || e.message === 'signer_not_enrolled')) msg = 'relink';
    else if (e && e.status === 403) msg = L('Deze uitnodiging hoort bij een ander e-mailadres. Log in met het adres waar de uitnodiging naartoe ging.', 'This invite is bound to a different email address. Sign in with the address the invite was sent to.');
    else if (e && e.status === 410 && (reason === 'voided' || reason === 'declined')) msg = closedExplanation(reason === 'declined' ? 'declined' : 'cancelled');
    else if (e && e.status === 410) msg = L('De termijn om te tekenen is voorbij (tot ', 'The signing period has ended (until ') + humanDate(__envelope.sign_expires_at) + L('). Vraag de afzender om een nieuw verzoek.', '). Ask the sender for a new request.');
    else if (e && e.status === 409 && reason === 'already_complete') msg = L('Iedereen heeft al getekend. Laad de pagina opnieuw om het document te downloaden.', 'Everyone has already signed. Reload the page to download the document.');
    else if (e && e.status === 409) msg = L('Deze toestemming om te ondertekenen is al gebruikt of verlopen. Laad de pagina opnieuw en probeer het nog eens.', 'That signing authorization was already used or expired. Reload the page and try again.');
    else if (e && e.code === 'cancelled') msg = L('Ondertekenen is geannuleerd. Tik op Ondertekenen als u klaar bent.', 'Signing cancelled. Tap Sign when you’re ready.');
    else if (e && (e.code === 'totp_invalid' || e.code === 'totp_required')) msg = L('Die code klopte niet. Tik op Ondertekenen en vul de huidige code van 6 cijfers in.', 'That authenticator code didn’t match. Tap Sign and enter the current 6-digit code.');
    else if (e && e.code === 'totp_unavailable') msg = L('Stel eerst een authenticator-app in op uw account (Account, Tweestapsverificatie) en teken daarna met de code.', 'Set up an authenticator app on your account first (Account → Two-factor), then sign with its code.');
    // Already translated by the signer (js/error-message.js).
    else if (e && e.code === 'service_error') msg = e.message;
    else if (e && (e.code === 'prf_unsupported' || e.code === 'need_passkey')) msg = L('Uw passkey kan hier niet met één tik ondertekenen. Tik op Ondertekenen om met de code uit uw authenticator-app te tekenen.', 'Your passkey can’t do one-tap signing here. Tap Sign to sign with your authenticator code instead.');
    else if (e && e.status) msg = L('Ondertekenen lukt nu niet (serverfout ', 'Signing could not be completed right now (server error ') + e.status + L('). Probeer het zo opnieuw.', '). Please try again in a moment.');
    else msg = L('Uw passkey kon het ondertekenen in deze browser niet afronden. Tik op Ondertekenen om het opnieuw te proberen. Lukt het steeds niet, probeer dan een andere browser of gebruik de passkey op uw telefoon.', 'Your passkey could not complete signing on this browser. Tap Sign to try again. If it keeps failing, try a different browser, or use the passkey on your phone.');
    if (msg === 'relink') {
      // 403 signer_not_enrolled: the key in this browser is not linked to this
      // account (a link that stopped halfway, or another account signing in the
      // same browser). It is not the e-mail address (retest T3-4). The way out
      // is a new key, linked now, as /sign offers it.
      setStatus('err', L('De ondertekensleutel in deze browser is niet aan uw account gekoppeld, bijvoorbeeld omdat het koppelen eerder halverwege stopte of omdat hier ook een ander account tekent. Koppel opnieuw: deze browser maakt een nieuwe sleutel en koppelt die met één bevestiging aan uw account. Er is nog niets ondertekend. ', 'The signing key in this browser is not linked to your account, for example because linking stopped halfway earlier or because another account also signs here. Link again: this browser makes a new key and links it to your account with one confirmation. Nothing has been signed yet. '));
      const st = $('sign-status');
      if (st) {
        const b = document.createElement('button');
        b.type = 'button'; b.id = 'cs-relink-key'; b.className = 'btn btn-primary';
        b.textContent = L('Sleutel opnieuw koppelen', 'Link the key again');
        b.addEventListener('click', relinkSigningKey);
        st.appendChild(b);
      }
      $('sign-confirm').disabled = false;
      return;
    }
    setStatus('err', msg);
    $('sign-confirm').disabled = false;
  }
}

// Retire exactly the key that was refused, then sign again: the next run finds
// no key here and sets up a new one, linked to THIS account.
async function relinkSigningKey() {
  const btn = $('cs-relink-key'); if (btn) btn.disabled = true;
  try {
    if (__signKey && __signKey.vaultId) await vaultDelete(__signKey.vaultId);
  } catch (e) {
    try { console.error('[paramant] vault delete', e); } catch { /* no console */ }
  }
  __signKey = null;
  __ephemeralSigner = null;
  doSign();
}

// For the browser tests: the page's own state, read-only.
window.__cosignDebug = { appearance: () => __appearance, ink: () => __ink, seed: () => __appearanceIsSeed, pages: () => __pageSizes.length };

init();
