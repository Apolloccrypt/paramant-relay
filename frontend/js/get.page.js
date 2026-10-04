'use strict';

// Two languages, one file. The page says which one it is in <html lang>:
// /get is Dutch, /en/get is English.
const LANG = (document.documentElement.lang || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';
const T = {
  nl: {
    foreign: (host) => 'Die link is geen link van ' + host + ', dus hij wordt hier niet geopend.',
    invalid: 'Dat lijkt geen geldige link om iets te ontvangen.',
    importTitle: 'Sleutel laden...',
    importStatus: 'De sleutel uit de link wordt geladen...',
    dlTitle: 'Downloaden...',
    dlStatus: 'Het verzegelde bestand wordt gedownload...',
    dlFail: (st) => 'Downloaden is mislukt (HTTP ' + st + ').',
    decTitle: 'Ontsleutelen...',
    decStatus: 'Het bestand wordt ontsleuteld...',
    decFail: 'De sleutel in de link past niet op dit bestand. De link is onderweg beschadigd of niet helemaal gekopieerd. Er is niets gewist: open de link opnieuw, precies zoals u hem kreeg.',
    checking: 'Even kijken of het bestand er nog is...',
    readyMeta: (size, ttl) => [size ? 'Grootte ' + size : '', Number.isFinite(ttl) ? 'nog ' + leftNl(ttl) + ' beschikbaar' : ''].filter(Boolean).join(', ') + (size || Number.isFinite(ttl) ? '.' : ''),
    busy: 'Dit bestand wordt op dit moment al gedownload, misschien op een ander apparaat. Probeer het over een minuut opnieuw.',
    stalled: 'De verbinding viel een minuut stil en de download is gestopt. Er is niets gewist: probeer het opnieuw.',
    netFail: 'De download kwam niet helemaal binnen. Er is niets gewist: probeer het opnieuw.',
    gone: {
      downloaded: { title: 'Dit bestand is al gedownload en daarna gewist.', sub: 'Een link van Paramant werkt maar één keer. Na de download is het bestand voorgoed van onze server verwijderd. Was u dat niet zelf, neem dan contact op met de afzender.' },
      expired: { title: 'Deze link is verlopen.', sub: 'Het bestand is niet gedownload. Het stond maar een beperkte tijd klaar en is nu van onze server verwijderd. Vraag de afzender om het opnieuw te sturen.' },
      lost: { title: 'Dit bestand is niet meer beschikbaar.', sub: 'Het is niet gedownload. Onze server is herstart of het bestand is verwijderd voordat u het kon ophalen. Vraag de afzender om het opnieuw te sturen. Onze excuses.' },
      withdrawn: { title: 'De afzender heeft dit bestand ingetrokken.', sub: 'Het staat niet meer op onze server. Neem contact op met de afzender als u het toch nodig hebt.' },
      exhausted: { title: 'Deze link is te vaak geprobeerd.', sub: 'Na vijf pogingen zonder geslaagde download is het bestand voor de zekerheid gewist. Vraag de afzender om het opnieuw te sturen.' },
      unknown: { title: 'Deze link werkt niet meer.', sub: 'Hij is verlopen, al gebruikt of nooit uitgegeven. Vraag de afzender om het bestand opnieuw te sturen.' },
    },
    tooShort: 'Het ontsleutelde bestand is te kort.',
    headerBad: 'De kop van het ontsleutelde bestand is beschadigd.',
    opening: 'Het document wordt geopend...',
    done: 'Klaar.',
    pages: (n, shown) => n + (n === 1 ? ' pagina' : ' pagina\'s') + (n > shown ? ', eerste ' + shown + ' getoond' : ''),
    haveFile: 'U hebt het bestand.',
    pdfLine: (name, pc, size) => name + ' (' + pc + ', ' + size + ') is hier ' +
      'geopend in dit tabblad. Onze kopie is voorgoed vernietigd, dus sla het nu op als ' +
      'u het wilt bewaren.',
    save: 'Opslaan',
    pdfFallback: 'Het document opent hier niet. Het wordt opgeslagen...',
    saving: 'Bestand wordt opgeslagen...',
    savedLine: (name, size) => name + ' (' + size + ') staat op uw apparaat. ' +
      'Onze kopie is voorgoed vernietigd.',
    unknown: 'Onbekende fout',
  },
  en: {
    foreign: (host) => 'That link is not a ' + host + ' link, so it is not opened here.',
    invalid: 'That does not look like a valid receive link.',
    importTitle: 'Importing key...',
    importStatus: 'Importing decryption key...',
    dlTitle: 'Downloading...',
    dlStatus: 'Downloading encrypted file from relay...',
    dlFail: (st) => 'Download failed: HTTP ' + st,
    decTitle: 'Decrypting...',
    decStatus: 'Decrypting with AES-256-GCM...',
    decFail: 'The key in the link does not fit this file. The link was damaged on the way or not copied whole. Nothing was deleted: open the link again exactly as you received it.',
    checking: 'Checking the file is still there...',
    readyMeta: (size, ttl) => [size ? 'Size ' + size : '', Number.isFinite(ttl) ? 'available for ' + leftEn(ttl) : ''].filter(Boolean).join(', ') + (size || Number.isFinite(ttl) ? '.' : ''),
    busy: 'This file is being downloaded right now, perhaps on another device. Try again in a minute.',
    stalled: 'The connection went quiet for a minute and the download stopped. Nothing was deleted: try again.',
    netFail: 'The download did not arrive in full. Nothing was deleted: try again.',
    gone: {
      downloaded: { title: 'This file has already been downloaded and burned.', sub: 'Paramant links are single-use. Once downloaded, the file is permanently deleted from the relay. If that was not you, contact the sender.' },
      expired: { title: 'This link has expired.', sub: 'The file was not downloaded. It was only available for a limited time and has now been removed from our server. Ask the sender to send it again.' },
      lost: { title: 'This file is no longer available.', sub: 'It was not downloaded. Our server restarted or the file was removed before you could fetch it. Ask the sender to send it again. Our apologies.' },
      withdrawn: { title: 'The sender withdrew this file.', sub: 'It is no longer on our server. Contact the sender if you still need it.' },
      exhausted: { title: 'This link was tried too often.', sub: 'After five attempts without a completed download the file was deleted to be safe. Ask the sender to send it again.' },
      unknown: { title: 'This link no longer works.', sub: 'It has expired, was already used, or was never issued. Ask the sender to send the file again.' },
    },
    tooShort: 'Decrypted payload too short',
    headerBad: 'Decrypted payload header corrupt',
    opening: 'Opening the document...',
    done: 'Done.',
    pages: (n, shown) => n + ' page' + (n === 1 ? '' : 's') + (n > shown ? ', first ' + shown + ' shown' : ''),
    haveFile: 'You have the file.',
    pdfLine: (name, pc, size) => name + ' (' + pc + ', ' + size + ') is open ' +
      'here in this tab. Our copy has been permanently destroyed, so save it now if ' +
      'you want to keep it.',
    save: 'Save',
    pdfFallback: 'The document would not open here, saving it instead...',
    saving: 'Saving file...',
    savedLine: (name, size) => name + ' (' + size + ') is saved on your device. ' +
      'Our copy has been permanently destroyed.',
    unknown: 'Unknown error',
  },
};
function t(k) { return T[LANG][k]; }
function leftNl(s) { return s >= 86400 ? Math.round(s / 86400) + (Math.round(s / 86400) === 1 ? ' dag' : ' dagen') : s >= 3600 ? Math.round(s / 3600) + ' uur' : Math.max(1, Math.round(s / 60)) + ' min'; }
function leftEn(s) { return s >= 86400 ? Math.round(s / 86400) + (Math.round(s / 86400) === 1 ? ' day' : ' days') : s >= 3600 ? Math.round(s / 3600) + (Math.round(s / 3600) === 1 ? ' hour' : ' hours') : Math.max(1, Math.round(s / 60)) + ' min'; }

// The language switch keeps the whole address, the key after # included, so
// it never travels anywhere but this browser.
function langSwitch() {
  const a = document.getElementById('lang-switch-link');
  if (!a) return;
  // Nothing is fetched before the receiver clicks, so switching language with
  // a one-time link in the address costs nothing: the other page asks again.
  const p = location.pathname;
  const naar = LANG === 'en' ? (p.replace(/^\/en(?=\/|$)/, '') || '/') : '/en' + p;
  a.href = naar + location.search + location.hash;
}
langSwitch();

// Which relay sector holds the blob. An account is valid on exactly one sector,
// and the sender's page knows which one, so the link carries it in `&r=`. Before
// that this file always asked health, which is right for most accounts and
// silently wrong for the rest: a legal or finance sender's receiver got a 404
// and the page called the file burned when it was sitting on another sector.
// An unknown or missing `r` still falls back to health, so every link minted
// before this change keeps working.
const RELAY_SECTORS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};
const DEFAULT_RELAY = RELAY_SECTORS.health;

function showStep(id) {
  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  document.getElementById(id).classList.add('active');
}

function setStatus(msg, pct) {
  var ind = document.getElementById('indeterminate-bar');
  var wrap = document.getElementById('progress-wrap');
  if (pct > 0) {
    if (ind)  ind.hidden = true;
    if (wrap) wrap.hidden = false;
    document.getElementById('pbar').style.width = pct + '%';
  } else {
    if (ind)  ind.hidden = false;
    if (wrap) wrap.hidden = true;
  }
  document.getElementById('status-msg').textContent = msg;
}

function setTitle(t) {
  document.getElementById('loading-title').textContent = t;
}

function showError(msg) {
  document.getElementById('error-msg').textContent = msg;
  showStep('step-error');
}

function fromB64url(s) {
  try {
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=');
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { return null; }
}

function formatSize(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}

async function waitForPdfjs() {
  // Sticky signal, so it does not matter whether the loader module ran before
  // or after this file. See js/ready.js.
  return window.ready.within('pdfjs', 10000, 'PDF.js');
}

// A PDF is the one arrival that has something worth putting on the end screen:
// the document itself. So it goes in the payload slot of the shared done state
// (see frontend/done-state.css) rather than on a fifth screen of its own with
// its own headline, its own card and its own row of badges, which is what this
// page had until 4 September 2026.
//
// Returns the element to hand to paramantDone.payload(), plus the page count
// for the one sentence above it.
async function renderPdfPreview(bytes) {
  const pdfjs = await waitForPdfjs();
  // PDF.js mutates the input buffer. Pass a copy so the original stays intact
  // for the save path.
  const copy = new Uint8Array(bytes);
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;

  const container = document.createElement('div');
  container.className = 'done-preview';
  container.id = 'preview-canvas-list';
  const MAX_PAGES = Math.min(pdf.numPages, 30);
  for (let i = 1; i <= MAX_PAGES; i++) {
    const page = await pdf.getPage(i);
    const baseViewport = page.getViewport({ scale: 1 });
    const targetWidth = Math.min(840, Math.floor(window.innerWidth * 0.9));
    const scale = targetWidth / baseViewport.width;
    const viewport = page.getViewport({ scale });
    const wrap = document.createElement('div');
    wrap.className = 'page-wrap';
    wrap.dataset.pageIndex = String(i - 1);
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    wrap.appendChild(canvas);
    container.appendChild(wrap);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  }

  return { node: container, pages: pdf.numPages, shown: MAX_PAGES };
}

function downloadBytes(bytes, name, mime) {
  const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);
}

// A download token is 48 lowercase hex characters (relay.js /v2/dl routes).
const TOKEN_RE = /^[a-f0-9]{48}$/;

// A link cut off or mangled on its way here. Not an error of ours and not
// something the dashboard can fix: the receiver needs the whole link again.
function showInvalid() {
  showStep('step-invalid');
}

// What the paste box accepts: a link to this site's own /get (with a token
// and the key after #) or /ontvang. `new URL(v, origin)` never fails on
// ordinary text, it turns "hello" into origin + "/hello", so the check is on
// the result, not on the parse.
function receiveTarget(v) {
  let raw = v;
  // "paramant.app/get?t=..." without a scheme.
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d+)?\//i.test(raw)) raw = 'https://' + raw;
  let u;
  try { u = new URL(raw, location.origin); } catch { return { err: 'invalid' }; }
  if (u.origin !== location.origin) return { err: 'foreign' };
  if (/^(\/en)?\/get(\.html)?$/.test(u.pathname)) {
    const t = u.searchParams.get('t') || '';
    if (!TOKEN_RE.test(t) || u.hash.length < 2) return { err: 'invalid' };
    return { href: u.href };
  }
  if (/^(\/en)?\/ontvang\/[A-Za-z0-9_-]{16,128}$/.test(u.pathname)) return { href: u.href };
  return { err: 'invalid' };
}

function goReceive() {
  const el = document.getElementById('enter-link');
  const errEl = document.getElementById('enter-err');
  if (errEl) errEl.textContent = '';
  const v = (el && el.value || '').trim();
  if (!v) return;
  const got = receiveTarget(v);
  if (got.href) {
    // Same page, different query or fragment: a hash-only change does not
    // reload, so load it explicitly.
    const sameDoc = got.href.split('#')[0] === location.href.split('#')[0];
    location.href = got.href;
    if (sameDoc) location.reload();
    return;
  }
  if (errEl) {
    errEl.textContent = got.err === 'foreign'
      ? t('foreign')(location.host)
      : t('invalid');
  }
}

// ── Reading the link ─────────────────────────────────────────────────────────
//
// Two link shapes arrive here.
//   web app:   /get?t=<48 hex>&r=<sector>#<key+iv, base64url, 44 bytes>
//   add-in and browser extension ("FileLink"):
//              /get?t=T1,T2&n=NAME&c=N&r=<relay url>#k=K1,K2
// The second shape used to point at /parashare, which sits behind the login,
// so a receiver without an account never reached the file. nginx now sends
// every such /parashare link here, query intact; the fragment survives that
// redirect because the Location carries none of its own.
const FILELINK_RELAYS = new Set([
  'https://relay.paramant.app',
  'https://health.paramant.app',
  'https://legal.paramant.app',
  'https://finance.paramant.app',
  'https://iot.paramant.app',
]);

function parseLink() {
  const params = new URLSearchParams(location.search);
  const tParam = params.get('t');
  const hash = location.hash.slice(1);
  if (!tParam && !hash) return { kind: 'none' };
  if (hash.startsWith('k=')) {
    // FileLink. Every part has to be whole, or nothing is fetched.
    const tokens = (tParam || '').split(',');
    const keys = hash.slice(2).split(',');
    let relay = (params.get('r') || '').replace(/\/+$/, '');
    if (!relay) relay = 'https://relay.paramant.app';
    if (!FILELINK_RELAYS.has(relay)) return { kind: 'invalid' };
    if (!tokens.length || tokens.length !== keys.length) return { kind: 'invalid' };
    if (!tokens.every((x) => TOKEN_RE.test(x))) return { kind: 'invalid' };
    const rawKeys = keys.map(fromB64url);
    if (!rawKeys.every((k) => k && k.length === 32)) return { kind: 'invalid' };
    return { kind: 'filelink', relay, tokens, rawKeys, name: params.get('n') || 'download' };
  }
  if (!tParam || !hash || !TOKEN_RE.test(tParam)) return { kind: 'invalid' };
  // Decode key+iv from fragment (44 bytes: first 32 = AES key, next 12 = IV)
  const keyIv = fromB64url(hash);
  if (!keyIv || keyIv.length < 44) return { kind: 'invalid' };
  return {
    kind: 'webapp',
    relay: RELAY_SECTORS[params.get('r')] || DEFAULT_RELAY,
    tokens: [tParam],
    rawKey: keyIv.slice(0, 32),
    iv: keyIv.slice(32, 44),
  };
}

// ── Nothing is fetched without the receiver's click ──────────────────────────
//
// Mail scanners (Safe Links, Mimecast, Proofpoint) open links in a real browser
// and run its JavaScript. When this page fetched on arrival, the scanner spent
// the one-time link and the receiver found it gone. So arrival only asks
// /info, which burns nothing, and the download waits for the button.
//
// The download itself is claimed (?claim=), not burned: the relay keeps the
// file until this page has decrypted it and says so (POST .../ack). A broken
// line, a slow line or a key with one wrong character costs nothing; the page
// gives the claim back (.../release) and the link still works.
let LINK = null;
let busyDownloading = false;
// One claim id per browser and link. In localStorage, so a reload AND a new
// tab of the same browser are the same claimant and are never told to wait
// for their own lease (hertest T4: a link reopened in a new tab after a broken
// download said "already being downloaded" for three minutes). Falls back to
// sessionStorage, then to a fresh id. The id is not a secret: it only says
// which of two downloads may ack, and both need the key from the fragment.
const CLAIM = (() => {
  const key = 'paramant-dl-claim:' + (new URLSearchParams(location.search).get('t') || '').slice(0, 48);
  for (const store of ['localStorage', 'sessionStorage']) {
    try {
      const kept = window[store].getItem(key);
      if (kept && /^[a-f0-9]{32}$/.test(kept)) return kept;
    } catch { /* storage refused: try the next */ }
  }
  const b = crypto.getRandomValues(new Uint8Array(16));
  const id = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  for (const store of ['localStorage', 'sessionStorage']) {
    try { window[store].setItem(key, id); break; } catch { /* idem */ }
  }
  return id;
})();
function forgetClaim() {
  const key = 'paramant-dl-claim:' + (new URLSearchParams(location.search).get('t') || '').slice(0, 48);
  for (const store of ['localStorage', 'sessionStorage']) { try { window[store].removeItem(key); } catch { /* fine */ } }
}

// A tab closed (or navigated away) mid-download gives its claim back at once,
// so the receiver can open the link again straight away. sendBeacon survives
// the unload; text/plain keeps it a simple request (no preflight). The relay
// reads the JSON body whatever the content type.
addEventListener('pagehide', () => {
  if (!busyDownloading || !LINK) return;
  for (const tk of LINK.tokens) {
    const body = JSON.stringify({ claim: CLAIM });
    try { if (navigator.sendBeacon && navigator.sendBeacon(LINK.relay + '/v2/dl/' + tk + '/release', body)) continue; } catch { /* fall through */ }
    fetch(LINK.relay + '/v2/dl/' + tk + '/release', { method: 'POST', body, keepalive: true, cache: 'no-store' }).catch(() => {});
  }
});

function showGone(reason) {
  const g = (T[LANG].gone[reason]) || T[LANG].gone.unknown;
  document.getElementById('burned-msg').textContent = g.title;
  document.getElementById('burned-sub').textContent = g.sub;
  const icon = document.getElementById('burned-icon');
  if (icon) icon.hidden = reason !== 'downloaded' && reason !== 'exhausted';
  document.getElementById('step-burned').dataset.reason = reason;
  showStep('step-burned');
}

async function reasonOf(r) {
  try { const j = await r.json(); return (j && j.reason) || 'unknown'; } catch { return 'unknown'; }
}

async function init() {
  LINK = parseLink();
  if (LINK.kind === 'none') { showStep('step-enter'); return; }
  // A missing half, a token of the wrong shape or a key that is too short all
  // mean the same to the receiver: the link did not arrive whole.
  if (LINK.kind === 'invalid') { showInvalid(); return; }

  showStep('step-ready');
  const meta = document.getElementById('ready-meta');
  const btn = document.getElementById('ready-btn');
  if (meta) meta.textContent = t('checking');
  // /info burns nothing. It tells the receiver up front when there is nothing
  // to fetch any more, and why, instead of after a click.
  let size = 0;
  let ttlLeft = Infinity;
  for (const token of LINK.tokens) {
    let r;
    try { r = await fetch(LINK.relay + '/v2/dl/' + token + '/info', { cache: 'no-store' }); }
    catch { if (meta) meta.textContent = ''; if (btn) btn.disabled = false; return; }
    if (r.status === 404 || r.status === 410) { showGone(await reasonOf(r)); return; }
    if (r.status === 400 || r.status === 401) { showInvalid(); return; }
    if (!r.ok) { if (meta) meta.textContent = ''; if (btn) btn.disabled = false; return; }
    const j = await r.json().catch(() => ({}));
    size += Number(j.file_size) || 0;
    if (Number.isFinite(j.ttl_left_s)) ttlLeft = Math.min(ttlLeft, j.ttl_left_s);
  }
  if (meta) meta.textContent = t('readyMeta')(size ? formatSize(size) : '', ttlLeft);
  if (btn) btn.disabled = false;
}

// Fetch one sealed blob. No deadline on the whole download, only on silence:
// a large file on a slow line may take minutes, a line that stops sending for
// a minute is broken.
const STALL_MS = 60000;
async function fetchSealed(token, onProgress) {
  const ctrl = new AbortController();
  let timer = null;
  const arm = () => { clearTimeout(timer); timer = setTimeout(() => ctrl.abort(), STALL_MS); };
  arm();
  try {
    const r = await fetch(LINK.relay + '/v2/dl/' + token + '/get' + '?claim=' + CLAIM, { signal: ctrl.signal, cache: 'no-store' });
    if (!r.ok) return { status: r.status, reason: await reasonOf(r) };
    const total = Number(r.headers.get('Content-Length')) || 0;
    if (!r.body || !r.body.getReader) return { status: 200, bytes: new Uint8Array(await r.arrayBuffer()) };
    const reader = r.body.getReader();
    const parts = [];
    let got = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      arm();
      parts.push(value);
      got += value.length;
      if (total) onProgress(Math.min(1, got / total));
    }
    if (total && got !== total) return { status: 0, reason: 'short' };
    const out = new Uint8Array(got);
    let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return { status: 200, bytes: out };
  } catch (e) {
    return { status: 0, reason: ctrl.signal.aborted ? 'stalled' : 'network' };
  } finally {
    clearTimeout(timer);
  }
}

function post(token, what) {
  return fetch(LINK.relay + '/v2/dl/' + token + '/' + what, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ claim: CLAIM }),
    cache: 'no-store',
  });
}
function releaseAll(tokens) {
  for (const tk of tokens) post(tk, 'release').catch(() => {});
}
async function ackAll(tokens) {
  for (const tk of tokens) {
    for (let i = 0; i < 3; i++) {
      try { const r = await post(tk, 'ack'); if (r.ok || r.status === 404 || r.status === 410) break; }
      catch { /* try again */ }
      await new Promise((res) => setTimeout(res, 800 * (i + 1)));
    }
  }
}

function retryable(msg) {
  showError(msg);
  const again = document.getElementById('error-retry');
  if (again) again.hidden = false;
}

async function tbDecryptChunk(blob, rawKey) {
  // packet: 0x02 | nonce(12) | ctLen(4 BE) | ciphertext ; then random padding
  if (blob.length < 17 || blob[0] !== 0x02) throw new Error('packet');
  const nonce = blob.slice(1, 13);
  const ctLen = new DataView(blob.buffer, blob.byteOffset + 13, 4).getUint32(0, false);
  if (17 + ctLen > blob.length) throw new Error('packet');
  const ct = blob.slice(17, 17 + ctLen);
  const symKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, symKey, ct));
  // 'PRSH' | metaLen(4 BE) | metaJSON | chunkData
  if (plain[0] !== 0x50 || plain[1] !== 0x52 || plain[2] !== 0x53 || plain[3] !== 0x48) throw new Error('magic');
  const metaLen = new DataView(plain.buffer, 4, 4).getUint32(0, false);
  let meta = null;
  try { meta = JSON.parse(new TextDecoder().decode(plain.slice(8, 8 + metaLen))); } catch { meta = null; }
  return { data: plain.slice(8 + metaLen), meta };
}

async function startDownload() {
  if (!LINK || busyDownloading) return;
  busyDownloading = true;
  let acked = false;
  const tokens = LINK.tokens;
  const errRetry = document.getElementById('error-retry');
  if (errRetry) errRetry.hidden = true;
  try {
    showStep('step-loading');
    setTitle(t('dlTitle'));
    setStatus(t('dlStatus'), 0);

    const blobs = [];
    for (let i = 0; i < tokens.length; i++) {
      const got = await fetchSealed(tokens[i], (f) => {
        setStatus(t('dlStatus'), Math.max(1, Math.round(((i + f) / tokens.length) * 80)));
      });
      if (got.status !== 200) {
        releaseAll(tokens);
        if (got.status === 404 || got.status === 410) { showGone(got.reason); return; }
        if (got.status === 409) { retryable(t('busy')); return; }
        if (got.status === 400 || got.status === 401) { showInvalid(); return; }
        if (got.reason === 'stalled') { retryable(t('stalled')); return; }
        if (got.reason === 'network' || got.reason === 'short') { retryable(t('netFail')); return; }
        retryable(t('dlFail')(got.status));
        return;
      }
      blobs.push(got.bytes);
    }

    setTitle(t('decTitle'));
    setStatus(t('decStatus'), 85);

    // Decrypt everything BEFORE the relay is told to burn. AES-GCM checks every
    // byte against its tag, so a wrong key or a damaged download fails here,
    // and then nothing has been spent.
    let filename;
    let fileData;
    try {
      if (LINK.kind === 'webapp') {
        const aesKey = await crypto.subtle.importKey('raw', LINK.rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
        const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: LINK.iv }, aesKey, blobs[0]));
        // Parse header: [uint32-LE nameLen][nameBytes][fileBytes]
        if (plaintext.length < 4) throw new Error('short');
        const nameLen = new DataView(plaintext.buffer).getUint32(0, true);
        if (plaintext.length < 4 + nameLen) throw new Error('header');
        filename = new TextDecoder().decode(plaintext.slice(4, 4 + nameLen)) || 'download';
        fileData = plaintext.slice(4 + nameLen);
      } else {
        const chunks = [];
        let metaName = null;
        for (let i = 0; i < blobs.length; i++) {
          const { data, meta } = await tbDecryptChunk(blobs[i], LINK.rawKeys[i]);
          // The extension core writes file_name; older senders wrote name.
          // Read from inside the seal, so the link needs no &n= (hertest T4-9).
          const mn = meta && (typeof meta.file_name === 'string' ? meta.file_name : meta.name);
          if (!metaName && typeof mn === 'string' && mn) metaName = mn;
          chunks.push(data);
        }
        const total = chunks.reduce((n, c) => n + c.length, 0);
        fileData = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) { fileData.set(c, off); off += c.length; }
        filename = metaName || LINK.name || 'download';
      }
    } catch {
      releaseAll(tokens);
      showError(t('decFail'));
      return;
    }

    // The file is whole and opened. Only now is the relay copy burned.
    await ackAll(tokens);
    acked = true;
    forgetClaim();
    await deliver(filename, fileData);
  } catch (e) {
    // Never a raw engine message on the receiver's screen (hertest T4-L1).
    // Before the ack nothing is spent; after it, "try again" would be untrue.
    if (!acked) { releaseAll(tokens); showError(t('netFail')); }
    else showError(t('unknown'));
  } finally {
    busyDownloading = false;
  }
}

async function deliver(filename, fileData) {
  // Detect PDF via magic bytes (%PDF). No header schema change required.
  const isPdf = fileData.length >= 4 &&
                fileData[0] === 0x25 && fileData[1] === 0x50 &&
                fileData[2] === 0x44 && fileData[3] === 0x46;

  if (isPdf) {
    setStatus(t('opening'), 90);
    try {
      const preview = await renderPdfPreview(fileData);
      setStatus(t('done'), 100);
      // Same heading and same shape as every other ending. The sentence says
      // what is true of THIS branch: nothing has been written to disk yet,
      // and the link is already spent, so saving is the one thing left to do.
      const pageCount = t('pages')(preview.pages, preview.shown);
      window.paramantDone.fill('step-done', {
        title: t('haveFile'),
        line: t('pdfLine')(filename, pageCount, formatSize(fileData.length)),
      });
      window.paramantDone.payload('step-done', preview.node);
      const note = document.getElementById('done-pdf-note');
      if (note) note.hidden = false;
      // One loud button, and on this branch it is the save that has not
      // happened yet. The bytes are deliberately NOT dropped when the tab
      // goes to the background: the document is on the screen, and a reader
      // who comes back to it has to still be able to save it.
      savedFile = { name: filename, bytes: fileData, mime: 'application/pdf' };
      const saveBtn = document.getElementById('done-save');
      if (saveBtn) saveBtn.textContent = t('save');
      showStep('step-done');
      return;
    } catch (e) {
      // Fall through to the plain save if the document will not open.
      setStatus(t('pdfFallback'), 95);
    }
  }

  setStatus(t('saving'), 90);

  // Trigger browser download (non-PDF path, or PDF preview fallback)
  const blob = new Blob([fileData]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);

  setStatus(t('done'), 100);

  // The end screen. One sentence in ordinary words; the algorithm names live
  // in the folded <details> next to it, not on the reader's face.
  window.paramantDone.fill('step-done', {
    title: t('haveFile'),
    line: t('savedLine')(filename, formatSize(fileData.length)),
  });
  // A browser can refuse or a person can dismiss a save dialog, and the bytes
  // are then unreachable for good: the link is spent and will not open again.
  // So the one primary button on this screen offers the save a second time.
  // The bytes are held for exactly as long as this tab is in front of
  // somebody, and dropped the moment it is not, which is the same bargain
  // /ontvang already makes on its own done screen.
  savedFile = { name: filename, bytes: fileData };
  document.addEventListener('visibilitychange', dropSavedFile);
  showStep('step-done');

}

// The file this tab may still hand over a second time, and the rule for
// letting go of it. See the note where it is filled, above.
let savedFile = null;
function dropSavedFile() {
  if (!document.hidden) return;
  savedFile = null;
  document.removeEventListener('visibilitychange', dropSavedFile);
  const btn = document.getElementById('done-save');
  if (btn) btn.hidden = true;
}
function saveAgain() {
  if (!savedFile) return;
  downloadBytes(savedFile.bytes, savedFile.name, savedFile.mime || 'application/octet-stream');
}

window.addEventListener('DOMContentLoaded', init);

act('click','goReceive',()=>goReceive());
window.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('enter-link');
  if (el) el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); goReceive(); }
  });
});
act('click','saveAgain',()=>saveAgain());
act('click','startDownload',()=>startDownload());
act('click','retryDownload',()=>startDownload());
