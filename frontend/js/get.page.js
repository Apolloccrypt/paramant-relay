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
    decFail: 'Ontsleutelen is mislukt. De link is misschien beschadigd of aangepast.',
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
    decFail: 'Decryption failed. The link may be corrupted or tampered with.',
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

// The language switch keeps the whole address, the key after # included, so
// it never travels anywhere but this browser.
function langSwitch() {
  const a = document.getElementById('lang-switch-link');
  if (!a) return;
  // With a one-time link in the address the file is fetched on arrival, so a
  // second load in the other language would find it already gone. The switch
  // is only offered on the bare page.
  if (new URLSearchParams(location.search).get('t')) {
    (a.closest('.lang-switch') || a).hidden = true;
    return;
  }
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

async function init() {
  const params = new URLSearchParams(location.search);
  const token = params.get('t');
  const fragment = location.hash.slice(1);
  const RELAY = RELAY_SECTORS[params.get('r')] || DEFAULT_RELAY;

  if (!token && !fragment) {
    showStep('step-enter');
    return;
  }
  // A missing half, a token of the wrong shape or a key that is too short all
  // mean the same to the receiver: the link did not arrive whole.
  if (!token || !fragment || !TOKEN_RE.test(token)) {
    showInvalid();
    return;
  }

  // Decode key+iv from fragment (44 bytes: first 32 = AES key, next 12 = IV)
  const keyIv = fromB64url(fragment);
  if (!keyIv || keyIv.length < 44) {
    showInvalid();
    return;
  }
  const rawKey = keyIv.slice(0, 32);
  const iv = keyIv.slice(32, 44);

  try {
    setTitle(t('importTitle'));
    setStatus(t('importStatus'), 10);
    const aesKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);

    setTitle(t('dlTitle'));
    setStatus(t('dlStatus'), 30);

    const r = await fetch(RELAY + '/v2/dl/' + token + '/get', {
      signal: AbortSignal.timeout(60000),
    });

    if (r.status === 410 || r.status === 404) {
      showStep('step-burned');
      return;
    }
    if (r.status === 400 || r.status === 401) {
      showInvalid();
      return;
    }
    if (!r.ok) {
      throw new Error(t('dlFail')(r.status));
    }

    setTitle(t('decTitle'));
    setStatus(t('decStatus'), 65);

    const ciphertext = await r.arrayBuffer();
    let plaintext;
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext));
    } catch {
      showError(t('decFail'));
      return;
    }

    // Parse header: [uint32-LE nameLen][nameBytes][fileBytes]
    if (plaintext.length < 4) throw new Error(t('tooShort'));
    const nameLen = new DataView(plaintext.buffer).getUint32(0, true);
    if (plaintext.length < 4 + nameLen) throw new Error(t('headerBad'));
    const filename = new TextDecoder().decode(plaintext.slice(4, 4 + nameLen)) || 'download';
    const fileData = plaintext.slice(4 + nameLen);

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

  } catch (e) {
    showError(e.message || t('unknown'));
  }
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
