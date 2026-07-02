'use strict';

const RELAY = 'https://health.paramant.app';

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
  if (window.__pdfjsLib) return window.__pdfjsLib;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('PDF.js failed to load')), 10000);
    window.addEventListener('pdfjs:ready', () => { clearTimeout(t); resolve(window.__pdfjsLib); }, { once: true });
  });
}

async function renderPdfPreview(bytes, name) {
  const pdfjs = await waitForPdfjs();
  // PDF.js mutates the input buffer. Pass a copy so the original stays intact
  // for the download-original path.
  const copy = new Uint8Array(bytes);
  const pdf = await pdfjs.getDocument({ data: copy, disableAutoFetch: true, disableStream: true }).promise;

  const container = document.getElementById('preview-canvas-list');
  container.innerHTML = '';
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
    wrap._pdfPage = { width: baseViewport.width, height: baseViewport.height, index: i - 1 };
    const canvas = document.createElement('canvas');
    canvas.width = Math.floor(viewport.width);
    canvas.height = Math.floor(viewport.height);
    wrap.appendChild(canvas);
    container.appendChild(wrap);
    await page.render({ canvasContext: canvas.getContext('2d'), viewport }).promise;
  }

  document.getElementById('preview-filename').textContent = name;
  document.getElementById('preview-pagecount').textContent =
    pdf.numPages + ' page' + (pdf.numPages === 1 ? '' : 's') +
    (pdf.numPages > MAX_PAGES ? ' (showing first ' + MAX_PAGES + ')' : '');
  document.getElementById('preview-filesize').textContent = formatSize(bytes.length);

  const dlBtn = document.getElementById('preview-download');
  dlBtn.onclick = () => downloadBytes(bytes, name, 'application/pdf');
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

function goReceive() {
  const el = document.getElementById('enter-link');
  const errEl = document.getElementById('enter-err');
  if (errEl) errEl.textContent = '';
  const v = (el && el.value || '').trim();
  if (!v) return;
  try { location.href = new URL(v, location.origin).href; }
  catch { if (errEl) errEl.textContent = 'That does not look like a valid receive link.'; }
}

async function init() {
  const params = new URLSearchParams(location.search);
  const token = params.get('t');
  const fragment = location.hash.slice(1);

  if (!token && !fragment) {
    showStep('step-enter');
    return;
  }
  if (!token || !fragment) {
    showError('Invalid link — missing download token or encryption key.');
    return;
  }

  // Decode key+iv from fragment (44 bytes: first 32 = AES key, next 12 = IV)
  const keyIv = fromB64url(fragment);
  if (!keyIv || keyIv.length < 44) {
    showError('Invalid link — encryption key is malformed or truncated.');
    return;
  }
  const rawKey = keyIv.slice(0, 32);
  const iv = keyIv.slice(32, 44);

  try {
    setTitle('Importing key...');
    setStatus('Importing decryption key...', 10);
    const aesKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);

    setTitle('Downloading...');
    setStatus('Downloading encrypted file from relay...', 30);

    const r = await fetch(RELAY + '/v2/dl/' + token + '/get', {
      signal: AbortSignal.timeout(60000),
    });

    if (r.status === 410 || r.status === 404) {
      showStep('step-burned');
      return;
    }
    if (!r.ok) {
      throw new Error('Download failed: HTTP ' + r.status);
    }

    setTitle('Decrypting...');
    setStatus('Decrypting with AES-256-GCM...', 65);

    const ciphertext = await r.arrayBuffer();
    let plaintext;
    try {
      plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext));
    } catch {
      showError('Decryption failed. The link may be corrupted or tampered with.');
      return;
    }

    // Parse header: [uint32-LE nameLen][nameBytes][fileBytes]
    if (plaintext.length < 4) throw new Error('Decrypted payload too short');
    const nameLen = new DataView(plaintext.buffer).getUint32(0, true);
    if (plaintext.length < 4 + nameLen) throw new Error('Decrypted payload header corrupt');
    const filename = new TextDecoder().decode(plaintext.slice(4, 4 + nameLen)) || 'download';
    const fileData = plaintext.slice(4 + nameLen);

    // Detect PDF via magic bytes (%PDF). No header schema change required.
    const isPdf = fileData.length >= 4 &&
                  fileData[0] === 0x25 && fileData[1] === 0x50 &&
                  fileData[2] === 0x44 && fileData[3] === 0x46;

    if (isPdf) {
      setStatus('Rendering PDF in browser...', 90);
      try {
        await renderPdfPreview(fileData, filename);
        setStatus('Done.', 100);
        showStep('step-preview');
        return;
      } catch (e) {
        // Fall through to download if preview fails for any reason.
        setStatus('Preview unavailable, downloading instead...', 95);
      }
    }

    setStatus('Saving file...', 90);

    // Trigger browser download (non-PDF path, or PDF preview fallback)
    const blob = new Blob([fileData]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 2000);

    setStatus('Done.', 100);

    document.getElementById('done-filename').textContent = filename;
    document.getElementById('done-filesize').textContent = formatSize(fileData.length);
    showStep('step-done');

  } catch (e) {
    showError(e.message || 'Unknown error');
  }
}

window.addEventListener('DOMContentLoaded', init);

act('click','goReceive',()=>goReceive());
