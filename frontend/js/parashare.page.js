'use strict';

const RELAY_WS  = 'wss://relay.paramant.app';
const RELAY_SECTORS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};
let RELAY_API = RELAY_SECTORS.health; // updated after key validation

let apiKey = '', keyValid = false, selectedFile = null, selectedFiles = [];
let sessionToken = '', ws = null;
let receiverPubs = null;

// ── Helpers ──
function $(id) { return document.getElementById(id); }
function showStep(id) {
  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  $(id).classList.add('active');
  globeOnStepChange(id);
  // The 5-stage stepper describes the sender's journey. Hide it for the
  // receiver-only download path (step-tb-download); show + advance otherwise.
  var stepper = $('ps-stepper');
  if (stepper) stepper.style.display = (id === 'step-tb-download') ? 'none' : '';
  var stepperKey = ({
    'step-setup': 'setup',
    'step-waiting': 'share',
    'step-encrypting': 'encrypt',
    'step-done': 'done'
  })[id];
  if (stepperKey) setStepperStage(stepperKey);
}

// Stepper: highlight current stage, mark earlier stages as done.
var STEPPER_ORDER = ['setup', 'share', 'verify', 'encrypt', 'done'];
function setStepperStage(key) {
  var idx = STEPPER_ORDER.indexOf(key);
  if (idx < 0) return;
  var nodes = document.querySelectorAll('#ps-stepper .ps-step');
  nodes.forEach(function(n, i) {
    n.classList.remove('active');
    n.classList.remove('done');
    if (i < idx) n.classList.add('done');
    else if (i === idx) n.classList.add('active');
  });
}

// Show the full API-key card (used by the "Change" link in the slim row)
function expandApiKeyCard() {
  var s = $('step-setup');
  if (s) s.classList.remove('has-saved-key');
  var inp = $('api-key');
  if (inp) { inp.value = ''; inp.focus(); onKeyInput(); }
  try { localStorage.removeItem('paramant_api_key'); } catch (_) {}
}

// Apply slim API-key view when a key was auto-fetched (login flow) or
// saved locally. Pure cosmetic: the underlying input still holds the key.
function applySlimApiKeyView() {
  var inp = $('api-key');
  if (!inp || !inp.value) return;
  var mask = $('ps-key-mask');
  if (mask) {
    var v = inp.value;
    mask.textContent = v.length > 14 ? v.slice(0, 8) + '...' + v.slice(-4) : v;
  }
  var s = $('step-setup');
  if (s) s.classList.add('has-saved-key');
}
function setStatus(id, msg, cls) {
  const el = $(id);
  el.textContent = msg;
  el.className = 'status-line' + (cls ? ' ' + cls : '');
}

// SHA-256(kyber_pub || ecdh_pub) → first 10 bytes → 5×4 hex groups
// Both parties compute independently; mismatch = relay MITM detected.
async function genFingerprint(kyberPubHex, ecdhPubHex) {
  const buf = hexToU8(kyberPubHex + (ecdhPubHex || ''));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  const h = [...hash.slice(0, 10)].map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
  return `${h.slice(0,4)}-${h.slice(4,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}`;
}

function u8toHex(u8) {
  return [...u8].map(b => b.toString(16).padStart(2,'0')).join('');
}
function hexToU8(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i*2, i*2+2), 16);
  return arr;
}
function concat(...arrays) {
  const total = arrays.reduce((s,a) => s + a.length, 0);
  const out = new Uint8Array(total); let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}
function u32be(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}
function toB64(u8) {
  let s = ''; const SZ = 8192;
  for (let i = 0; i < u8.length; i += SZ) s += String.fromCharCode(...u8.slice(i,i+SZ));
  return btoa(s);
}

async function copyLink() {
  const url = $('session-link').textContent;
  await navigator.clipboard.writeText(url).catch(()=>{});
  $('session-link').textContent = '✓ Copied!';
  setTimeout(() => { $('session-link').textContent = url; }, 2000);
}

// ── Fingerprint localStorage (TOFU) ──
function fpStorageKey(fp) { return 'paramant_fp_' + fp.replace(/-/g,''); }
function storeFingerprintConfirmed(fp) {
  try { localStorage.setItem(fpStorageKey(fp), JSON.stringify({ fp, ts: new Date().toISOString() })); } catch {}
}
function isFingerprintKnown(fp) {
  try { return !!localStorage.getItem(fpStorageKey(fp)); } catch { return false; }
}

// ── QR code for fingerprint ──
function renderFingerprintQR(fp) {
  const canvas = $('fp-qr');
  if (!canvas || typeof QRCode === 'undefined') return;
  try {
    QRCode.toCanvas(canvas, fp, { width: 140, margin: 1, color: { dark: '#000', light: '#fff' } });
    canvas.style.display = '';
    const lbl = $('fp-qr-label');
    if (lbl) lbl.style.display = '';
  } catch(e) { console.warn('QR render failed:', e); }
}

// ── Helpers ──
async function showReceiverConnected(kyberPub, ecdhPub) {
  receiverPubs = { kyber_pub: kyberPub, ecdh_pub: ecdhPub };
  const fp = await genFingerprint(kyberPub, ecdhPub);
  $('fp-card').style.display = '';
  $('fp-display').textContent = fp;
  $('waiting-title').textContent = 'Receiver connected';
  $('waiting-dot').className = 'dot';
  setStatus('waiting-status', 'Receiver is waiting for you to verify the fingerprint');
  setStepperStage('verify');
  // TOFU: check if we've verified this fingerprint before
  if (isFingerprintKnown(fp)) {
    $('fp-seen-before').style.display = '';
    $('fp-new-device').style.display = 'none';
  } else {
    $('fp-new-device').style.display = '';
    $('fp-seen-before').style.display = 'none';
  }
  // Render QR code for easy scanning
  renderFingerprintQR(fp);
}

// ── Relay discovery: try all sectors in parallel, pick first valid ──
async function discoverRelay(key) {
  const results = await Promise.allSettled(
    Object.entries(RELAY_SECTORS).map(async ([sector, url]) => {
      const r = await fetch(`${url}/v2/check-key`, {
        headers: { 'X-Api-Key': key },
        signal: AbortSignal.timeout(5000)
      });
      const d = await r.json();
      if (!d.valid) throw new Error('invalid');
      return { sector, url, plan: d.plan };
    })
  );
  const valid = results.filter(r => r.status === 'fulfilled').map(r => r.value);
  if (!valid.length) return null;
  // Prefer health; otherwise first sector that responded
  return valid.find(v => v.sector === 'health') || valid[0];
}

// ── Key validation ──
async function onKeyInput() {
  apiKey = $('api-key').value.trim();
  if (apiKey) localStorage.setItem('paramant_api_key', apiKey);
  if (apiKey.length < 10 || !apiKey.startsWith('pgp_')) {
    setStatus('key-status', 'Invalid format');
    keyValid = false; updateBtn(); return;
  }
  setStatus('key-status', 'Checking...');
  try {
    const found = await discoverRelay(apiKey);
    if (found) {
      RELAY_API = found.url;
      const sectorLabel = found.sector !== 'health' ? ` · ${found.sector}` : '';
      setStatus('key-status', `✓ Valid — plan: ${found.plan}${sectorLabel}`, 'ok');
      keyValid = true;
    } else {
      setStatus('key-status', 'Invalid or revoked key', 'err');
      keyValid = false;
    }
  } catch(e) {
    setStatus('key-status', 'Could not verify key', 'err');
    keyValid = false;
  }
  updateBtn();
}

function onFileSelect() {
  const files = $('file-input').files;
  selectedFile = files[0] || null;
  if (!files.length) { setStatus('file-status', 'No file selected'); $('vault-list').style.display='none'; updateBtn(); return; }
  if (files.length === 1) {
    setStatus('file-status', '✓ ' + files[0].name + ' (' + (files[0].size/1024/1024).toFixed(1) + ' MB)', 'ok');
    $('vault-list').style.display = 'none';
  } else {
    setStatus('file-status', '✓ ' + files.length + ' files selected — vault mode', 'ok');
    const vl = $('vault-list');
    vl.style.display = 'block';
    vl.innerHTML = [...files].map(f =>
      '<div style="font-size:10px;color:rgba(248,250,252,.65);padding:2px 0;font-family:var(--mono)">' + f.name + ' <span style="color:rgba(248,250,252,.5)">(' + (f.size/1024/1024).toFixed(1) + ' MB)</span></div>'
    ).join('');
  }
  updateBtn();
}

function updateBtn() {
  selectedFiles = $('file-input') ? [...$('file-input').files] : [];
  $('btn-create-session').disabled = !(keyValid && selectedFiles.length > 0);
}

// ── Session creation ──
async function createSession() {
  // Generate random invite token
  const tokenBytes = crypto.getRandomValues(new Uint8Array(16));
  sessionToken = 'inv_' + u8toHex(tokenBytes).slice(0, 32);

  // Build receiver URL
  const activeSector = Object.entries(RELAY_SECTORS).find(([, u]) => u === RELAY_API)?.[0] || 'health';
  const recvUrl = `${location.origin}/ontvang?s=${encodeURIComponent(sessionToken)}&r=${activeSector}`;
  $('session-link').textContent = recvUrl;

  showStep('step-waiting');
  connectWebSocket();
}

// ── WebSocket signaling ──
async function connectWebSocket() {
  let wsUrl = RELAY_WS + '/v2/stream';
  try {
    // Ticket must come from the same relay host the WS connects to (relay-main)
    const wsHttpBase = RELAY_WS.replace('wss://', 'https://').replace('ws://', 'http://');
    const tr = await fetch(`${wsHttpBase}/v2/ws-ticket`, {method:'POST',headers:{'X-Api-Key':apiKey},signal:AbortSignal.timeout(5000)});
    if (tr.ok) { const td = await tr.json(); if (td.ticket) wsUrl += '?ticket=' + encodeURIComponent(td.ticket); }
  } catch {}
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    // Join the invite room
    ws.send(JSON.stringify({ type: 'join', room: sessionToken, nick: 'sender' }));
    setStatus('waiting-status', 'Waiting for receiver to open the link...');
  };

  // Poll voor receiver pubkey via ghost pipe relay
  let pubkeyPollInterval = setInterval(async () => {
    try {
      const r = await fetch(`${RELAY_API}/v2/pubkey/${encodeURIComponent(sessionToken)}`, { headers: { 'X-Api-Key': apiKey }, signal: AbortSignal.timeout(3000) });
      if (r.ok) {
        const d = await r.json();
        if (d.kyber_pub && d.ecdh_pub) {
          clearInterval(pubkeyPollInterval);
          await showReceiverConnected(d.kyber_pub, d.ecdh_pub);
        }
      }
    } catch(e) {}
  }, 2000);

  ws.onmessage = async (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }

    try {
      if (msg.type === 'pubkey_offer' && msg.kyber_pub && msg.ecdh_pub) {
        await showReceiverConnected(msg.kyber_pub, msg.ecdh_pub);
      }

      if (msg.type === 'peer_left') {
        setStatus('waiting-status', 'Receiver disconnected', 'err');
      }
    } catch(err) {
      console.error('ws.onmessage handler error:', err);
      setStatus('waiting-status', 'Error processing receiver message — ' + err.message, 'err');
    }
  };

  ws.onerror = () => setStatus('waiting-status', 'Connection error', 'err');
  ws.onclose = () => { if (!receiverPubs) setStatus('waiting-status', 'Disconnected', 'err'); };
}

// ── Fingerprint confirmed — encrypt & send ──
async function confirmFingerprint() {
  if (!receiverPubs) return;
  if (!document.getElementById('fp-confirm-check')?.checked) return;

  // Guard: abort if WASM crypto bridge failed to load
  if (!window._cryptoBridge?.encryptBlob) {
    setStatus('waiting-status', 'ERROR: WASM crypto module not loaded — cannot encrypt safely. Refresh and try again.', 'err');
    return;
  }

  // Store confirmed fingerprint in localStorage (TOFU)
  const confirmedFp = $('fp-display').textContent;
  if (confirmedFp && confirmedFp !== '—') storeFingerprintConfirmed(confirmedFp);

  // Tell receiver we confirmed (best-effort via WS — file transfer uses HTTP anyway)
  try { ws.send(JSON.stringify({ type: 'packet', chatHash: sessionToken, seq: 0, payload: JSON.stringify({ type: 'fingerprint_ok' }) })); } catch(e) { console.warn('WS send failed (non-fatal):', e.message); }

  showStep('step-encrypting');

  try {
    const CHUNK_PLAIN = 4.5 * 1024 * 1024;
    const META_MAGIC = new Uint8Array([0x50, 0x52, 0x53, 0x48]);
    const ttlMs = parseInt($('ttl-select').value);

    // Helper: encrypt + upload one file, returns token array
    async function encryptFile(file, fileIndex, totalFiles) {
      const totalChunks = Math.ceil(file.size / CHUNK_PLAIN) || 1;
      const fileId = u8toHex(crypto.getRandomValues(new Uint8Array(8)));
      const tokens = [];

      // Grootte-waarschuwing bij > 500MB
      if (file.size > 500 * 1024 * 1024) {
        $('enc-status').textContent = 'Large file (' + (file.size/1024/1024/1024).toFixed(2) + ' GB) — streaming mode, reading chunk by chunk...';
        await new Promise(r => setTimeout(r, 400));
      }

      for (let i = 0; i < totalChunks; i++) {
        const globalPct = Math.round(
          ((fileIndex + (i / totalChunks)) / totalFiles) * 85
        );
        $('enc-progress').style.width = globalPct + '%';
        const mbDone = Math.round((i * CHUNK_PLAIN) / 1024 / 1024);
        const mbTotal = Math.round(file.size / 1024 / 1024);
        $('enc-status').textContent = (totalFiles > 1 ? 'File ' + (fileIndex+1) + '/' + totalFiles + ' — ' : '') +
          'Encrypting ' + mbDone + '/' + mbTotal + ' MB (chunk ' + (i+1) + '/' + totalChunks + ')...';

        const start = Math.round(i * CHUNK_PLAIN);
        const end = Math.min(start + CHUNK_PLAIN, file.size);
        // Stream-read: alleen dit chunk in RAM, niet het hele bestand
        const chunkData = new Uint8Array(await file.slice(start, end).arrayBuffer());

        const metaJson = JSON.stringify({
          file_id: fileId, file_name: file.name,
          file_size: file.size, chunk_index: i,
          total_chunks: totalChunks, chunk_size: chunkData.length
        });
        const metaBytes = new TextEncoder().encode(metaJson);
        const payload = concat(META_MAGIC, u32be(metaBytes.length), metaBytes, chunkData);

        // ML-KEM-768 + ECDH P-256 + AES-256-GCM via Rust/WASM (crypto-bridge.js)
        const padded = await window._cryptoBridge.encryptBlob(
          payload,
          hexToU8(receiverPubs.kyber_pub),
          hexToU8(receiverPubs.ecdh_pub)
        );

        const mbUp = Math.round((i * CHUNK_PLAIN) / 1024 / 1024);
        $('enc-status').textContent = (totalFiles > 1 ? 'File ' + (fileIndex+1) + '/' + totalFiles + ' — ' : '') +
          'Uploading ' + mbUp + '/' + Math.round(file.size/1024/1024) + ' MB...';
        const hashBuf = await crypto.subtle.digest('SHA-256', padded);
        const hash = u8toHex(new Uint8Array(hashBuf));

        const ur = await fetch(RELAY_API + '/v2/inbound', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
          body: JSON.stringify({
            hash, payload: toB64(padded), ttl_ms: ttlMs,
            // file_name omitted — filename is only in the encrypted payload (finding #4)
            meta: { device_id: 'transfer-web', chunk_index: i, total_chunks: totalChunks, file_id: fileId }
          }),
          signal: AbortSignal.timeout(120000)
        });
        const ud = await ur.json();
        if (!ud.ok) throw new Error(ud.error || 'Upload failed: ' + file.name);
        tokens.push(ud.download_token);
      }
      return { name: file.name, size: file.size, tokens };
    }

    // Upload all files
    const files = [...$('file-input').files];
    const vaultFiles = [];
    for (let fi = 0; fi < files.length; fi++) {
      vaultFiles.push(await encryptFile(files[fi], fi, files.length));
    }

    $('enc-progress').style.width = '100%';
    $('enc-status').textContent = 'Notifying receiver...';

    const isVault = files.length > 1;
    await fetch(RELAY_API + '/v2/pubkey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
      body: JSON.stringify({
        device_id: sessionToken + '_ready',
        ecdh_pub: isVault ? JSON.stringify(vaultFiles) : vaultFiles[0].tokens.join(','),
        kyber_pub: isVault
          ? 'vault|' + files.length + '|' + ttlMs
          : files[0].name + '|' + vaultFiles[0].tokens.length + '|' + ttlMs
      })
    });

    const label = isVault
      ? files.length + ' files sent — vault ready for receiver'
      : files[0].name + ' sent securely';
    $('done-status').textContent = '✓ ' + label;
    showStep('step-done');

  } catch(e) {
    $('enc-status').textContent = 'Error: ' + e.message;
    $('enc-status').className = 'status-line err';
  }
}

function rejectFingerprint() {
  ws.close();
  showStep('step-setup');
  setStatus('key-status', 'Transfer aborted — fingerprint mismatch', 'err');
}

// ── Globe HUD ─────────────────────────────────────────────────────────────────
let globeInstance = null, globeOpen = false, globePollInterval = null;
let _gUserLat = null, _gUserLng = null;  // set after geo lookup
const RELAY_LOC = { lat: 50.1109, lng: 8.6821, label: 'Relay · Nuremberg EU/DE' };

// Keyboard shortcut
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'g') { e.preventDefault(); toggleGlobe(); }
  if (e.key === 'Escape' && globeOpen) toggleGlobe();
});

// ── Thunderbird FileLink download — URL format: ?t=T1,T2&n=NAME&c=N&r=RELAY#k=K1,K2 ──
// Keys travel in the fragment (never sent to server). Relay only sees download tokens.
async function tbDecryptChunk(blobBytes, rawKeyB64url) {
  // Decode URL-safe base64 (no padding)
  const b64 = rawKeyB64url.replace(/-/g,'+').replace(/_/g,'/');
  const padded64 = b64 + '=='.slice(0, (4 - b64.length % 4) % 4);
  const rawKey = Uint8Array.from(atob(padded64), c => c.charCodeAt(0));
  const blob = new Uint8Array(blobBytes);
  const version = blob[0];
  if (version !== 0x02) throw new Error('Unsupported packet version ' + version + ' — this link was generated by an older version');
  const nonce  = blob.slice(1, 13);
  const ctLen  = new DataView(blob.buffer, 13, 4).getUint32(0, false);
  const ct     = blob.slice(17, 17 + ctLen);
  const symKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  const plain  = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, symKey, ct));
  // PRSH layout: magic(4) | metaLen(4) | metaJSON | chunkData
  if (plain[0]!==0x50||plain[1]!==0x52||plain[2]!==0x53||plain[3]!==0x48) throw new Error('Invalid decrypted payload — wrong key?');
  const metaLen = new DataView(plain.buffer, 4, 4).getUint32(0, false);
  const data = plain.slice(8 + metaLen);
  return data;
}

async function tbDownload(tokensParam, name, relay, keysParam) {
  const tokens = tokensParam.split(',');
  const keys   = keysParam.split(',');
  if (tokens.length !== keys.length) throw new Error('Token/key count mismatch in URL');
  const dlStatus = $('tb-dl-status');
  const dlBar    = $('tb-dl-bar');
  const chunks = [];
  for (let i = 0; i < tokens.length; i++) {
    dlStatus.textContent = 'Downloading chunk ' + (i+1) + ' of ' + tokens.length + '…';
    dlBar.style.width = Math.round((i / tokens.length) * 60) + '%';
    const resp = await fetch(relay + '/v2/dl/' + tokens[i] + '/get');
    if (!resp.ok) throw new Error('Download failed: HTTP ' + resp.status + ' for chunk ' + i);
    const buf = await resp.arrayBuffer();
    dlStatus.textContent = 'Decrypting chunk ' + (i+1) + '…';
    const data = await tbDecryptChunk(buf, keys[i]);
    chunks.push(data);
    dlBar.style.width = Math.round(((i+1) / tokens.length) * 90) + '%';
  }
  // Reassemble
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const assembled = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { assembled.set(c, off); off += c.length; }
  dlBar.style.width = '100%';
  dlStatus.className = 'status-line ok';
  dlStatus.textContent = 'Decrypted — saving file…';
  // Trigger browser download
  const url = URL.createObjectURL(new Blob([assembled]));
  const a = document.createElement('a');
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  $('tb-dl-title').textContent = 'Downloaded.';
  $('tb-dl-sub').textContent   = 'File decrypted and saved. The key existed only in your browser.';
  $('tb-dl-dot').className     = 'dot';
}

// Auto-init globe as background on load, restore saved API key
document.addEventListener('DOMContentLoaded', () => {
  // Thunderbird FileLink download mode — check before restoring upload UI
  const sp = new URLSearchParams(location.search);
  const tbTokens = sp.get('t');
  const tbRelay  = sp.get('r');
  const tbKeys   = location.hash.startsWith('#k=') ? location.hash.slice(3) : null;
  if (tbTokens && tbKeys && tbRelay) {
    showStep('step-tb-download');
    tbDownload(tbTokens, decodeURIComponent(sp.get('n') || 'download'), decodeURIComponent(tbRelay), tbKeys)
      .catch(e => {
        $('tb-dl-status').className = 'status-line err';
        $('tb-dl-status').textContent = 'Error: ' + e.message;
        $('tb-dl-dot').className = 'dot red';
      });
    setTimeout(() => initGlobe(), 400);
    return;
  }

  // Prefer the session-derived key: if the user is logged in, their current API key
  // is the authoritative value. localStorage may still hold a stale key from a
  // previous (revoked/rotated) account and would otherwise show "Invalid key".
  (async function resolveKey(){
    try {
      const r = await fetch('/api/user/account/key', { credentials: 'include' });
      if (r.ok) {
        const d = await r.json();
        if (d && d.api_key) {
          $('api-key').value = d.api_key;
          try { localStorage.setItem('paramant_api_key', d.api_key); } catch {}
          onKeyInput();
          applySlimApiKeyView();
          return;
        }
      }
    } catch {}
    // Not logged in or endpoint unavailable: fall back to localStorage (manual paste flow).
    const saved = localStorage.getItem('paramant_api_key');
    if (saved) {
      $('api-key').value = saved;
      onKeyInput();
      applySlimApiKeyView();
    }
  })();
  // Small delay so DOM is fully painted before Globe.gl reads dimensions
  setTimeout(() => initGlobe(), 400);
});

function toggleGlobe() {
  const overlay = document.getElementById('globe-overlay');
  const mainEl  = document.querySelector('main');
  const navEl   = document.querySelector('nav');
  globeOpen = !globeOpen;
  if (globeOpen) {
    // Fullscreen HUD mode: hide UI, show HUD panels
    overlay.classList.add('globe-fullscreen');
    if (mainEl) mainEl.style.display = 'none';
    const _gb = document.getElementById('globe-btn'); if (_gb) _gb.style.color = '#B2FF3F';
    if (_gb) _gb.style.boxShadow = '0 0 12px rgba(178,255,63,.3)';
    if (_gb) _gb.textContent = '✕ Close';
  } else {
    // Background mode: restore UI, hide HUD panels
    overlay.classList.remove('globe-fullscreen');
    if (mainEl) mainEl.style.display = '';
    const _gb2 = document.getElementById('globe-btn'); if (_gb2) _gb2.style.color = '';
    if (_gb2) _gb2.style.boxShadow = '';
    if (_gb2) _gb2.textContent = '⬡ Globe';
    if (globePollInterval) { clearInterval(globePollInterval); globePollInterval = null; }
  }
}

function loadScript(src) {
  return new Promise((ok, fail) => {
    if (document.querySelector(`script[src="${src}"]`)) { ok(); return; }
    const s = document.createElement('script');
    s.src = src; s.onload = ok; s.onerror = fail;
    document.head.appendChild(s);
  });
}

async function initGlobe() {
  if (globeInstance) { startGlobePoll(); return; }

  // Dynamisch laden — alleen als globe geopend wordt
  try {
    await loadScript('/globe.gl.min.js');
  } catch(e) {
    document.getElementById('globe-loading').innerHTML =
      '<span style="color:#e05252">Failed to load Globe.gl — check network</span>';
    return;
  }

  // Gebruikerslocatie: gebruik relay-locatie als fallback (privacy — geen externe IP lookup)
  let userLat = RELAY_LOC.lat + 0.5, userLng = RELAY_LOC.lng - 2;
  _gUserLat = userLat; _gUserLng = userLng;
  document.getElementById('hud-loc').textContent = 'EU · DE';

  const wrap = document.getElementById('globe-canvas-wrap');

  // Globe.gl instantiëren
  globeInstance = Globe({ animateIn: true })
    .globeImageUrl('/images/globe/earth-night.jpg')
    .bumpImageUrl('/images/globe/earth-topology.png')
    .backgroundImageUrl('/images/globe/night-sky.png')
    .showAtmosphere(true)
    .atmosphereColor('#B2FF3F')
    .atmosphereAltitude(0.18)
    // HTML dots — crisp DOM elements, no pixelation at any zoom
    .htmlElementsData([
      { lat: userLat,      lng: userLng,      label: 'Your Node',          type: 'user'  },
      { lat: RELAY_LOC.lat, lng: RELAY_LOC.lng, label: RELAY_LOC.label,   type: 'relay' },
    ])
    .htmlElement(d => {
      const wrap = document.createElement('div');
      const color = d.type === 'relay' ? '#B2FF3F' : 'var(--ink-dim)';
      wrap.innerHTML = `<div title="${d.label}" style="
        width:14px;height:14px;border-radius:50%;
        background:${color};
        box-shadow:0 0 10px ${color},0 0 20px ${color}55;
        border:2px solid rgba(255,255,255,.5);
        cursor:pointer;position:relative">
        <div style="position:absolute;top:-22px;left:50%;transform:translateX(-50%);
          white-space:nowrap;font:9px/1.2 monospace;color:${color};
          background:rgba(12,12,12,.8);padding:2px 5px;
          pointer-events:none;letter-spacing:.06em">${d.label}</div>
      </div>`;
      return wrap.firstChild;
    })
    .htmlTransitionDuration(0)
    // Transfer arc gebruiker → relay
    .arcsData([
      {
        startLat: userLat, startLng: userLng,
        endLat: RELAY_LOC.lat, endLng: RELAY_LOC.lng,
        color: ['rgba(178,255,63,0)', '#B2FF3F', '#B2FF3F', 'rgba(178,255,63,0)'],
        label: 'Ghost Pipe · Encrypted Channel',
      }
    ])
    .arcColor(d => d.color)
    .arcDashLength(0.35)
    .arcDashGap(0.18)
    .arcDashAnimateTime(2200)
    .arcStroke(0.4)
    .arcAltitudeAutoScale(0.35)
    .arcLabel(d => `<div style="font:10px monospace;background:rgba(12,12,12,.9);
      border:1px solid rgba(178,255,63,.25);padding:4px 8px;color:#B2FF3F">${d.label}</div>`)
    // Pulserende ringen op knooppunten
    .ringsData([
      { lat: userLat, lng: userLng, maxR: 3, propagationSpeed: 2.5, repeatPeriod: 1200, color: () => 'rgba(178,255,63,' },
      { lat: RELAY_LOC.lat, lng: RELAY_LOC.lng, maxR: 2.5, propagationSpeed: 2, repeatPeriod: 1600, color: () => 'rgba(178,255,63,' },
    ])
    .ringColor(d => t => `${d.color()}${1 - t})`)
    .ringMaxRadius('maxR')
    .ringPropagationSpeed('propagationSpeed')
    .ringRepeatPeriod('repeatPeriod')
    (wrap);

  // Expliciete grootte na mount — Globe.gl leest offsetWidth/Height op mount moment
  // gebruik requestAnimationFrame zodat de browser de reflow heeft verwerkt
  requestAnimationFrame(() => {
    const w = wrap.offsetWidth  || window.innerWidth;
    const h = wrap.offsetHeight || window.innerHeight;
    globeInstance.width(w).height(h);
  });

  // Resize handler
  if (!window._globeResizeHandler) {
    window._globeResizeHandler = () => {
      if (!globeInstance) return;
      const wr = document.getElementById('globe-canvas-wrap');
      const w = wr.offsetWidth  || window.innerWidth;
      const h = wr.offsetHeight || window.innerHeight;
      globeInstance.width(w).height(h);
    };
    window.addEventListener('resize', window._globeResizeHandler);
  }

  // Startpositie: tussen gebruiker en relay
  globeInstance.pointOfView({ lat: (userLat + RELAY_LOC.lat) / 2, lng: (userLng + RELAY_LOC.lng) / 2, altitude: 2.0 }, 1200);

  // Toon controls info
  globeInstance.controls().autoRotate = true;
  globeInstance.controls().autoRotateSpeed = 0.35;

  // Stop autorotate bij interactie
  wrap.addEventListener('mousedown', () => { globeInstance.controls().autoRotate = false; });
  wrap.addEventListener('touchstart', () => { globeInstance.controls().autoRotate = false; });

  // Verberg loading
  document.getElementById('globe-loading').style.display = 'none';

  // Poll relay stats
  startGlobePoll();

  // Live transfer arc bijwerken als er een actieve sessie is
  updateGlobeTransfer(userLat, userLng);
}

function startGlobePoll() {
  if (globePollInterval) return;
  updateGlobeStats();
  globePollInterval = setInterval(updateGlobeStats, 8000);
}

async function updateGlobeStats() {
  // Health check
  try {
    const r = await fetch(RELAY_API + '/health', { signal: AbortSignal.timeout(4000) });
    const d = await r.json();
    const bl = document.getElementById('hud-blobs');
    if (bl) bl.textContent = (d.blobs || 0) + ' blobs';
    const up = document.getElementById('hud-uptime');
    if (up && d.uptime_s) {
      const h = Math.floor(d.uptime_s / 3600), m = Math.floor((d.uptime_s % 3600) / 60);
      up.textContent = h + 'h ' + m + 'm';
    }
  } catch(e) {}

  // Actieve sessie bijwerken
  updateSessionsPanel();
}

function updateSessionsPanel() {
  const el = document.getElementById('hud-sessions');
  if (!el) return;
  const sessions = [];

  if (sessionToken) {
    const step = document.querySelector('.step.active');
    const stepId = step ? step.id : '';
    let status = 'Idle';
    if (stepId === 'step-waiting') status = receiverPubs ? 'Receiver connected' : 'Awaiting receiver';
    else if (stepId === 'step-encrypting') status = 'Encrypting...';
    else if (stepId === 'step-done') status = 'Transfer complete';
    sessions.push({ label: 'Session · ' + sessionToken.slice(4,12) + '...', status, active: stepId !== 'step-done' });
  }

  const st = document.getElementById('hud-session-stat');
  if (st) st.textContent = sessions.length ? sessions[0].status : 'No session';

  el.innerHTML = sessions.length
    ? sessions.map(s => `<div class="hud-session">
        <span class="hud-dot${s.active ? '' : ' amber'}"></span>
        <span style="flex:1">${s.label}</span>
        <span style="color:rgba(178,255,63,.5);font-size:9px">${s.status}</span>
      </div>`).join('')
    : '<div class="hud-session"><span class="hud-dot amber"></span><span>No active session</span></div>';
}

// ── Globe state machine ───────────────────────────────────────────────────────
const _GLOBE_STATES = {
  idle:       { arcSpeed: 2800, arcColor: ['rgba(178,255,63,0)','#B2FF3F','#B2FF3F','rgba(178,255,63,0)'], ringSpeed: 1800, ringMax: 2.5, label: 'Ghost Pipe · Encrypted Channel' },
  waiting:    { arcSpeed: 1800, arcColor: ['rgba(178,255,63,0)','var(--ink-dim)','var(--ink-dim)','rgba(178,255,63,0)'], ringSpeed: 1200, ringMax: 3,   label: 'Ghost Pipe · Receiver Connected' },
  encrypting: { arcSpeed: 700,  arcColor: ['rgba(178,255,63,0)','#fff','var(--ink-dim)','rgba(178,255,63,0)'],   ringSpeed: 600,  ringMax: 4,   label: 'Ghost Pipe · Transmitting ▶' },
  done:       { arcSpeed: 2800, arcColor: ['rgba(178,255,63,0)','#B2FF3F','#B2FF3F','rgba(178,255,63,0)'], ringSpeed: 1800, ringMax: 2.5, label: 'Ghost Pipe · Transfer Complete ✓' },
};

function _globeApplyState(name) {
  if (!globeInstance || _gUserLat === null) return;
  const s = _GLOBE_STATES[name] || _GLOBE_STATES.idle;
  const uLat = _gUserLat, uLng = _gUserLng;
  const rLat = RELAY_LOC.lat, rLng = RELAY_LOC.lng;

  globeInstance
    .arcsData([{
      startLat: uLat, startLng: uLng,
      endLat: rLat, endLng: rLng,
      color: s.arcColor, label: s.label,
    }])
    .arcColor(d => d.color)
    .arcDashAnimateTime(s.arcSpeed)
    .ringsData([
      { lat: uLat, lng: uLng, maxR: s.ringMax, propagationSpeed: 2.5, repeatPeriod: s.ringSpeed, color: () => 'rgba(178,255,63,' },
      { lat: rLat, lng: rLng, maxR: s.ringMax * 0.9, propagationSpeed: 2, repeatPeriod: s.ringSpeed * 1.15, color: () => 'rgba(178,255,63,' },
    ])
    .ringColor(d => t => `${d.color()}${1 - t})`)
    .ringMaxRadius('maxR')
    .ringPropagationSpeed('propagationSpeed')
    .ringRepeatPeriod('repeatPeriod');
}

function _globeBurst() {
  if (!globeInstance || _gUserLat === null) return;
  const uLat = _gUserLat, uLng = _gUserLng;
  const rLat = RELAY_LOC.lat, rLng = RELAY_LOC.lng;
  // Big burst rings — 3 waves from relay and user
  const burstRings = [];
  for (let i = 0; i < 3; i++) {
    burstRings.push({ lat: rLat, lng: rLng, maxR: 8 + i * 4, propagationSpeed: 5 + i, repeatPeriod: 99999, color: () => 'rgba(178,255,63,' });
    burstRings.push({ lat: uLat, lng: uLng, maxR: 6 + i * 3, propagationSpeed: 4 + i, repeatPeriod: 99999, color: () => 'rgba(178,255,63,' });
  }
  globeInstance
    .ringsData(burstRings)
    .ringColor(d => t => `${d.color()}${1 - t})`)
    .ringMaxRadius('maxR')
    .ringPropagationSpeed('propagationSpeed')
    .ringRepeatPeriod('repeatPeriod');

  // Flash arc white then restore idle
  globeInstance.arcsData([{
    startLat: uLat, startLng: uLng,
    endLat: rLat, endLng: rLng,
    color: ['rgba(255,255,255,0)', '#fff', 'var(--ink-dim)', 'rgba(178,255,63,0)'],
    label: 'Ghost Pipe · Transfer Complete ✓',
  }]).arcDashAnimateTime(400);

  setTimeout(() => _globeApplyState('done'), 3200);
}

function globeOnStepChange(stepId) {
  if (!globeInstance) return;
  if (stepId === 'step-waiting')    _globeApplyState('waiting');
  else if (stepId === 'step-encrypting') _globeApplyState('encrypting');
  else if (stepId === 'step-done')  _globeBurst();
  else                              _globeApplyState('idle');
  updateSessionsPanel();
}

function updateGlobeTransfer(userLat, userLng) {
  _gUserLat = userLat; _gUserLng = userLng;
  _globeApplyState('idle');
}


act('change','fpConfirmToggle',(el)=>{const b=document.getElementById('fp-confirm-btn');if(b)b.disabled=!el.checked;});
act('change','onFileSelect',()=>onFileSelect());
act('click','confirmFingerprint',()=>confirmFingerprint());act('click','copyLink',()=>copyLink());
act('click','createSession',()=>createSession());act('click','expandApiKeyCard',()=>expandApiKeyCard());
act('click','rejectFingerprint',()=>rejectFingerprint());act('input','onKeyInput',()=>onKeyInput());
act('click','reload',()=>location.reload());
