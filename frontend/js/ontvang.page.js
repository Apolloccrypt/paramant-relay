'use strict';

const RELAY_WS  = 'wss://relay.paramant.app';
const RELAY_SECTORS = {
  health:  'https://health.paramant.app',
  legal:   'https://legal.paramant.app',
  finance: 'https://finance.paramant.app',
  iot:     'https://iot.paramant.app',
};

function $(id) { return document.getElementById(id); }
function showStep(id) {
  document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
  $(id).classList.add('active');
}
function showError(msg) {
  $('error-msg').textContent = msg;
  showStep('step-error');
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
function b64urlToU8(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64url.length / 4) * 4, '=');
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

// Must match parashare.html: SHA-256(kyber_pub || ecdh_pub) → first 10 bytes → 5×4 hex
async function genFingerprint(kyberPubHex, ecdhPubHex) {
  const buf = hexToU8(kyberPubHex + (ecdhPubHex || ''));
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
  const h = [...hash.slice(0, 10)].map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
  return `${h.slice(0,4)}-${h.slice(4,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}`;
}

// ── Get session token + relay sector from URL ──
const params = new URLSearchParams(location.search);
const sessionToken = params.get('s');
const RELAY_API = RELAY_SECTORS[params.get('r')] || RELAY_SECTORS.health;
const tokenValid = !!sessionToken && /^inv_[a-zA-Z0-9]{32}$/.test(sessionToken);
if (!tokenValid) {
  // A bad link is a bad link whether or not the crypto library ever arrives, so
  // say so now instead of waiting on a signal that may never come.
  showError('Invalid or missing session token');
}

// ── State ──
let myPrivateKey_ECDH = null;      // CryptoKey (for ECDH deriveBits — kept for legacy)
let myPrivateKey_ECDH_RAW = null;  // Uint8Array 32-byte scalar (for WASM decryptBlob)
let myPrivateKey_MLKEM = null;
let ws = null;

// ── Main flow ──
async function init() {
  // Wait for the ML-KEM library, however late it arrives. This used to be a
  // bare 'mlkem-ready' listener, which never fired for us: the loader is a
  // module higher up the page, so it announced itself before this deferred file
  // had registered anything, and receiving a file hung on "Generating
  // keypair..." for three weeks. ready.within() is sticky, so the order of the
  // two scripts no longer decides whether the product works.
  try {
    await window.ready.within('mlkem', 20000, 'ML-KEM-768 library');
  } catch {
    showError('ML-KEM-768 library failed to load. Refresh the page and try again. Do not proceed without post-quantum encryption.');
    return;
  }
  // Loaded, but is it the real thing? Refuse to fall back to weaker crypto.
  if (typeof ml_kem768 === 'undefined' || !ml_kem768?.keygen) {
    showError('ML-KEM-768 library failed to load. Refresh the page and try again. Do not proceed without post-quantum encryption.');
    return;
  }
  try {
    // Restore keypair from sessionStorage (survives refresh, not tab-close)
    const storageKey = 'paramant_kp_' + sessionToken;
    const cached = sessionStorage.getItem(storageKey);
    let kyberPubHex, ecdhPubHex;

    if (cached) {
      $('keygen-status').textContent = 'Restoring keypair...';
      $('keygen-progress').style.width = '60%';
      const kp = JSON.parse(cached);
      kyberPubHex = kp.kyberPubHex;
      ecdhPubHex  = kp.ecdhPubHex;
      myPrivateKey_MLKEM = new Uint8Array(kp.kyberSec);
      myPrivateKey_ECDH = await crypto.subtle.importKey(
        'jwk', kp.ecdhSecJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false, ['deriveBits']
      );
      // Extract raw 32-byte scalar from JWK d field (base64url → Uint8Array)
      myPrivateKey_ECDH_RAW = b64urlToU8(kp.ecdhSecJwk.d);
    } else {
      // Generate ML-KEM-768 keypair via Web Worker (non-blocking)
      $('keygen-status').textContent = 'Generating ML-KEM-768 keypair...';
      $('keygen-progress').style.width = '40%';
          const { publicKey: kyberPub, secretKey: kyberSec } = await new Promise(resolve => setTimeout(() => resolve(ml_kem768.keygen()), 50));
      myPrivateKey_MLKEM = kyberSec;

      // Generate ECDH P-256 keypair
      $('keygen-status').textContent = 'Generating ECDH P-256 keypair...';
      $('keygen-progress').style.width = '70%';
      const ecdhPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
      myPrivateKey_ECDH = ecdhPair.privateKey;
      const ecdhPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', ecdhPair.publicKey));

      kyberPubHex = u8toHex(kyberPub);
      ecdhPubHex  = u8toHex(ecdhPubRaw);

      // Save to sessionStorage so refresh restores the same keypair
      const ecdhSecJwk = await crypto.subtle.exportKey('jwk', ecdhPair.privateKey);
      // Extract raw 32-byte scalar from JWK d field (base64url → Uint8Array)
      myPrivateKey_ECDH_RAW = b64urlToU8(ecdhSecJwk.d);
      sessionStorage.setItem(storageKey, JSON.stringify({
        kyberPubHex, ecdhPubHex,
        kyberSec: Array.from(kyberSec),
        ecdhSecJwk
      }));
    }

    $('keygen-progress').style.width = '100%';
    $('keygen-status').textContent = 'Keypair ready - connecting to relay...';

    const fp = await genFingerprint(kyberPubHex, ecdhPubHex);

    // Show fingerprint
    $('fp-display').textContent = fp;
    showStep('step-fingerprint');

    // Registreer pubkey via HTTP — onafhankelijk van WS (ontvanger heeft geen API key)
    try {
      await fetch(`${RELAY_API}/v2/pubkey`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: sessionToken,
          ecdh_pub: ecdhPubHex,
          kyber_pub: kyberPubHex
        }),
        signal: AbortSignal.timeout(8000)
      });
      $('fp-status').textContent = 'Ready - waiting for sender to verify fingerprint';
    } catch(e) { console.warn('pubkey register failed', e); }

    // Connect WebSocket (best-effort — ontvanger heeft geen API key, kan falen)
    try {
      ws = new WebSocket(RELAY_WS + '/v2/stream');
      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'join', room: sessionToken, nick: 'receiver' }));
      };
    } catch(e) { ws = { send: () => {}, close: () => {} }; }

    ws.onmessage = async (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      console.log('WS msg:', msg.type, msg.payload ? msg.payload.slice?.(0,50) : '');

      try {
        let payload = null;
        if (msg.type === 'packet' && msg.payload) {
          try { payload = typeof msg.payload === 'string' ? JSON.parse(msg.payload) : msg.payload; } catch {}
        }

        if (payload?.type === 'fingerprint_ok') {
          $('fp-title').textContent = 'Fingerprint confirmed - receiving file...';
          $('fp-status').textContent = 'Sender confirmed fingerprint - file is being encrypted for you';
        }

        // ook via HTTP polling afgehandeld hieronder

        if (msg.type === 'peer_left') {
          if (!$('step-done').classList.contains('active')) {
            showError('Sender disconnected');
          }
        }
      } catch(err) {
        console.error('ws.onmessage handler error:', err);
      }
    };

    ws.onerror = (e) => console.warn('WS optional for receiver — file transfer via HTTP polling', e);
    ws.onclose = () => {};

    // Poll voor transfer_ready via HTTP
    let _transferClaimed = false;
    const pollTransfer = setInterval(async () => {
      if (_transferClaimed) return;
      try {
        const r = await fetch(RELAY_API + '/v2/pubkey/' + encodeURIComponent(sessionToken + '_ready'), {
          signal: AbortSignal.timeout(3000)
        });
        if (r.ok) {
          const d = await r.json();
          if (d.ecdh_pub && d.kyber_pub) {
            if (_transferClaimed) return;
            _transferClaimed = true;
            clearInterval(pollTransfer);
            // The sender wrote this field with frontend/js/handshake-meta.js and
            // this side reads it with the same module. Reading it here by hand
            // is what put the block count in ttl until 4 September 2026.
            const meta = window.paramantHandshake.decode(d.kyber_pub);
            // 'vault' is a hint from a name field, so confirm it against the
            // thing a vault actually carries: a JSON list of files. A single
            // file that happens to be named "vault" then still arrives.
            let vaultFiles = null;
            if (meta.kind === 'vault') {
              try { vaultFiles = JSON.parse(d.ecdh_pub); } catch (_) { vaultFiles = null; }
              if (!Array.isArray(vaultFiles)) vaultFiles = null;
            }
            if (vaultFiles) {
              await receiveVault(vaultFiles, meta.ttlMs, myPrivateKey_MLKEM, myPrivateKey_ECDH_RAW);
            } else {
              // The name is a courtesy from the handshake and only used until
              // chunk 0 arrives: the real name travels inside the sealed bytes,
              // and receiveFile() overwrites this with it.
              await receiveFile({ tokens: d.ecdh_pub, file_name: meta.name || 'download',
                total_chunks: meta.chunks, ttl_ms: meta.ttlMs }, myPrivateKey_MLKEM, myPrivateKey_ECDH_RAW);
            }
          }
        }
      } catch(e) {}
    }, 2000);

  } catch(e) {
    showError('Keypair generation failed: ' + e.message);
  }
}

async function receiveFile(msg, kyberSec, ecdhPrivRaw, opts = {}) {
  showStep('step-receiving');
  const tokens = msg.tokens.split(',');
  const totalChunks = parseInt(msg.total_chunks) || 1;
  let fileName = msg.file_name || 'download';
  const chunks = [];
  const burnedHashes = [];
  let fileWriter = null;  // File System Access API streaming writer

  try {
    for (let i = 0; i < tokens.length; i++) {
      const pct = Math.round(10 + (i / tokens.length) * 75);
      $('recv-progress').style.width = pct + '%';
      $('recv-status').textContent = `Downloading chunk ${i+1}/${tokens.length}...`;

      const r = await fetch(`${RELAY_API}/v2/dl/${tokens[i]}/get`, {
        signal: AbortSignal.timeout(60000)
      });
      if (!r.ok) throw new Error('Download failed for chunk ' + (i+1) + ': ' + r.status + ' - blob expired or already burned');
      const burnHash = r.headers.get('X-Hash') || r.headers.get('X-Paramant-Hash') || '';
      burnedHashes.push({ chunk: i+1, hash: burnHash.slice(0,16), ts: new Date().toISOString() });
      const raw = new Uint8Array(await r.arrayBuffer());

      $('recv-status').textContent = `Decrypting chunk ${i+1}/${tokens.length} with ML-KEM-768...`;

      if (!window._cryptoBridge) throw new Error('WASM crypto bridge not ready');
      const plainPadded = await window._cryptoBridge.decryptBlob(raw, kyberSec, ecdhPrivRaw);

      // Strip metadata header: META_MAGIC(4) | metaLen(4) | meta | chunkData
      const META_MAGIC = new Uint8Array([0x50, 0x52, 0x53, 0x48]);
      let doff = 0;
      if (plainPadded[0] === META_MAGIC[0] && plainPadded[1] === META_MAGIC[1]) {
        doff = 4;
        const metaLen = new DataView(plainPadded.buffer).getUint32(doff, false);
        if (i === 0) {
          try {
            const metaObj = JSON.parse(new TextDecoder().decode(plainPadded.slice(doff + 4, doff + 4 + metaLen)));
            if (metaObj.file_name) fileName = metaObj.file_name;
          } catch(_) {}
        }
        doff += 4 + metaLen;
      }

      // Bestandsnaam is nu bekend (uit chunk 0). Open de save-picker met de juiste
      // suggestedName. showSaveFilePicker vereist user-activation; lukt dat niet dan
      // valt het terug op Blob-assembly onderaan, nu met de correcte bestandsnaam.
      if (i === 0 && window.showSaveFilePicker) {
        try {
          const handle = await window.showSaveFilePicker({ suggestedName: fileName, _startIn: 'downloads' });
          fileWriter = await handle.createWritable();
        } catch(e) {
          // Gebruiker annuleerde of geen user-activation — val terug op Blob
          fileWriter = null;
        }
      }
      const decryptedChunk = plainPadded.slice(doff);
      if (fileWriter) {
        await fileWriter.write(decryptedChunk);
      } else {
        chunks.push(decryptedChunk);
      }
    }

    $('recv-progress').style.width = '100%';
    $('recv-status').textContent = 'Saving file...';

    let totalSize = 0;
    let savedBlob = null;
    if (fileWriter) {
      // Streaming: sluit schrijfstream — bestand al opgeslagen op disk
      await fileWriter.close();
      fileWriter = null;
      totalSize = chunks.length; // niet beschikbaar, gebruik 0
    } else {
      // Blob assembly: geef chunks direct aan Blob (efficienter dan concat).
      // Expliciet octet-stream zodat de browser geen .txt-extensie afleidt.
      const blob = new Blob(chunks, { type: 'application/octet-stream' });
      totalSize = blob.size;
      savedBlob = blob;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = fileName; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    if (!opts.silent) {
      // The end screen. What somebody who has just received a photo wants to
      // know is that they have it and that nothing is left lying about, in that
      // order. The chunk hashes and the algorithm names still exist, one fold
      // down under "What made this safe".
      const sizeStr = totalSize > 0 ? ' (' + formatSize(totalSize) + ')' : '';
      window.paramantDone.fill('step-done', {
        title: 'You have the file.',
        line: fileName + sizeStr + ' is saved on your device. Our copy has been permanently destroyed.',
      });
      offerSaveAgain(savedBlob, fileName);
      renderBurnReceipt(burnedHashes);
      showStep('step-done');
      if (ws) ws.close();
    }

    // Burn-on-tab-switch: wis decrypted data als tab verborgen wordt
    const _burnOnHide = () => {
      if (document.hidden) {
        chunks.length = 0;  // leeg de chunk array
        // The offer to save again goes with it: it is the same bytes.
        offerSaveAgain(null, null);
        document.removeEventListener('visibilitychange', _burnOnHide);
      }
    };
    document.addEventListener('visibilitychange', _burnOnHide);

  } catch(e) {
    if (fileWriter) { try { await fileWriter.abort(); } catch(_) {} fileWriter = null; }
    showError('Decryption failed: ' + e.message);
  }
}


async function receiveVault(vaultFiles, ttl_ms, kyberSec, ecdhPriv) {
  showStep('step-receiving');
  $('recv-status').textContent = 'Receiving vault — ' + vaultFiles.length + ' files...';

  const burnedHashes = [];

  for (let fi = 0; fi < vaultFiles.length; fi++) {
    const vf = vaultFiles[fi];
    await receiveFile(
      { tokens: vf.tokens.join(','), file_name: 'download', total_chunks: vf.tokens.length, ttl_ms, _vaultIdx: fi, _vaultTotal: vaultFiles.length },
      kyberSec, ecdhPriv, { silent: fi < vaultFiles.length - 1 }
    );
    $('recv-status').textContent = 'Vault: ' + (fi+1) + '/' + vaultFiles.length + ' downloaded';
  }

  window.paramantDone.fill('step-done', {
    title: 'You have the files.',
    line: vaultFiles.length + ' files are saved on your device. Our copies have been permanently destroyed.',
  });
  // Each file in a vault saved itself as it arrived; there is no single blob
  // left to hand over again, so the screen keeps the dashboard as its one
  // button rather than offering a save it cannot perform.
  offerSaveAgain(null, null);
  renderBurnReceipt(burnedHashes);
  showStep('step-done');
  if (ws) ws.close();
}
// ── The end screen's two moving parts ────────────────────────────────────────
//
// A browser can refuse a save and a person can dismiss the dialog, and on this
// page the bytes are then unreachable for good: every block was burned on the
// relay as it was read. So the screen offers the save a second time while it
// still can, and says so with the one primary button it has. When there is
// nothing to hand over again the dashboard link takes that place instead, so
// the screen is never a dead end and never has two loud buttons.
let savedFile = null;
function offerSaveAgain(blob, name) {
  const btn = $('done-save');
  const dash = $('done-dashboard');
  savedFile = (blob && name) ? { blob, name } : null;
  if (btn) btn.hidden = !savedFile;
  if (dash) dash.className = savedFile ? 'done-quiet' : 'btn done-primary';
}
function saveAgain() {
  if (!savedFile) return;
  const url = URL.createObjectURL(savedFile.blob);
  const a = document.createElement('a');
  a.href = url; a.download = savedFile.name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// What the relay reported as each block went. Machine detail, so it lives
// inside the folded <details> and not on the face of the screen.
function renderBurnReceipt(burnedHashes) {
  const el = $('burn-receipt');
  if (!el) return;
  if (!burnedHashes || !burnedHashes.length) { el.hidden = true; return; }
  el.textContent = burnedHashes
    .map(b => 'block ' + b.chunk + '  hash ' + b.hash + '...  wiped ' + b.ts)
    .join('\n');
  el.hidden = false;
}

// Bytes into something a person reads. Same rounding as /get.
function formatSize(n) {
  if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}

// init() waits for the ML-KEM library itself, so there is nothing to listen for
// and no event left to miss.
if (tokenValid) init();

act('click','reload',()=>location.reload());
act('click','saveAgain',()=>saveAgain());
