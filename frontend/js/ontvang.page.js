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
if (!sessionToken || !/^inv_[a-zA-Z0-9]{32}$/.test(sessionToken)) {
  window.addEventListener('mlkem-ready', () => showError('Invalid or missing session token'));
}

// ── State ──
let myPrivateKey_ECDH = null;      // CryptoKey (for ECDH deriveBits — kept for legacy)
let myPrivateKey_ECDH_RAW = null;  // Uint8Array 32-byte scalar (for WASM decryptBlob)
let myPrivateKey_MLKEM = null;
let ws = null;

// ── Main flow ──
async function init() {
  // Guard: if ML-KEM library failed to load, refuse to proceed
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
            const parts = d.kyber_pub.split('|');
            if (parts[0] === 'vault') {
              // Vault mode: meerdere bestanden
              const ttl_ms = parseInt(parts[2]) || 3600000;
              const vaultFiles = JSON.parse(d.ecdh_pub);
              await receiveVault(vaultFiles, ttl_ms, myPrivateKey_MLKEM, myPrivateKey_ECDH_RAW);
            } else {
              // Enkelvoudig bestand — formaat: total_chunks|ttl_ms (bestandsnaam zit alleen in encrypted payload)
              const ttl_ms = parseInt(parts[1]) || 3600000;
              await receiveFile({ tokens: d.ecdh_pub, file_name: 'download', total_chunks: parseInt(parts[0]) || 1, ttl_ms }, myPrivateKey_MLKEM, myPrivateKey_ECDH_RAW);
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
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = fileName; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    }

    if (!opts.silent) {
      const sizeStr = totalSize > 0 ? ' (' + (totalSize/1024/1024).toFixed(2) + ' MB)' : '';
      $('done-status').textContent = '✓ ' + fileName + sizeStr + ' — decrypted and saved';
      const receiptEl = $('burn-receipt');
      if (receiptEl && burnedHashes.length) {
        receiptEl.textContent = burnedHashes.map(b => 'chunk ' + b.chunk + '  hash:' + b.hash + '...  burned: ' + b.ts).join('\n');
        receiptEl.style.display = 'block';
      }
      if (msg.ttl_ms) {
        const exp = new Date(Date.now() + msg.ttl_ms);
        $('ttl-note').textContent = 'Relay copy auto-expired at: ' + exp.toLocaleTimeString();
        $('ttl-note').style.display = 'block';
      }
      showStep('step-done');
      if (ws) ws.close();
    }

    // Burn-on-tab-switch: wis decrypted data als tab verborgen wordt
    const _burnOnHide = () => {
      if (document.hidden) {
        chunks.length = 0;  // leeg de chunk array
        $('done-status').textContent += ' — memory cleared (tab hidden)';
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

  $('done-status').textContent = '✓ Vault opened — ' + vaultFiles.length + ' files decrypted and saved';
  const ttlNote = $('ttl-note');
  if (ttlNote) {
    ttlNote.textContent = 'All vault blobs burned. TTL: ' + (ttl_ms/1000) + 's';
    ttlNote.style.display = 'block';
  }
  showStep('step-done');
  if (ws) ws.close();
}
window.addEventListener('mlkem-ready', () => {
  if (sessionToken) init();
});

act('click','reload',()=>location.reload());
