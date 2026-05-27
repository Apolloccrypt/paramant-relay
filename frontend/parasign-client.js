// ParaSign /sign page logic.
// SECURITY: the private key and the document NEVER leave this browser.
// Only the SHA3-256 hash (hex), the ML-DSA-65 signature (base64), and the
// public key (base64) are sent to the relay notary. (Contract matches
// relay/parasign.js + the /v2/sign handler, which base64-decodes signature
// and signer_public_key.)
// Crypto is vendored same-origin (frontend/vendor/paramant-pqc.js, built from
// @noble/post-quantum + @noble/hashes) so it loads under the site CSP (script-src 'self').
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';

const RELAY_URL = 'https://relay.paramant.app';
let signerKey = null, documentBuffer = null, documentFilename = '', lastEnvelope = null;

const $ = id => document.getElementById(id);
const toHex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const fromHex = h => new Uint8Array(h.match(/.{2}/g).map(b => parseInt(b, 16)));
function toB64(u8) { let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return btoa(s); }

function setStatus(kind, msg) {
  const el = $('ps-sign-status'); if (!el) return;
  el.hidden = false; el.className = 'ps-banner ' + kind; el.textContent = msg;
}
function updateSignButton() {
  const apiKey = ($('ps-api-key').value || '').trim();
  $('ps-sign').disabled = !(signerKey && documentBuffer && apiKey);
}

function generateKey() {
  setStatus('info', 'Generating ML-DSA-65 key locally (in this browser only)...');
  try {
    const keys = ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
    signerKey = { secretKey: keys.secretKey, publicKey: keys.publicKey };
    $('ps-pubkey-fp').textContent = toHex(sha3_256(keys.publicKey)).slice(0, 32) + '...';
    $('ps-key-info').hidden = false; $('ps-save-key').disabled = false;
    setStatus('ok', 'Key generated. Private key stays in browser memory.');
    updateSignButton();
  } catch (e) { setStatus('err', 'Keygen failed: ' + e.message); }
}

async function loadKey(file) {
  try {
    const d = JSON.parse(await file.text());
    if (!d.secretKey || !d.publicKey) throw new Error('invalid key file');
    signerKey = { secretKey: fromHex(d.secretKey), publicKey: fromHex(d.publicKey) };
    $('ps-pubkey-fp').textContent = toHex(sha3_256(signerKey.publicKey)).slice(0, 32) + '...';
    $('ps-key-info').hidden = false; $('ps-save-key').disabled = false;
    setStatus('ok', 'Key loaded (client-side only).'); updateSignButton();
  } catch (e) { setStatus('err', 'Load failed: ' + e.message); }
}

function saveKey() {
  if (!signerKey) return;
  const data = { algorithm: 'ML-DSA-65', publicKey: toHex(signerKey.publicKey),
    secretKey: toHex(signerKey.secretKey), generated_at: new Date().toISOString(),
    warning: 'Private key. Anyone with this can sign as you. Keep it secret.' };
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  a.download = 'parasign-key-' + Date.now() + '.json'; a.click(); URL.revokeObjectURL(a.href);
}

async function onDoc(file) {
  if (!file) return;
  documentBuffer = await file.arrayBuffer(); documentFilename = file.name;
  $('ps-document-info').textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
  updateSignButton();
}

async function sign() {
  if (!signerKey || !documentBuffer) return;
  $('ps-sign').disabled = true;
  setStatus('info', 'Hashing + signing locally (key + document stay here)...');
  try {
    const docHash = sha3_256(new Uint8Array(documentBuffer));   // 32-byte digest, local
    const signature = ml_dsa65.sign(signerKey.secretKey, docHash); // local sign over the digest
    setStatus('info', 'Sending hash + signature to the notary (no document, no key)...');
    const res = await fetch(RELAY_URL + '/v2/sign', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': $('ps-api-key').value.trim() },
      body: JSON.stringify({
        document_hash: toHex(docHash),                 // hex
        signature: toB64(signature),                   // base64 (relay decodes b64)
        signer_public_key: toB64(signerKey.publicKey), // base64
        signer_label: $('ps-label').value || null,
      }),
    });
    if (!res.ok) throw new Error('HTTP ' + res.status + ': ' + (await res.text()).slice(0, 200));
    const result = await res.json();
    lastEnvelope = result.envelope || result;
    $('ps-ct-index').textContent = (lastEnvelope.notary && lastEnvelope.notary.ct_log_index) ?? lastEnvelope.ct_log_index ?? '-';
    $('ps-result').hidden = false;
    setStatus('ok', 'Document signed. Envelope ready to download.');
  } catch (e) { setStatus('err', 'Sign failed: ' + e.message); $('ps-sign').disabled = false; }
}

function download() {
  if (!lastEnvelope) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(lastEnvelope, null, 2)], { type: 'application/json' }));
  a.download = (documentFilename || 'document') + '.psign'; a.click(); URL.revokeObjectURL(a.href);
}

$('ps-gen-key').addEventListener('click', generateKey);
$('ps-load-key').addEventListener('change', e => e.target.files[0] && loadKey(e.target.files[0]));
$('ps-save-key').addEventListener('click', saveKey);
$('ps-document').addEventListener('change', e => onDoc(e.target.files[0]));
$('ps-api-key').addEventListener('input', updateSignButton);
$('ps-sign').addEventListener('click', sign);
$('ps-download-psign').addEventListener('click', download);
