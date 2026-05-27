// ParaSign /verify page logic.
// The document NEVER leaves the browser: only its SHA3-256 hash + the .psign
// envelope are sent to /v2/verify (which runs the verification math).
// The deployed /v2/verify requires X-Api-Key, so a key field is shown.
import { sha3_256 } from 'https://esm.sh/@noble/hashes@1.5.0/sha3';

const RELAY_URL = 'https://relay.paramant.app';
let documentBuffer = null, envelope = null;

const $ = id => document.getElementById(id);
const toHex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const esc = s => String(s).replace(/[<>&"]/g, c => ({ '<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;' }[c]));

function update() {
  const apiKey = ($('vf-api-key').value || '').trim();
  $('vf-verify').disabled = !(documentBuffer && envelope && apiKey);
}

async function onDoc(file) {
  if (!file) return;
  documentBuffer = await file.arrayBuffer();
  $('vf-document-info').textContent = file.name + ' (' + (file.size / 1024).toFixed(1) + ' KB)';
  update();
}

async function onEnv(file) {
  if (!file) return;
  try {
    envelope = JSON.parse(await file.text());
    if (envelope.envelope) envelope = envelope.envelope;
    const info = ['algorithm: ' + (envelope.algorithm || '?'), 'signed_at: ' + (envelope.signed_at || '?')];
    if (envelope.signer && envelope.signer.label) info.push('signer: ' + envelope.signer.label);
    const idx = (envelope.notary && envelope.notary.ct_log_index);
    if (idx != null) info.push('ct_log_index: ' + idx);
    $('vf-envelope-info').textContent = info.join('  |  ');
  } catch (e) { $('vf-envelope-info').textContent = 'Invalid envelope: ' + e.message; envelope = null; }
  update();
}

async function verify() {
  $('vf-verify').disabled = true;
  $('vf-result').hidden = false;
  $('vf-result').innerHTML = '<div class="ps-banner info">Hashing locally + verifying via relay...</div>';
  try {
    const docHash = sha3_256(new Uint8Array(documentBuffer)); // local
    const res = await fetch(RELAY_URL + '/v2/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Api-Key': $('vf-api-key').value.trim() },
      body: JSON.stringify({ document_hash: toHex(docHash), envelope }),
    });
    if (!res.ok && res.status !== 200) {
      const t = await res.text();
      $('vf-result').innerHTML = '<div class="ps-banner err">Relay HTTP ' + res.status + ': ' + esc(t.slice(0, 200)) + '</div>';
      return;
    }
    renderResult(await res.json());
  } catch (e) {
    $('vf-result').innerHTML = '<div class="ps-banner err">Verify failed: ' + esc(e.message) + '</div>';
  } finally { $('vf-verify').disabled = false; }
}

function renderResult(r) {
  const out = [];
  out.push(r.valid
    ? '<div class="ps-banner ok"><strong>Signature valid.</strong> Document matches the signed hash.</div>'
    : '<div class="ps-banner err"><strong>Signature INVALID.</strong></div>');
  if (r.errors && r.errors.length) {
    out.push('<ul style="margin-top:var(--space-3)">');
    r.errors.forEach(e => out.push('<li class="ps-help">' + esc(e) + '</li>'));
    out.push('</ul>');
  }
  if (r.note) out.push('<p class="ps-help">' + esc(r.note) + '</p>');
  const idx = envelope && envelope.notary && envelope.notary.ct_log_index;
  if (idx != null) out.push('<p class="ps-help">CT log index: <a href="/ct-log">' + esc(String(idx)) + '</a></p>');
  $('vf-result').innerHTML = out.join('');
}

$('vf-document').addEventListener('change', e => onDoc(e.target.files[0]));
$('vf-envelope').addEventListener('change', e => onEnv(e.target.files[0]));
$('vf-api-key').addEventListener('input', update);
$('vf-verify').addEventListener('click', verify);
