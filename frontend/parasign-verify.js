// ParaSign /verify page logic.
// The document NEVER leaves the browser: only its SHA3-256 hash + the .psign
// envelope are sent to /v2/verify (which runs the verification math).
// The deployed /v2/verify requires X-Api-Key, so a key field is shown.
import { sha3_256 } from '/vendor/paramant-pqc.js';

const RELAY_URL = 'https://relay.paramant.app';
let documentBuffer = null, envelope = null;

const $ = id => document.getElementById(id);
const toHex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

function fromB64(s) {
  const bin = atob(s);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

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
    await renderResult(await res.json());
  } catch (e) {
    $('vf-result').innerHTML = '<div class="ps-banner err">Verify failed: ' + esc(e.message) + '</div>';
  } finally { $('vf-verify').disabled = false; }
}

// Resolve "Signed by <label> (<email>)" via the public lookup endpoint.
// Returns an HTML fragment (already-escaped) or '' if no attribution found.
async function lookupSignerHtml(envelope) {
  try {
    const pkB64 = envelope && envelope.signer && envelope.signer.public_key;
    if (!pkB64) return '';
    const pkBytes = fromB64(pkB64);
    const pkHash = toHex(sha3_256(pkBytes));
    const res = await fetch(RELAY_URL + '/v2/lookup-signer/' + pkHash);
    if (res.status === 404) {
      return '<p class="ps-help">Signer not linked to a Paramant account. Identified by public-key fingerprint <code class="mono">'
        + esc(pkHash.slice(0, 16)) + '...</code> only.</p>';
    }
    if (!res.ok) return '';
    const d = await res.json();
    if (!d.found) return '';
    const label = d.label ? esc(d.label) : '<em>(no label)</em>';
    const email = d.email ? esc(d.email) : '<em>(unverified)</em>';
    const algo  = esc(d.alg || '?');
    let html = '<p class="ps-help"><strong>Signed by ' + label + ' (' + email + ')</strong> &middot; ' + algo + '</p>';
    if (d.revoked_at) {
      html += '<p class="ps-help">This key was revoked on ' + esc(d.revoked_at)
        + '. The signature is still cryptographically valid; treat as valid if signed before that date.</p>';
    } else if (d.enrolled_at) {
      html += '<p class="ps-help">Key enrolled on ' + esc(d.enrolled_at) + '.</p>';
    }
    return html;
  } catch { return ''; }
}

async function renderResult(r) {
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
  // First paint without attribution so the user sees the valid/invalid badge fast.
  $('vf-result').innerHTML = out.join('');
  // Then enrich with public-key lookup (best-effort, can be 404).
  if (r.valid) {
    const attr = await lookupSignerHtml(envelope);
    if (attr) $('vf-result').innerHTML = out.join('') + attr;
  }
}

$('vf-document').addEventListener('change', e => onDoc(e.target.files[0]));
$('vf-envelope').addEventListener('change', e => onEnv(e.target.files[0]));
$('vf-api-key').addEventListener('input', update);
$('vf-verify').addEventListener('click', verify);
