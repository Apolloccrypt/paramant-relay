// ParaSign /verify page logic.
//
// Two verification paths:
//
//   1) Envelopes produced by the new /sign flow (parasign-visual-1,
//      parasign-image-1, parasign-hash-1) are verified FULLY CLIENT-SIDE.
//      We hash the user's document, compare to envelope.stamped_hash
//      (or original_hash for hash-only), reconstruct the exact same
//      sign-message bytes the signer used, and run ml-dsa-65.verify
//      locally. No relay call, no API key needed.
//
//   2) Legacy parasign-v1 envelopes still go through /v2/verify on the
//      relay, which requires an X-Api-Key.
//
// The document never leaves the browser in either case.
import { ml_dsa65, sha3_256 } from '/vendor/paramant-pqc.js';

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
  // Client-side capable envelopes do not require an API key.
  if (envelope && isClientSideVersion(envelope.version)) {
    $('vf-verify').disabled = !(documentBuffer && envelope);
  } else {
    const apiKey = ($('vf-api-key').value || '').trim();
    $('vf-verify').disabled = !(documentBuffer && envelope && apiKey);
  }
}

function isClientSideVersion(v) {
  return v === 'parasign-visual-1' || v === 'parasign-image-1' || v === 'parasign-hash-1';
}

function hexToBytes(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
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
    const info = ['version: ' + (envelope.version || '?'), 'algorithm: ' + (envelope.algorithm || '?'), 'signed_at: ' + (envelope.signed_at || '?')];
    if (envelope.signer_name) info.push('signer: ' + envelope.signer_name);
    if (envelope.signer && envelope.signer.label) info.push('signer: ' + envelope.signer.label);
    const idx = (envelope.notary && envelope.notary.ct_log_index);
    if (idx != null) info.push('ct_log_index: ' + idx);
    $('vf-envelope-info').textContent = info.join('  |  ');
    // Show/hide the right section based on what this envelope needs.
    const apiSection = $('vf-api-section');
    const csBadge = $('vf-clientside-badge');
    if (isClientSideVersion(envelope.version)) {
      if (apiSection) apiSection.hidden = true;
      if (csBadge)   csBadge.hidden = false;
    } else {
      if (apiSection) apiSection.hidden = false;
      if (csBadge)   csBadge.hidden = true;
    }
  } catch (e) {
    $('vf-envelope-info').textContent = 'Invalid envelope: ' + e.message;
    envelope = null;
    const apiSection = $('vf-api-section');
    const csBadge = $('vf-clientside-badge');
    if (apiSection) apiSection.hidden = true;
    if (csBadge)   csBadge.hidden = true;
  }
  update();
}

// Client-side verification for envelopes produced by the new /sign flow.
// Returns { valid, errors, mode } or null if version is unknown (caller
// should fall through to the relay /v2/verify endpoint).
async function clientSideVerify() {
  const docBytes = new Uint8Array(documentBuffer);
  const docHashBytes = sha3_256(docBytes);
  const docHashHex = toHex(docHashBytes);
  const errors = [];

  if (envelope.version === 'parasign-hash-1') {
    // User uploads the original file. document_hash binds to it directly.
    if (envelope.document_hash !== docHashHex) {
      errors.push('Document hash mismatch: computed ' + docHashHex.slice(0, 24) + '... vs envelope ' + (envelope.document_hash || '(missing)').slice(0, 24) + '...');
    }
    try {
      const sig = fromB64(envelope.signature);
      const pk  = fromB64(envelope.signer_public_key);
      const ok = ml_dsa65.verify(pk, docHashBytes, sig);
      if (!ok) errors.push('ML-DSA-65 signature failed verification');
    } catch (e) {
      errors.push('Signature decode failed: ' + e.message);
    }
    return { valid: errors.length === 0, errors, mode: 'client-side (hash-only)' };
  }

  if (envelope.version === 'parasign-visual-1' || envelope.version === 'parasign-image-1') {
    // User must upload the SIGNED file (signed-<name>.pdf or .png/.jpg),
    // not the original - the signature is over the stamped output.
    if (envelope.stamped_hash !== docHashHex) {
      errors.push('Stamped-hash mismatch: computed ' + docHashHex.slice(0, 24) + '... vs envelope ' + (envelope.stamped_hash || '(missing)').slice(0, 24) + '... - make sure you uploaded the signed-<name> file, not the original.');
    }
    try {
      const origHash = hexToBytes(envelope.original_hash || '');
      if (origHash.length !== 32) errors.push('original_hash missing or wrong length');
      const stampedHash = docHashBytes;
      // New schema uses .stamps (array), legacy uses .coords (single object).
      // Sign-message bytes = JSON.stringify of whichever shape was used.
      const stampsField = envelope.stamps ? envelope.stamps : (envelope.coords || {});
      const stampsBytes = new TextEncoder().encode(JSON.stringify(stampsField));
      const msg = new Uint8Array(origHash.length + stampedHash.length + stampsBytes.length);
      msg.set(origHash, 0);
      msg.set(stampedHash, origHash.length);
      msg.set(stampsBytes, origHash.length + stampedHash.length);
      const sig = fromB64(envelope.signature);
      const pk  = fromB64(envelope.signer_public_key);
      const ok = ml_dsa65.verify(pk, msg, sig);
      if (!ok) errors.push('ML-DSA-65 signature failed verification');
    } catch (e) {
      errors.push('Signature reconstruction failed: ' + e.message);
    }
    return { valid: errors.length === 0, errors, mode: 'client-side (' + envelope.version + ')' };
  }

  return null;   // unknown version, fall back to relay
}

async function verify() {
  $('vf-verify').disabled = true;
  $('vf-result').hidden = false;
  try {
    if (isClientSideVersion(envelope.version)) {
      $('vf-result').innerHTML = '<div class="ps-banner info">Verifying locally (no API key, no relay round-trip)...</div>';
      const r = await clientSideVerify();
      await renderResult(r);
      return;
    }
    $('vf-result').innerHTML = '<div class="ps-banner info">Hashing locally + verifying via relay...</div>';
    const docHash = sha3_256(new Uint8Array(documentBuffer));
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
    ? '<div class="ps-banner ok"><strong>Signature valid.</strong> Document matches the signed hash.' + (r.mode ? ' <small style="opacity:.7">(' + esc(r.mode) + ')</small>' : '') + '</div>'
    : '<div class="ps-banner err"><strong>Signature INVALID.</strong>' + (r.mode ? ' <small style="opacity:.7">(' + esc(r.mode) + ')</small>' : '') + '</div>');
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
