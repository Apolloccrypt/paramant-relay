// ParaSign /verify page logic.
// The document NEVER leaves the browser: only its SHA3-256 hash is ever needed.
// v3 (parasign-doc-3) envelopes are verified ENTIRELY client-side with the same
// ML-DSA-65 + SHA3-256 primitives the signer used -- no relay, no API key, so
// the counterparty (who has no Paramant account) can verify offline. v1/v2
// envelopes carry a relay notary signature that only the relay can check, so
// they still POST to /v2/verify (which requires an API key).
import { sha3_256, ml_dsa65 } from '/vendor/paramant-pqc.js';

const RELAY_URL = 'https://relay.paramant.app';
// Byte-identical to relay/envelope.js SIGN_DOMAIN_DOC (recipe v3). Keep in sync.
const SIGN_DOMAIN_DOC = 'paramant/parasign/doc/v1';
let documentBuffer = null, envelope = null, isV3 = false, isMulti = false;

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

function hexToBytes(s) {
  const h = String(s || '');
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function concatBytes(arrs) {
  let n = 0;
  for (const a of arrs) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJSON(value[key])).join(',') + '}';
}

function normaliseAppearance(value) {
  const source = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const fields = Array.isArray(source.fields) ? source.fields.map((field) => {
    const clean = { type: String(field.type || ''), page_index: Number(field.page_index) };
    for (const name of ['x', 'y', 'w', 'h']) clean[name] = Math.round(Number(field[name]) * 1000000) / 1000000;
    return clean;
  }) : [];
  return { version: 1, fields };
}

function appearanceHash(value) {
  return sha3_256(new TextEncoder().encode(JSON.stringify(normaliseAppearance(value))));
}

// Reconstruct the versioned document-signing message, byte-identical to
// parasign-signer.js and relay/envelope.js.
function buildDocSignMessage(envelopeId, docHashHex, partyIndex, emailHashHex, recipeVersion, signerPublicKey, appearance) {
  const enc = new TextEncoder();
  const parts = [];
  if (Number(recipeVersion) >= 3) parts.push(enc.encode(SIGN_DOMAIN_DOC), new Uint8Array([0]));
  parts.push(
    enc.encode(String(envelopeId)),
    hexToBytes(docHashHex),
    enc.encode(String(partyIndex)),
  );
  if (Number(recipeVersion) >= 2) parts.push(hexToBytes(emailHashHex || ''));
  if (Number(recipeVersion) >= 4) parts.push(fromB64(signerPublicKey || ''));
  if (Number(recipeVersion) >= 5) parts.push(appearanceHash(appearance));
  return sha3_256(concatBytes(parts));
}

function isV3Envelope(env) {
  return !!env && (env.version === 'parasign-doc-3' || Number(env.recipe_version) >= 3);
}

// v3 verifies keyless client-side; v1/v2 need the relay (and its API key).
function update() {
  const apiKey = ($('vf-api-key').value || '').trim();
  const ready = documentBuffer && envelope && (isV3 || apiKey);
  $('vf-verify').disabled = !ready;
}

// Hide the API-key field for keyless v3 envelopes; show it for v1/v2.
function syncKeyField() {
  const block = $('vf-key-block');
  if (!block) return;
  block.hidden = isV3;
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
    let parsed;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      throw new Error('This file is not valid JSON. Choose the .psign envelope produced when the document was signed.');
    }
    if (parsed && typeof parsed === 'object' && parsed.envelope) parsed = parsed.envelope;
    if (!parsed || typeof parsed !== 'object' || !parsed.algorithm) {
      throw new Error('This does not look like a .psign envelope (no algorithm field).');
    }
    envelope = parsed;
    isMulti = envelope.type === 'parasign-envelope-receipt';
    isV3 = isMulti || isV3Envelope(envelope);

    const info = ['algorithm: ' + (envelope.algorithm || '?'), 'signed_at: ' + (envelope.signed_at || envelope.completed_at || '?')];
    if (isMulti) {
      info.push('signers: ' + String((envelope.parties || []).length));
      info.push('envelope: ' + String(envelope.envelope_id || '').slice(0, 12) + '…');
      info.push('keyless (offline)');
    } else if (isV3) {
      // v3 (parasign-doc-3): flat signer fields, no nested signer.label / notary.
      const signer = envelope.signer_name
        || (envelope.signer_pk_fingerprint ? 'key ' + String(envelope.signer_pk_fingerprint).slice(0, 16) + '…' : null);
      if (signer) info.push('signer: ' + signer);
      const envId = envelope.multiparty && envelope.multiparty.envelope_id;
      if (envId) info.push('envelope: ' + String(envId).slice(0, 12) + '…');
      info.push('keyless (offline)');
    } else {
      // v1/v2: nested signer.label + notary.ct_log_index.
      if (envelope.signer && envelope.signer.label) info.push('signer: ' + envelope.signer.label);
      const idx = (envelope.notary && envelope.notary.ct_log_index);
      if (idx != null) info.push('ct_log_index: ' + idx);
    }
    $('vf-envelope-info').textContent = info.join('  |  ');
  } catch (e) {
    $('vf-envelope-info').textContent = e.message;
    envelope = null; isV3 = false; isMulti = false;
  }
  syncKeyField();
  update();
}

// Keyless client-side verification of a v3 (parasign-doc-3) envelope. Mirrors
// relay/parasign.js verifyDocEnvelopeV3 exactly, with the same primitives - no
// relay call, no API key. Collects every failure rather than short-circuiting.
function verifyV3Client(docHashHex) {
  const errors = [];
  const env = envelope;
  if (env.algorithm && env.algorithm !== 'ML-DSA-65') errors.push('unsupported algorithm: ' + env.algorithm);
  const mp = env.multiparty || {};
  if (!mp.envelope_id) errors.push('missing multiparty.envelope_id');

  // pdf/image sign the stamped document; other documents sign document_hash.
  const signedHash = env.stamped_hash || env.document_hash;
  if (!signedHash) errors.push('missing signed document hash (stamped_hash or document_hash)');
  if (docHashHex && signedHash && signedHash !== docHashHex) {
    errors.push('document hash mismatch: this document does not match the one that was signed');
  }
  if (!env.signer_public_key) errors.push('missing signer_public_key');
  if (env.party_email_hash == null) {
    errors.push('missing party_email_hash (cannot reconstruct the signed message offline)');
  }
  const recipeVersion = Number(env.recipe_version) || 3;
  if (recipeVersion >= 5) {
    try {
      const computed = toHex(appearanceHash(env.appearance));
      if (computed !== env.appearance_hash) errors.push('appearance hash mismatch');
    } catch (e) { errors.push('invalid appearance manifest: ' + e.message); }
  }

  if (errors.length === 0) {
    try {
      const msg = buildDocSignMessage(
        String(mp.envelope_id),
        signedHash,
        mp.party_index != null ? mp.party_index : 0,
        env.party_email_hash || '',
        recipeVersion,
        env.signer_public_key,
        env.appearance,
      );
      const ok = ml_dsa65.verify(fromB64(env.signer_public_key), msg, fromB64(env.signature || ''));
      if (!ok) errors.push('signer signature invalid');
    } catch (e) { errors.push('signer signature verify error: ' + e.message); }
  }
  if (env.expires_at && new Date(env.expires_at) < new Date()) {
    errors.push('envelope expired at ' + env.expires_at);
  }
  return { valid: errors.length === 0, errors };
}

function verifyMultiClient(docHashHex) {
  const errors = [];
  const env = envelope;
  if (env.algorithm !== 'ML-DSA-65') errors.push('unsupported algorithm: ' + env.algorithm);
  if (!env.envelope_id) errors.push('missing envelope_id');
  if (!env.document_hash) errors.push('missing document_hash');
  if (env.document_hash && docHashHex !== env.document_hash) errors.push('document hash mismatch: choose the original delivered document, not the visual PDF copy');
  const recipe = Number(env.sign_recipe || env.recipe_version) || 1;
  const parties = Array.isArray(env.parties) ? env.parties : [];
  if (!parties.length) errors.push('missing parties');
  for (const party of parties) {
    if (!party || party.status !== 'signed' || !party.public_key || !party.signature) {
      errors.push('party ' + String(party && party.index) + ' has no complete signature');
      continue;
    }
    let visualHash = '';
    if (recipe >= 5) {
      try {
        visualHash = toHex(appearanceHash(party.appearance));
        if (visualHash !== party.appearance_hash) errors.push('party ' + party.index + ' appearance hash mismatch');
      } catch (e) { errors.push('party ' + party.index + ' appearance invalid: ' + e.message); }
    }
    try {
      const message = buildDocSignMessage(env.envelope_id, env.document_hash, party.index, party.email_hash || '', recipe, party.public_key, party.appearance);
      if (!ml_dsa65.verify(fromB64(party.public_key), message, fromB64(party.signature))) errors.push('party ' + party.index + ' signature invalid');
    } catch (e) { errors.push('party ' + party.index + ' signature verify error: ' + e.message); }
  }
  const notary = env.notary || {};
  if (!notary.relay_public_key) errors.push('missing embedded relay public key');
  if (!env.notary_signature) errors.push('missing notary signature');
  if (notary.relay_public_key) {
    try {
      const relayKey = fromB64(notary.relay_public_key);
      const relayHash = toHex(sha3_256(relayKey));
      if (relayHash !== notary.relay_pk_hash) errors.push('relay public key hash mismatch');
      const unsigned = { ...env };
      delete unsigned.notary_signature;
      const message = new TextEncoder().encode(canonicalJSON(unsigned));
      if (!ml_dsa65.verify(relayKey, message, fromB64(env.notary_signature || ''))) errors.push('notary signature invalid');
    } catch (e) { errors.push('notary signature verify error: ' + e.message); }
  }
  return { valid: errors.length === 0, errors };
}

async function verify() {
  $('vf-verify').disabled = true;
  $('vf-result').hidden = false;
  $('vf-result').innerHTML = '<div class="ps-banner info">' +
    (isV3 ? 'Verifying locally in your browser…' : 'Hashing locally + verifying via relay…') + '</div>';
  try {
    const docHash = sha3_256(new Uint8Array(documentBuffer)); // local
    if (isMulti) {
      await renderResult(verifyMultiClient(toHex(docHash)));
      return;
    }
    if (isV3) {
      // Fully offline: never touches the network for the crypto.
      await renderResult(verifyV3Client(toHex(docHash)));
      return;
    }
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
    // v1/v2 nest the key under signer.public_key; v3 (parasign-doc-3) carries it
    // flat as signer_public_key.
    const pkB64 = (envelope && envelope.signer && envelope.signer.public_key)
      || (envelope && envelope.signer_public_key);
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
  if (isV3) {
    const envId = isMulti ? envelope && envelope.envelope_id : envelope && envelope.multiparty && envelope.multiparty.envelope_id;
    if (envId) out.push('<p class="ps-help">Envelope: <code class="mono">' + esc(String(envId)) + '</code> &middot; verified offline, no account needed.</p>');
  } else {
    const idx = envelope && envelope.notary && envelope.notary.ct_log_index;
    if (idx != null) out.push('<p class="ps-help">CT log index: <a href="/ct-log">' + esc(String(idx)) + '</a></p>');
  }
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
