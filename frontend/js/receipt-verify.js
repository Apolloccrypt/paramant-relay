// ParaSend transfer-receipt verifier. Runs entirely in the browser.
//
// A ParaSend delivery receipt is the proof that a specific encrypted transfer
// was handed over at a specific moment and then destroyed. Until now the only
// way to check one was POST /v2/verify-receipt, which asks the relay to grade
// its own homework and needs an API key. This module does the same four checks
// with the same primitives on the visitor's machine, so the receipt can be
// checked without Paramant and without a network connection.
//
// The checks mirror relay.js POST /v2/verify-receipt and relay/lib/ct-hash.js
// byte for byte. Keep them in sync.
import { sha3_256, ml_dsa65 } from '/vendor/paramant-pqc.js';
import { defaultAnchor, anchorByFingerprint, PUBKEY_URL } from '/js/relay-trust-anchors.js';

const LEAF_TRANSFER = 0x02; // domain separator for blob/transfer leaves
const NODE = 0x01;          // domain separator for inner Merkle nodes
const ML_DSA65_PK_BYTES = 1952;

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();

const esc = (s) => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

function hexToBytes(s) {
  const h = String(s || '');
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('not a hexadecimal value');
  const out = new Uint8Array(h.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function fromB64(s) {
  const padded = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

function concatBytes(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

// Byte-identical to relay.js canonicalJSON: sorted keys, no whitespace.
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// relay/lib/ct-hash.js blobLeafHash
function blobLeafHash(blobHashHex, sector, ts) {
  const data = concatBytes([
    hexToBytes(blobHashHex),
    sha3_256(enc.encode(sector || 'relay')),
    enc.encode(String(ts)),
  ]);
  return toHex(sha3_256(concatBytes([new Uint8Array([LEAF_TRANSFER]), data])));
}

// relay/lib/ct-hash.js ctNodeHash
function nodeHash(leftHex, rightHex) {
  return toHex(sha3_256(concatBytes([
    new Uint8Array([NODE]), hexToBytes(leftHex), hexToBytes(rightHex),
  ])));
}

// ── Reading whatever the visitor drops in ───────────────────────────────────
// Receipts travel as base64url (the X-Paramant-Receipt-* handover and the body
// of POST /v2/verify-receipt), but people paste the decoded JSON just as often,
// and some tools wrap it as {"receipt": "..."}. All three are the same receipt.
export function parseReceipt(input) {
  const text = String(input || '').trim();
  if (!text) throw new Error('There is nothing here to check yet.');
  let obj = null;
  if (text[0] === '{') {
    try { obj = JSON.parse(text); } catch { throw new Error('This looks like JSON but it is damaged, so it cannot be read.'); }
    if (obj && typeof obj.receipt === 'string') return parseReceipt(obj.receipt);
  } else {
    const compact = text.replace(/\s+/g, '');
    let decoded;
    try { decoded = new TextDecoder().decode(fromB64(compact)); }
    catch { throw new Error('This is not a receipt. Paste the receipt text, or drop the receipt file.'); }
    try { obj = JSON.parse(decoded); } catch { throw new Error('This is not a receipt. Paste the receipt text, or drop the receipt file.'); }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw new Error('This is not a receipt. Paste the receipt text, or drop the receipt file.');
  }
  if (!obj.blob_hash || !obj.inclusion_proof) {
    throw new Error('This file is not a ParaSend transfer receipt. A receipt names the file it covers and carries its place in the transparency log.');
  }
  return obj;
}

// ── The verification itself ─────────────────────────────────────────────────
// Every check runs; nothing short-circuits, so a bad receipt says everything
// that is wrong with it at once.
export function verifyReceipt(receipt, relayKeyBytes) {
  // `ok` is true, false, or null for "could not be checked here". Only an
  // outright false makes the receipt untrustworthy; a null makes it unproven.
  const checks = [];
  const add = (id, ok, label, detail) => { checks.push({ id, ok, label, detail: detail || '' }); return ok; };
  const proof = receipt.inclusion_proof || {};

  // 1. Does the receipt point at this exact transfer?
  let leafOk = false;
  try {
    const expected = blobLeafHash(receipt.blob_hash, receipt.sector, receipt.ts);
    leafOk = expected === proof.leaf_hash;
    add('leaf', leafOk,
      leafOk ? 'The receipt is about this file and no other.'
             : 'The receipt does not match the file it names.',
      leafOk ? '' : 'The entry it points to in the transparency log belongs to a different file, or the fingerprint inside the receipt was changed afterwards.');
  } catch (e) {
    add('leaf', false, 'The receipt does not match the file it names.', 'The file fingerprint inside it could not be read (' + e.message + ').');
  }

  // 2. Does the log entry really sit in the tree the receipt claims?
  let rootOk = false;
  try {
    let computed = proof.leaf_hash;
    for (const step of (proof.audit_path || [])) {
      computed = step.position === 'right' ? nodeHash(computed, step.hash) : nodeHash(step.hash, computed);
    }
    rootOk = !!computed && computed === proof.root;
    add('tree', rootOk,
      rootOk ? 'It really is in the public transparency log.'
             : 'It is not in the transparency log it claims to be in.',
      rootOk ? '' : 'Recomputing the log from the entry gives a different result, so the proof of inclusion does not hold.');
  } catch (e) {
    add('tree', false, 'It is not in the transparency log it claims to be in.', 'The proof of inclusion could not be recomputed (' + e.message + ').');
  }

  // 3. The relay's signature over the whole receipt.
  const { signature, ...unsigned } = receipt;
  let sigOk = false;
  let keyKnown = null;
  let fingerprint = '';
  if (!relayKeyBytes) {
    add('signature', null, 'The signature was not checked.',
      'No server key was available to check it against. Everything else on this page was still checked.');
  } else if (!signature) {
    add('signature', false, 'This receipt carries no signature at all.',
      'A genuine receipt is always signed by the server that handed the file over.');
  } else {
    try {
      fingerprint = toHex(sha3_256(relayKeyBytes));
      sigOk = ml_dsa65.verify(relayKeyBytes, enc.encode(canonicalJSON(unsigned)), fromB64(signature));
    } catch { sigOk = false; }
    keyKnown = anchorByFingerprint(fingerprint);
    add('signature', sigOk,
      sigOk ? 'The signature holds, so not one character has been altered.'
            : 'The signature does not hold.',
      sigOk ? '' : 'Either the receipt was edited after it was signed, or it was signed by a different key than the one used to check it.');
  }

  // 4. The relay's signature over the log snapshot the proof refers to.
  const sth = proof.sth || null;
  if (sth && sth.signature) {
    if (!relayKeyBytes) {
      add('sth', null, 'The log snapshot was not checked.', 'No server key was available to check its signature against.');
    } else {
      const { signature: sthSig, ...sthPayload } = sth;
      let sthOk = false;
      try { sthOk = ml_dsa65.verify(relayKeyBytes, enc.encode(canonicalJSON(sthPayload)), fromB64(sthSig)); } catch { sthOk = false; }
      const rootMatch = sth.sha3_root === proof.root;
      add('sth', sthOk && rootMatch,
        (sthOk && rootMatch) ? 'The log itself was signed at that moment too.'
                             : 'The log snapshot inside the receipt does not hold up.',
        !sthOk ? 'The signature over the log snapshot does not check out.'
               : (!rootMatch ? 'The snapshot describes a different state of the log than the proof does.' : ''));
    }
  }

  const failed = checks.filter((c) => c.ok === false);
  return {
    valid: failed.length === 0,
    checkedSignature: !!relayKeyBytes,
    checks,
    fingerprint,
    keyName: keyKnown ? keyKnown.name : null,
    receipt,
  };
}

// ── Plain language ──────────────────────────────────────────────────────────
function formatMoment(value) {
  const d = value == null ? null : new Date(typeof value === 'number' ? value : String(value));
  if (!d || isNaN(d.getTime())) return null;
  const date = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(d);
  const time = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }).format(d);
  return date + ' at ' + time + ' UTC';
}

function shortHost(relayId) {
  const raw = String(relayId || '').trim();
  if (!raw) return '';
  try { return new URL(raw).host; } catch { return raw; }
}

function keySentence(result) {
  const fp = result.fingerprint;
  if (!result.checkedSignature) {
    return 'Nobody could be identified as the signer, because no key was available to compare against.';
  }
  const short = esc(fp.slice(0, 16));
  if (result.keyName) {
    return 'It was signed by ' + esc(result.keyName) + ', key <code class="mono">' + short + '</code>.';
  }
  return 'It was signed by a key this page does not recognise, fingerprint <code class="mono">' + short
    + '</code>. Compare that against the key Paramant publishes before you trust it.';
}

export function renderResult(result, target) {
  const r = result.receipt;
  const out = [];
  const signedFully = result.valid && result.checkedSignature;

  if (signedFully && result.keyName) {
    out.push('<div class="ps-banner ok"><strong>This receipt is genuine.</strong> It was issued by '
      + esc(result.keyName) + ' and not one character has changed since.</div>');
  } else if (signedFully) {
    // Every check passed, but against a key this page has never seen. Saying
    // "genuine" there would launder an unknown signer into a Paramant promise.
    out.push('<div class="ps-banner ok"><strong>This receipt is unchanged.</strong> It all still matches the key you gave, and this page does not know that key.</div>');
  } else if (result.valid) {
    out.push('<div class="ps-banner info"><strong>The receipt holds together.</strong> Its signature was not checked, because no server key was available.</div>');
  } else {
    out.push('<div class="ps-banner err"><strong>Do not trust this receipt.</strong> It failed at least one check below.</div>');
  }

  const facts = [];
  facts.push(keySentence(result));
  const when = formatMoment(r.retrieved_at);
  if (when) facts.push('The file was handed over on ' + esc(when) + '.');
  const issued = formatMoment(r.ts);
  if (issued && issued !== when) facts.push('It was accepted by the server on ' + esc(issued) + '.');
  const host = shortHost(r.relay_id);
  if (host) facts.push('The handover was done by <code class="mono">' + esc(host) + '</code>.');
  facts.push('The file it covers has fingerprint <code class="mono">' + esc(String(r.blob_hash)) + '</code>.');
  if (r.burn_confirmed === true) facts.push('The server destroyed its copy of the file as it was handed over.');
  else if (r.burn_confirmed === false) facts.push('The server kept its copy after this download, because the transfer allowed more than one download.');
  const proof = r.inclusion_proof || {};
  if (proof.leaf_index != null && proof.tree_size != null) {
    facts.push('It is entry ' + esc(String(proof.leaf_index + 1)) + ' in a public log that held '
      + esc(String(proof.tree_size)) + ' entries at that moment.');
  }

  // A receipt that failed a check has not earned the word "says": from here on
  // its contents are a claim, and the heading has to read that way.
  out.push('<h3 class="rv-sub">' + (result.valid ? 'What this receipt says' : 'What this receipt claims')
    + '</h3><ul class="rv-facts">');
  for (const f of facts) out.push('<li>' + f + '</li>');
  out.push('</ul>');

  out.push('<h3 class="rv-sub">What was checked</h3><ul class="rv-checks">');
  for (const c of result.checks) {
    const state = c.ok === true ? 'ok' : (c.ok === false ? 'bad' : 'skip');
    const mark = { ok: '\u2713', bad: '\u2715', skip: '\u2013' }[state];
    const words = { ok: 'Passed', bad: 'Failed', skip: 'Not checked' }[state];
    out.push('<li class="rv-' + state + '"><span class="rv-mark" aria-hidden="true">' + mark
      + '</span><span class="rv-body"><span class="rv-sr">' + words + ': </span>'
      + esc(c.label) + (c.detail ? '<span class="rv-detail">' + esc(c.detail) + '</span>' : '') + '</span></li>');
  }
  out.push('</ul>');

  out.push('<details class="rv-raw"><summary>Show the receipt as it was written</summary><pre class="mono">'
    + esc(JSON.stringify(r, null, 2)) + '</pre></details>');

  target.innerHTML = out.join('');
}

// ── Page wiring ─────────────────────────────────────────────────────────────
// A pasted key wins over the pinned one, so a receipt from another relay, or
// from a relay that has rotated its key, stays checkable without a redeploy.
function resolveKey(pastedKey) {
  const raw = String(pastedKey || '').replace(/\s+/g, '');
  if (raw) {
    let bytes;
    try { bytes = fromB64(raw); } catch { throw new Error('That key is not readable. It is one unbroken block of letters and digits.'); }
    if (bytes.length !== ML_DSA65_PK_BYTES) {
      throw new Error('That is not a Paramant signing key: it is ' + bytes.length + ' bytes long instead of ' + ML_DSA65_PK_BYTES + '.');
    }
    return bytes;
  }
  const anchor = defaultAnchor();
  return anchor ? fromB64(anchor.key) : null;
}

export function initReceiptVerifier() {
  const input = $('rv-input');
  const button = $('rv-check');
  const result = $('rv-result');
  const drop = $('rv-drop');
  const file = $('rv-file');
  const keyField = $('rv-key');
  if (!input || !button || !result) return;

  const fail = (message) => {
    result.hidden = false;
    result.innerHTML = '<div class="ps-banner err"><strong>' + esc(message) + '</strong></div>';
  };

  const run = () => {
    result.hidden = false;
    result.innerHTML = '<div class="ps-banner info">Checking on this device…</div>';
    let receipt;
    try { receipt = parseReceipt(input.value); } catch (e) { return fail(e.message); }
    let key = null;
    try { key = resolveKey(keyField ? keyField.value : ''); } catch (e) { return fail(e.message); }
    try {
      renderResult(verifyReceipt(receipt, key), result);
    } catch (e) {
      fail('This receipt could not be checked: ' + e.message);
    }
  };

  button.addEventListener('click', run);

  const loadFile = async (f) => {
    if (!f) return;
    try {
      input.value = await f.text();
      if ($('rv-file-info')) $('rv-file-info').textContent = f.name + ' loaded';
      run();
    } catch { fail('That file could not be read.'); }
  };

  if (file) file.addEventListener('change', (e) => loadFile(e.target.files && e.target.files[0]));
  if (drop) {
    const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
    ['dragenter', 'dragover'].forEach((n) => drop.addEventListener(n, (e) => { stop(e); drop.classList.add('rv-over'); }));
    ['dragleave', 'drop'].forEach((n) => drop.addEventListener(n, (e) => { stop(e); drop.classList.remove('rv-over'); }));
    drop.addEventListener('drop', (e) => loadFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]));
  }

  const keyHint = $('rv-key-hint');
  if (keyHint) keyHint.textContent = PUBKEY_URL;
}

// The page holds two unrelated proofs. Tabs keep one URL, /verify, and
// /verify#receipt opens straight on the receipt side for a link in an email.
export function initTabs() {
  const pairs = [
    { tab: $('tab-doc'), panel: $('panel-doc'), hash: '' },
    { tab: $('tab-receipt'), panel: $('panel-receipt'), hash: '#receipt' },
  ];
  if (pairs.some((p) => !p.tab || !p.panel)) return;

  const show = (chosen) => {
    for (const p of pairs) {
      const on = p === chosen;
      p.tab.setAttribute('aria-selected', on ? 'true' : 'false');
      p.panel.hidden = !on;
    }
  };
  for (const p of pairs) p.tab.addEventListener('click', () => show(p));
  const wanted = pairs.find((p) => p.hash && p.hash === location.hash);
  show(wanted || pairs[0]);
}

initTabs();
initReceiptVerifier();
