// In-browser check that one entry of the public CT log really sits in the tree
// the relay has signed. Used by /ct-log and /en/ct-log.
//
// WHY THIS EXISTS. The "Check a hash" box on /ct-log used to answer "✓ Verified"
// as soon as a prefix of the typed hash matched a row in the list the relay had
// just sent. That is a text search in the relay's own answer: no Merkle proof,
// no signed tree head, no key. A relay that lied would have been "verified" by
// its own lie (independent review, 2026-10-06, RAPPORT.md section 4).
//
// What this module checks, every step against something the relay cannot bend:
//   1. the key: the relay's ML-DSA-65 key is the one this site pins in
//      relay-trust-anchors.js, and SHA3-256 of it is the pinned fingerprint;
//   2. the head: GET /v2/sth is signed by that pinned key, over the same
//      canonical JSON relay.js produceSth() signs, and names this relay;
//   3. inclusion: GET /v2/ct/proof/:i?tree_size=N folds from the listed leaf to
//      the signed root at that size (RFC 9162 section 2.1.3.2, positions derived
//      from index and size, not taken from the server);
//   4. consistency: if this browser has seen a signed head of this relay before,
//      GET /v2/sth/consistency proves the new tree extends the old one.
// Only when 1-3 hold and 4 does not fail does the page say "verified".
//
// What it does NOT show, and the page says so: that anyone else sees the same
// tree. Without an outside witness a relay can show each visitor a different
// tree; step 4 only catches that between two visits of the same browser.
import { sha3_256, ml_dsa65 } from '/vendor/paramant-pqc.js';
import { anchorByHost, hostOfRelayId } from '/js/relay-trust-anchors.js?v=2';

const enc = new TextEncoder();
const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

function hexToBytes(s) {
  const h = String(s || '');
  if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2) throw new Error('not hex');
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

// relay/lib/ct-hash.js ctNodeHash: SHA3-256(0x01 || left || right).
export function nodeHash(leftHex, rightHex) {
  const l = hexToBytes(leftHex), r = hexToBytes(rightHex);
  const buf = new Uint8Array(1 + l.length + r.length);
  buf[0] = 0x01; buf.set(l, 1); buf.set(r, 1 + l.length);
  return toHex(sha3_256(buf));
}

const isHash = (h) => typeof h === 'string' && /^[0-9a-f]{64}$/i.test(h);

// Canonical JSON exactly as relay.js produceSth(): sorted keys, no whitespace.
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// RFC 9162 section 2.1.3.2. `proof` is the relay's format: an array of
// {hash, position} (or plain hashes). The positions the server sends are
// checked against the ones the index and size dictate; a proof that only works
// with positions of its own choosing is rejected.
export function verifyInclusion(leafHex, index, treeSize, proof, rootHex) {
  if (!isHash(leafHex) || !isHash(rootHex)) return false;
  if (!Number.isInteger(index) || !Number.isInteger(treeSize) || index < 0 || index >= treeSize) return false;
  if (!Array.isArray(proof)) return false;
  let fn = index, sn = treeSize - 1, r = leafHex.toLowerCase();
  for (const step of proof) {
    const p = typeof step === 'string' ? step : step && step.hash;
    const claimed = typeof step === 'object' && step ? step.position : null;
    if (!isHash(p)) return false;
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      if (claimed && claimed !== 'left') return false;
      r = nodeHash(p, r);
      if (!(fn & 1)) { while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    } else {
      if (claimed && claimed !== 'right') return false;
      r = nodeHash(r, p);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && r === rootHex.toLowerCase();
}

// RFC 9162 section 2.1.4.2, the same algorithm as relay/lib/ct-tree.js
// verifyConsistency.
export function verifyConsistency(from, to, oldRoot, newRoot, proof) {
  if (!Array.isArray(proof)) return false;
  if (from === to) return proof.length === 0 && oldRoot === newRoot;
  if (!(from > 0) || from > to) return false;
  let path = proof.slice();
  if (path.some((h) => !isHash(h))) return false;
  if ((from & (from - 1)) === 0) path = [oldRoot].concat(path);
  if (path.length === 0) return false;
  let fn = from - 1, sn = to - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = path[0], sr = path[0];
  for (let i = 1; i < path.length; i++) {
    const c = path[i];
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      fr = nodeHash(c, fr); sr = nodeHash(c, sr);
      if (!(fn & 1)) { while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && fr === oldRoot && sr === newRoot;
}

export function verifySthSignature(sth, pkBytes) {
  if (!sth || !sth.signature || !pkBytes) return false;
  const payload = {
    relay_id: sth.relay_id, sha3_root: sth.sha3_root, timestamp: sth.timestamp,
    tree_size: sth.tree_size, version: sth.version || 1,
  };
  try { return ml_dsa65.verify(pkBytes, enc.encode(canonicalJSON(payload)), fromB64(sth.signature)); }
  catch { return false; }
}

const storeKey = (host) => 'paramant.ct.seen-sth.' + host;
function readSeen(host) {
  try { const v = JSON.parse(localStorage.getItem(storeKey(host)) || 'null'); return v && Number.isInteger(v.tree_size) && isHash(v.sha3_root) ? v : null; }
  catch { return null; }
}
function writeSeen(host, sth) {
  try { localStorage.setItem(storeKey(host), JSON.stringify({ tree_size: sth.tree_size, sha3_root: sth.sha3_root })); } catch { /* private mode */ }
}

// Result: { verdict, steps, treeSize }
//   verdict 'verified' every check held;
//           'failed'   a check came back wrong (do not trust this relay's answer);
//           'unchecked' a check could not be run (offline, no pinned key) - the
//                      entry is in the list, and nothing more is claimed.
//   steps   [{ id: 'key'|'sth'|'inclusion'|'consistency', ok: true|false|null }]
//           consistency ok:null means "no earlier head in this browser".
export async function verifyEntry({ relay, index, leafHash, fetchFn }) {
  const get = fetchFn || ((u) => fetch(u));
  const steps = [];
  const add = (id, ok) => { steps.push({ id, ok }); return ok; };
  const done = () => {
    const required = steps.filter((s) => s.id !== 'consistency');
    const verdict = steps.some((s) => s.ok === false) ? 'failed'
      : (required.length === 3 && required.every((s) => s.ok === true)) ? 'verified' : 'unchecked';
    return { verdict, steps };
  };
  const host = hostOfRelayId(relay);
  const anchor = anchorByHost(host);
  let pk = null;
  if (anchor) {
    try {
      pk = fromB64(anchor.key);
      if (toHex(sha3_256(pk)) !== anchor.fingerprint) pk = null;
    } catch { pk = null; }
  }
  if (!add('key', pk ? true : null)) return done();

  let sth;
  try {
    const r = await get(relay + '/v2/sth');
    sth = r.ok ? (await r.json()).sth : null;
  } catch { sth = null; }
  if (!sth) { add('sth', null); return done(); }
  const sthOk = verifySthSignature(sth, pk) && hostOfRelayId(sth.relay_id) === host
    && Number.isInteger(sth.tree_size) && isHash(sth.sha3_root);
  if (!add('sth', sthOk)) return done();

  if (!Number.isInteger(index) || index >= sth.tree_size) { add('inclusion', null); return done(); }
  let proof;
  try {
    const r = await get(relay + '/v2/ct/proof/' + index + '?tree_size=' + sth.tree_size);
    proof = r.ok ? await r.json() : null;
  } catch { proof = null; }
  if (!proof) { add('inclusion', null); return done(); }
  // A relay from before 3.1.2 ignores ?tree_size and answers with the path to
  // the tree at index + 1, without a tree_size field. That path cannot fold to
  // the current head, and calling it "failed" would accuse an honest relay, so
  // it is "not checked" instead.
  if (proof.tree_size !== sth.tree_size) { add('inclusion', null); return done(); }
  const inclOk = String(proof.leaf_hash || '').toLowerCase() === String(leafHash || '').toLowerCase()
    && verifyInclusion(String(leafHash || '').toLowerCase(), index, sth.tree_size, proof.proof, sth.sha3_root);
  if (!add('inclusion', inclOk)) return done();

  const seen = readSeen(host);
  if (!seen) {
    add('consistency', null);
  } else if (seen.tree_size === sth.tree_size) {
    add('consistency', seen.sha3_root === sth.sha3_root);
  } else if (seen.tree_size > sth.tree_size) {
    add('consistency', false);
  } else {
    let ok = null;
    try {
      const r = await get(relay + '/v2/sth/consistency?from=' + seen.tree_size + '&to=' + sth.tree_size);
      if (r.ok) {
        const c = await r.json();
        ok = verifyConsistency(seen.tree_size, sth.tree_size, seen.sha3_root, sth.sha3_root, c.proof);
      }
    } catch { ok = null; }
    add('consistency', ok);
  }
  const consistency = steps[steps.length - 1].ok;
  if (consistency !== false) writeSeen(host, sth);
  const res = done();
  res.treeSize = sth.tree_size;
  return res;
}
