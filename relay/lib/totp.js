'use strict';
// Pure TOTP core (RFC 6238), extracted verbatim from relay.js so the monolith
// and its tests share ONE implementation instead of a hand-copied duplicate.
// Dual-verify: a code is accepted if it matches under SHA-256 OR SHA-1 (the RFC
// 6238 default), so every standard authenticator app works. The +/-window slot
// scan is evaluated in full for both algorithms (no early exit), the compare
// stays constant-time, and the per-slot SET NX replay guard is unchanged. On a
// match the algorithm that matched is returned so call sites can flag SHA-1 use.
// relay.js delegates base32Decode / totpCode / verifyTotpGeneric here; the
// in-process verifyTotp (single master secret) keeps its own _usedTotpCodes
// replay map and is dual-verify too.
const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Best-effort wipe of a secret-bearing buffer. Copied from relay.js zeroBuffer so
// the extracted totpCode zeroes its derived key/mac exactly as before.
function zeroBuffer(buf) {
  if (buf && Buffer.isBuffer(buf)) {
    try { crypto.randomFillSync(buf); } catch {}
    try { buf.fill(0); } catch {}
  }
}

function base32Encode(buf) {
  let bits = 0, value = 0, output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { output += ALPHABET[(value >>> (bits - 5)) & 0x1f]; bits -= 5; }
  }
  if (bits > 0) output += ALPHABET[(value << (5 - bits)) & 0x1f];
  return output;
}

function base32Decode(s) {
  let bits = 0, value = 0, output = [];
  s = s.toUpperCase().replace(/=+$/, '');
  for (const c of s) {
    const idx = ALPHABET.indexOf(c);
    // Fix 14 (relay.js): throw on invalid Base32 instead of silently using -1
    if (idx === -1) throw new Error(`Invalid Base32 character: '${c}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xFF); bits -= 8; }
  }
  return Buffer.from(output);
}

function totpCode(secret, counter, algorithm = 'sha256') {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac(algorithm, key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  zeroBuffer(key); zeroBuffer(mac);
  return code.toString().padStart(6, '0');
}

// Pure +/-window slot match. Returns { slot, algorithm } for the matched counter
// slot, or null. By default it dual-verifies: it tries SHA-256 AND SHA-1 (the RFC
// 6238 default) so codes from any standard authenticator app are accepted. An
// explicit `algorithm` (or `algorithms`) opt narrows the set, so single-algorithm
// callers and tests still work. The full window is scanned for every algorithm
// (never short-circuits) to avoid a timing oracle, exactly as the inline relay.js
// loop did. If a code matches under BOTH algorithms (rare), the strongest wins:
// SHA-256 is reported over SHA-1.
function matchTotpSlot(token, secret, opts = {}) {
  const { window = 1, algorithm, algorithms, now = Date.now() } = opts;
  const tokenBuf = Buffer.from(String(token || ''), 'utf8');
  if (tokenBuf.length !== 6) return null;
  const algs = algorithms || (algorithm ? [algorithm] : ['sha256', 'sha1']);
  const counter = Math.floor(now / 1000 / 30);
  let matched = null;
  for (const alg of algs) {
    for (let i = -window; i <= window; i++) {
      const c = counter + i;
      const expected = totpCode(secret, c, alg);
      const expectedBuf = Buffer.from(expected, 'utf8');
      const eq = tokenBuf.length === expectedBuf.length && crypto.timingSafeEqual(tokenBuf, expectedBuf);
      // Full scan, no early exit. Keep the strongest match: SHA-256 over SHA-1.
      if (eq && (matched === null || alg === 'sha256')) matched = { slot: c, algorithm: alg };
    }
  }
  return matched;
}

// Verify with an injected replay store (Redis-shaped: async set(key,val,{NX,EX})
// returning 'OK' or null). Dual-verify by default (SHA-256 OR SHA-1). Behaviour-
// identical to the former relay.js verifyTotpGeneric for the replay path: no store
// or no replayKey => match-only; a per-slot NX key rejects reuse of a still-in-
// window code; a store error fails OPEN (.catch => 'OK') so a Redis blip never
// locks out a legitimate first use. On success returns { valid:true, algorithm },
// where algorithm is 'sha256' or 'sha1' (the one that matched); on no match returns
// { valid:false }.
async function verifyTotpGeneric(token, secret, opts = {}, store = null) {
  const { window = 1, replayKey, algorithm, algorithms, now } = opts;
  const matched = matchTotpSlot(token, secret, { window, algorithm, algorithms, now: now ?? Date.now() });
  if (matched === null) return { valid: false };
  if (replayKey && store) {
    const slotKey = `${replayKey}:${matched.slot}`;
    const ok = await store.set(slotKey, '1', { NX: true, EX: 90 }).catch(() => 'OK');
    if (ok === null) return { valid: false };
  }
  return { valid: true, algorithm: matched.algorithm };
}

module.exports = {
  ALPHABET,
  base32Encode,
  base32Decode,
  totpCode,
  matchTotpSlot,
  verifyTotpGeneric,
};
