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
// returning 'OK' or null). Dual-verify by default (SHA-256 OR SHA-1). No store or
// no replayKey => match-only; a per-slot NX key rejects reuse of a still-in-window
// code. On success returns { valid:true, algorithm }, where algorithm is 'sha256'
// or 'sha1' (the one that matched); on no match returns { valid:false }.
//
// FAIL-CLOSED ON A STORE ERROR (changed). This used to be
// `.catch(() => 'OK')`: if Redis threw, the single-use check silently reported
// success and the code was accepted. The comment above it called that a
// deliberate choice for availability, and for a check that only prevented
// double-spending a code it would be arguable. It is not arguable here. The NX
// key is the only thing standing between an observed TOTP code and its replay
// inside the same 30-second slot, on the endpoint that mints admin-panel
// sessions. Trading that away buys availability for a login that, during a Redis
// outage, cannot mint a session anyway: the session store IS Redis.
//
// So a store failure now yields { valid:false, error:'replay_store_unavailable' },
// which call sites answer with 503 and a log line, distinct from the 401 a wrong
// code gets. A refused replay yields { valid:false, error:'replay' }.
//
// A STORE THAT NEVER ANSWERS IS ALSO AN OUTAGE. node-redis queues commands while
// it reconnects, so against an unreachable server `set` neither resolves nor
// rejects: it waits. Fail-closed has to cover that case too, or the guard simply
// hangs instead of deciding, so the wait is bounded (`storeTimeoutMs`, 1s) and a
// timeout is reported exactly like a thrown error. A SET that lands after the
// timeout does no harm: it marks a slot used, which is the safe direction.
const REPLAY_STORE_UNAVAILABLE = 'replay_store_unavailable';
const REPLAY_STORE_TIMEOUT_MS = 1000;

async function verifyTotpGeneric(token, secret, opts = {}, store = null) {
  const { window = 1, replayKey, algorithm, algorithms, now, storeTimeoutMs = REPLAY_STORE_TIMEOUT_MS } = opts;
  const matched = matchTotpSlot(token, secret, { window, algorithm, algorithms, now: now ?? Date.now() });
  if (matched === null) return { valid: false };
  if (replayKey && store) {
    const slotKey = `${replayKey}:${matched.slot}`;
    let ok;
    // try/catch as well as .catch: a store whose set() throws synchronously
    // never returns a promise to attach a handler to.
    let timer = null;
    try {
      const call = Promise.resolve(store.set(slotKey, '1', { NX: true, EX: 90 }));
      const TIMED_OUT = Symbol('replay_store_timeout');
      const deadline = new Promise((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), storeTimeoutMs); });
      ok = await Promise.race([call, deadline]);
      if (ok === TIMED_OUT) return { valid: false, error: REPLAY_STORE_UNAVAILABLE };
    } catch {
      return { valid: false, error: REPLAY_STORE_UNAVAILABLE };
    } finally {
      if (timer) clearTimeout(timer);
    }
    if (ok === null) return { valid: false, error: 'replay' };
  }
  return { valid: true, algorithm: matched.algorithm };
}

module.exports = {
  ALPHABET,
  REPLAY_STORE_UNAVAILABLE,
  REPLAY_STORE_TIMEOUT_MS,
  base32Encode,
  base32Decode,
  totpCode,
  matchTotpSlot,
  verifyTotpGeneric,
};
