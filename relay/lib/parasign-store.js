'use strict';
// ParaSign Open-API (/v1) durable side-store.
//
// The /v1 hosted-ceremony (Model A) is the ONE deliberate break of the "relay
// never sees the PDF" invariant: to run the signing ceremony the relay must
// hold the document bytes and a small side-record (webhook target + secret,
// plaintext signer names/emails, metadata) that the zero-knowledge envelope
// hash in envelope.js cannot carry. The first build kept both IN-MEMORY, so a
// relay restart lost every in-flight document, webhook and owner mapping and
// GET /document returned document_gone for a still-valid envelope.
//
// This module makes that side-store DURABLE and ENCRYPTED-AT-REST:
//   * backend = redis when a client + a 32-byte key are injected, else an
//     in-memory Map fallback (unit tests / crypto-less dev).
//   * every value is AES-256-GCM sealed before it touches redis. The GCM AAD
//     binds each ciphertext to its exact key ("parasign:<kind>:<id>"), so a
//     redis-write attacker cannot lift one envelope's blob under another id.
//   * TTL is preserved: redis keys carry PX = ttlMs, so a document disappears
//     exactly when its envelope would have. A still-valid envelope survives a
//     restart because redis (the same store the envelope lives in) persists it.
//
// Kinds:
//   blob:<id>    -> the original PDF bytes (Buffer)
//   stamped:<id> -> the server-stamped PDF bytes (Buffer, cached after first bake)
//   meta:<id>    -> the JSON side-record (webhook_url/secret, signers, metadata)
//
// The module owns NO envelope crypto and NO signing key. Its only secret is the
// at-rest encryption key, injected by relay.js (PARASIGN_STORE_KEY, falling back
// to the already-required PARAMANT_TOTP_MASTER_KEY).

const crypto = require('crypto');

const NONCE_LEN = 12;
const TAG_LEN = 16;

// AES-256-GCM seal. Layout: nonce(12) || tag(16) || ciphertext, base64-encoded
// so it stores as a plain redis string (the shared client is not in Buffer mode).
// aad binds the ciphertext to its logical slot so it cannot be relocated.
function seal(plain, key, aad) {
  const nonce = crypto.randomBytes(NONCE_LEN);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(Buffer.from(aad, 'utf8'));
  const enc = Buffer.concat([c.update(plain), c.final()]);
  const tag = c.getAuthTag();
  return Buffer.concat([nonce, tag, enc]).toString('base64');
}

function unseal(b64, key, aad) {
  const raw = Buffer.from(String(b64), 'base64');
  if (raw.length < NONCE_LEN + TAG_LEN) throw new Error('sealed value too short');
  const nonce = raw.subarray(0, NONCE_LEN);
  const tag = raw.subarray(NONCE_LEN, NONCE_LEN + TAG_LEN);
  const ct = raw.subarray(NONCE_LEN + TAG_LEN);
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// Coerce an arbitrary env-provided key into a 32-byte Buffer, or null. Accepts
// base64 (preferred) or hex; anything not exactly 32 bytes is rejected so a
// misconfigured key fails loud rather than silently weakening encryption.
function normalizeKey(raw) {
  if (!raw) return null;
  if (Buffer.isBuffer(raw)) return raw.length === 32 ? raw : null;
  const s = String(raw);
  for (const enc of ['base64', 'hex']) {
    try { const k = Buffer.from(s, enc); if (k.length === 32) return k; } catch { /* try next */ }
  }
  return null;
}

function createParaSignStore({ redis, encKey, log } = {}) {
  const key = normalizeKey(encKey);
  const useRedis = !!(redis && key);
  if (redis && !key && log) {
    log('warn', 'parasign_store_memory_fallback',
      { reason: 'no 32-byte encryption key; documents will NOT survive restart' });
  }

  // In-memory fallback: { val, expiresAt }. A lazy sweep on read + a periodic
  // timer keep it bounded. Only used without redis/key (tests, crypto-less dev).
  const mem = new Map();
  const memSweep = () => {
    const now = Date.now();
    for (const [k, v] of mem) if (v.expiresAt && now > v.expiresAt) mem.delete(k);
  };
  const memTimer = useRedis ? null : setInterval(memSweep, 300_000);
  if (memTimer && memTimer.unref) memTimer.unref();

  const rkey = (kind, id) => `psign:${kind}:${id}`;
  const aadOf = (kind, id) => `parasign:${kind}:${id}`;

  async function put(kind, id, plainBuf, ttlMs) {
    const n = Number(ttlMs);
    // Valid positive ttl passes through; a missing/NaN/non-positive ttl falls
    // back to the default retention. Floored at 1ms so redis PX is always a
    // positive integer (PX <= 0 is rejected).
    const ttl = Math.max(1, (Number.isFinite(n) && n > 0) ? n : 30 * 86400_000);
    if (useRedis) {
      const sealed = seal(plainBuf, key, aadOf(kind, id));
      await redis.set(rkey(kind, id), sealed, { PX: Math.floor(ttl) });
      return;
    }
    mem.set(rkey(kind, id), { val: Buffer.from(plainBuf), expiresAt: Date.now() + ttl });
  }

  async function get(kind, id) {
    if (useRedis) {
      const sealed = await redis.get(rkey(kind, id));
      if (!sealed) return null;
      try { return unseal(sealed, key, aadOf(kind, id)); }
      catch (e) { log && log('warn', 'parasign_store_unseal_fail', { kind, id, err: e.message }); return null; }
    }
    memSweep();
    const rec = mem.get(rkey(kind, id));
    return rec ? Buffer.from(rec.val) : null;
  }

  async function del(kind, id) {
    if (useRedis) { try { await redis.del(rkey(kind, id)); } catch { /* best effort */ } return; }
    mem.delete(rkey(kind, id));
  }

  return {
    backend: useRedis ? 'redis' : 'memory',

    // ── document blobs (original + stamped) ─────────────────────────────────
    async putBlob(id, pdfBuf, ttlMs) { return put('blob', id, pdfBuf, ttlMs); },
    async getBlob(id) { return get('blob', id); },
    async delBlob(id) { await del('blob', id); await del('stamped', id); },
    async putStamped(id, pdfBuf, ttlMs) { return put('stamped', id, pdfBuf, ttlMs); },
    async getStamped(id) { return get('stamped', id); },

    // ── side-record (webhook + plaintext signers + metadata) ────────────────
    async putMeta(id, obj, ttlMs) {
      return put('meta', id, Buffer.from(JSON.stringify(obj || {}), 'utf8'), ttlMs);
    },
    async getMeta(id) {
      const buf = await get('meta', id);
      if (!buf) return null;
      try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
    },
    async delMeta(id) { await del('meta', id); },

    // test/diagnostic hooks
    _mem: mem,
    _sealForTest: (plain, aad) => seal(plain, key, aad),
  };
}

module.exports = { createParaSignStore, normalizeKey, seal, unseal };
