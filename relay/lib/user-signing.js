'use strict';
// Account-bound signing identity store.
//
// Persists the *public half* of a user's ML-DSA-65 signing key alongside the
// rest of their account state. Private keys never reach the server — only
// the public key, its SHA3-256 fingerprint, and an optional label.
//
// Multiple keys per user (GitHub-SSH style). Revoke keeps history (sets
// revoked_at) so old envelopes remain "valid at signing time" verifiable.
//
// Redis layout:
//   paramant:user:signing_pk:${userId}      → JSON array of pk entries
//   paramant:signing_pk_index:${pk_hash}    → JSON { userId }  (O(1) reverse lookup)
//
// Each entry shape:
//   { alg: 'ML-DSA-65', pk_b64, pk_hash_sha3, label, enrolled_at, revoked_at|null,
//     expires_at|absent }
//
// expires_at (36-K): a key bound with a 6-digit code is made for ONE signature.
// The browser does not keep its secret half, so it can never sign again, yet it
// stayed "active" for ever and fifty of them closed the account off
// (MAX_ACTIVE_KEYS). Such a key now lapses by itself after CODE_KEY_TTL_MS. A
// lapsed key is history like a revoked one: it stays in the list and in the
// reverse index, so old signatures still resolve, but it no longer counts as
// active and cannot fill a new signature slot.

const crypto = require('crypto');

const ALG = 'ML-DSA-65';
const ML_DSA_65_PK_LEN = 1952; // bytes; per NIST FIPS 204

function _userKey(userId) { return `paramant:user:signing_pk:${userId}`; }
function _indexKey(pkHash) { return `paramant:signing_pk_index:${pkHash}`; }

function _isHex64(s) { return typeof s === 'string' && /^[0-9a-f]{64}$/.test(s); }

function _computePkHash(pkB64) {
  const pkBuf = Buffer.from(pkB64, 'base64');
  if (pkBuf.length !== ML_DSA_65_PK_LEN) {
    throw new Error(`invalid ML-DSA-65 public key length: ${pkBuf.length} (expected ${ML_DSA_65_PK_LEN})`);
  }
  return crypto.createHash('sha3-256').update(pkBuf).digest('hex');
}

async function _readArray(redisClient, userId) {
  const raw = await redisClient.get(_userKey(userId));
  if (!raw) return [];
  try { const parsed = JSON.parse(raw); return Array.isArray(parsed) ? parsed : []; }
  catch { return []; }
}

async function _writeArray(redisClient, userId, arr) {
  await redisClient.set(_userKey(userId), JSON.stringify(arr));
}

const MAX_ACTIVE_KEYS = 50;
// Long enough for the signature it was made for (bind, sign and submit happen
// in one sitting), short enough that the ceiling is never a dead end.
const CODE_KEY_TTL_MS = 24 * 60 * 60 * 1000;

function isExpired(e, nowMs = Date.now()) {
  if (!e || !e.expires_at) return false;
  const t = Date.parse(e.expires_at);
  return Number.isFinite(t) && t <= nowMs;
}
function isActive(e, nowMs = Date.now()) {
  return !!e && !e.revoked_at && !isExpired(e, nowMs);
}

// Append a new enrollment. Server computes pk_hash itself — never trusts client.
// Idempotent: re-enrolling the same pk for the same user returns the existing
// entry (and clears revoked_at if it was revoked, treating it as re-enrollment).
// expiresInMs: set for a key bound with a code (one signature, see expires_at
// above); absent for passkey-attested and invite keys, which do not lapse.
async function storeSigningPk(redisClient, userId, { pk_b64, label, expiresInMs } = {}) {
  if (!userId) throw new Error('userId required');
  if (typeof pk_b64 !== 'string' || !pk_b64) throw new Error('pk_b64 required');
  const pk_hash_sha3 = _computePkHash(pk_b64); // also validates length
  const cleanLabel = (label || '').toString().slice(0, 64);

  // Reverse-index conflict check: same pk_hash already mapped to a *different* user?
  const idxRaw = await redisClient.get(_indexKey(pk_hash_sha3));
  if (idxRaw) {
    try {
      const idx = JSON.parse(idxRaw);
      if (idx.userId && idx.userId !== userId) {
        throw new Error('pubkey already enrolled to a different account');
      }
    } catch (e) {
      if (e.message === 'pubkey already enrolled to a different account') throw e;
      // Fail closed: an index entry exists but is unreadable. Overwriting it would
      // be fail-open (could silently re-map a pubkey across accounts on corruption).
      throw new Error('pubkey index unreadable; refusing to overwrite');
    }
  }

  const arr = await _readArray(redisClient, userId);
  const existing = arr.find(e => e.pk_hash_sha3 === pk_hash_sha3);
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const expiresAt = Number.isFinite(expiresInMs) && expiresInMs > 0 ? new Date(nowMs + expiresInMs).toISOString() : null;

  if (existing) {
    // Re-enrollment of a previously revoked key clears the revocation.
    existing.revoked_at = null;
    if (cleanLabel) existing.label = cleanLabel;
    // A code bind lapses again from now; any other bind makes it lasting.
    if (expiresAt) existing.expires_at = expiresAt; else delete existing.expires_at;
    await _writeArray(redisClient, userId, arr);
    await redisClient.set(_indexKey(pk_hash_sha3), JSON.stringify({ userId }));
    return { entry: existing, reenrolled: true };
  }

  // A ceiling on active keys: every new key needs its own confirmation, but a
  // bind that succeeded while the answer was lost leaves a key nobody holds,
  // and nothing bounded how many could pile up (review r2 (c)). Revoked keys
  // stay as history and do not count, and neither do lapsed code keys (36-K).
  //
  // At the ceiling the OLDEST active keys lapse, they are not refused (review
  // #555, M9): code keys bound before keys had an expiry stay active forever,
  // so an account that signed fifty times before the deploy could not sign
  // again. A lapsed key is not revoked: signatures it made still verify and
  // its lookup still names the account; it only stops counting and binding.
  const active = arr.filter((e) => isActive(e, nowMs))
    .sort((a, b) => (Date.parse(a.enrolled_at) || 0) - (Date.parse(b.enrolled_at) || 0));
  const retired = [];
  while (active.length >= MAX_ACTIVE_KEYS) {
    const old = active.shift();
    old.expires_at = now;
    old.expired_reason = 'key_cap';
    retired.push(old.pk_hash_sha3);
  }
  const entry = {
    alg: ALG,
    pk_b64,
    pk_hash_sha3,
    label: cleanLabel || null,
    enrolled_at: now,
    revoked_at: null,
  };
  if (expiresAt) entry.expires_at = expiresAt;
  arr.push(entry);
  await _writeArray(redisClient, userId, arr);
  await redisClient.set(_indexKey(pk_hash_sha3), JSON.stringify({ userId }));
  return { entry, reenrolled: false, ...(retired.length ? { retired } : {}) };
}

async function getSigningPks(redisClient, userId) {
  return _readArray(redisClient, userId);
}

async function getActiveSigningPks(redisClient, userId) {
  const arr = await _readArray(redisClient, userId);
  const nowMs = Date.now();
  return arr.filter(e => isActive(e, nowMs));
}

// Marks the entry with matching pk_hash_sha3 as revoked. History is kept so
// envelopes that quoted this pubkey remain verifiable against the snapshot.
async function revokeSigningPk(redisClient, userId, pkHashSha3) {
  if (!_isHex64(pkHashSha3)) throw new Error('pk_hash_sha3 must be 64-char hex');
  const arr = await _readArray(redisClient, userId);
  const idx = arr.findIndex(e => e.pk_hash_sha3 === pkHashSha3);
  if (idx < 0) return { revoked: false, reason: 'not_found' };
  if (arr[idx].revoked_at) return { revoked: false, reason: 'already_revoked', entry: arr[idx] };
  arr[idx].revoked_at = new Date().toISOString();
  await _writeArray(redisClient, userId, arr);
  // Keep the reverse-index intact so lookups for old signatures still resolve
  // (showing revoked_at on the result so the verifier can decide).
  return { revoked: true, entry: arr[idx] };
}

// Public lookup. Exact-hash match only — never a prefix scan — so an attacker
// cannot enumerate the keyspace. Rate-limiting is the caller's responsibility.
// Returns { userId, entry } or null. Caller decides what to project (e.g., add
// email from user-meta).
async function lookupByPkHash(redisClient, pkHashSha3) {
  if (!_isHex64(pkHashSha3)) return null;
  const idxRaw = await redisClient.get(_indexKey(pkHashSha3));
  if (!idxRaw) return null;
  let userId;
  try { userId = JSON.parse(idxRaw).userId; } catch { return null; }
  if (!userId) return null;
  const arr = await _readArray(redisClient, userId);
  const entry = arr.find(e => e.pk_hash_sha3 === pkHashSha3);
  if (!entry) return null;
  return { userId, entry };
}

module.exports = {
  MAX_ACTIVE_KEYS,
  CODE_KEY_TTL_MS,
  isExpired,
  isActive,
  ALG,
  ML_DSA_65_PK_LEN,
  storeSigningPk,
  getSigningPks,
  getActiveSigningPks,
  revokeSigningPk,
  lookupByPkHash,
  _computePkHash, // exposed for relay-side hash binding (e.g., revoke validation)
};
