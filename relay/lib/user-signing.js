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
//   { alg: 'ML-DSA-65', pk_b64, pk_hash_sha3, label, enrolled_at, revoked_at|null }

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

// Append a new enrollment. Server computes pk_hash itself — never trusts client.
// Idempotent: re-enrolling the same pk for the same user returns the existing
// entry (and clears revoked_at if it was revoked, treating it as re-enrollment).
async function storeSigningPk(redisClient, userId, { pk_b64, label }) {
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
  const now = new Date().toISOString();

  if (existing) {
    // Re-enrollment of a previously revoked key clears the revocation.
    existing.revoked_at = null;
    if (cleanLabel) existing.label = cleanLabel;
    await _writeArray(redisClient, userId, arr);
    await redisClient.set(_indexKey(pk_hash_sha3), JSON.stringify({ userId }));
    return { entry: existing, reenrolled: true };
  }

  const entry = {
    alg: ALG,
    pk_b64,
    pk_hash_sha3,
    label: cleanLabel || null,
    enrolled_at: now,
    revoked_at: null,
  };
  arr.push(entry);
  await _writeArray(redisClient, userId, arr);
  await redisClient.set(_indexKey(pk_hash_sha3), JSON.stringify({ userId }));
  return { entry, reenrolled: false };
}

async function getSigningPks(redisClient, userId) {
  return _readArray(redisClient, userId);
}

async function getActiveSigningPks(redisClient, userId) {
  const arr = await _readArray(redisClient, userId);
  return arr.filter(e => !e.revoked_at);
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
  ALG,
  ML_DSA_65_PK_LEN,
  storeSigningPk,
  getSigningPks,
  getActiveSigningPks,
  revokeSigningPk,
  lookupByPkHash,
  _computePkHash, // exposed for relay-side hash binding (e.g., revoke validation)
};
