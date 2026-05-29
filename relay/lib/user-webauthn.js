'use strict';
// Account-bound WebAuthn / passkey credential store (ADR R018, PR-A).
//
// Persists only the PUBLIC verification material of a user's passkey(s):
// credential id, COSE public key, signature counter, transports, and a
// per-credential PRF-support flag. The relay never sees the authenticator's
// private key. The WebAuthn *ceremony* (challenge issue + attestation/assertion
// verification, rpId/origin checks) lives in the admin server, same-origin with
// the site; this module is just durable storage, mirroring user-signing.js and
// user-totp.js so passkeys are as durable (and sector-replicated) as TOTP.
//
// Multiple credentials per user (one per device/passkey). Revoke keeps the
// history entry (sets revoked_at) but removes the cred-id index so a revoked
// credential can no longer be looked up for authentication.
//
// A random per-account user handle is minted on first registration and used as
// the WebAuthn user.id (so the credential carries no PII and never the pgp_
// API key). It also enables usernameless / discoverable-credential login.
//
// Redis layout:
//   paramant:user:webauthn:creds:${userId}     → JSON array of credential entries
//   paramant:webauthn:credid_index:${credId}   → JSON { userId }  (auth lookup)
//   paramant:user:webauthn:handle:${userId}    → user handle (base64url string)
//   paramant:webauthn:handle_index:${handle}   → JSON { userId }  (usernameless login)
//
// Each credential entry:
//   { credId, publicKey, counter, transports, prfSupported, aaguid,
//     label, created_at, last_used_at, revoked_at|null }
//   credId/publicKey are base64url strings.

const crypto = require('crypto');

const HANDLE_BYTES = 16; // 22-char base64url; well under WebAuthn's 64-byte user.id cap

function _credsKey(userId)   { return `paramant:user:webauthn:creds:${userId}`; }
function _credIdIndex(credId){ return `paramant:webauthn:credid_index:${credId}`; }
function _handleKey(userId)  { return `paramant:user:webauthn:handle:${userId}`; }
function _handleIndex(handle){ return `paramant:webauthn:handle_index:${handle}`; }

function _isB64Url(s) { return typeof s === 'string' && s.length > 0 && /^[A-Za-z0-9_-]+$/.test(s); }

async function _readArray(redisClient, userId) {
  const raw = await redisClient.get(_credsKey(userId));
  if (!raw) return [];
  try { const p = JSON.parse(raw); return Array.isArray(p) ? p : []; }
  catch { return []; }
}

async function _writeArray(redisClient, userId, arr) {
  await redisClient.set(_credsKey(userId), JSON.stringify(arr));
}

// Return the account's WebAuthn user handle, minting (and indexing) one on
// first call. Idempotent: a second call returns the same handle.
async function getOrCreateUserHandle(redisClient, userId) {
  if (!userId) throw new Error('userId required');
  const existing = await redisClient.get(_handleKey(userId));
  if (existing) return existing;
  const handle = crypto.randomBytes(HANDLE_BYTES).toString('base64url');
  await redisClient.set(_handleKey(userId), handle);
  await redisClient.set(_handleIndex(handle), JSON.stringify({ userId }));
  return handle;
}

async function getUserHandle(redisClient, userId) {
  return (await redisClient.get(_handleKey(userId))) || null;
}

// Resolve a WebAuthn userHandle (from a discoverable-credential assertion) back
// to the account. Returns { userId } or null.
async function lookupByHandle(redisClient, handle) {
  if (!_isB64Url(handle)) return null;
  const raw = await redisClient.get(_handleIndex(handle));
  if (!raw) return null;
  try { const { userId } = JSON.parse(raw); return userId ? { userId } : null; }
  catch { return null; }
}

// Store (or re-enroll) a credential. The caller (admin ceremony) has already
// verified the registration attestation; this only persists the result.
// Idempotent on credId for the same user. Rejects a credId already bound to a
// different account.
async function storeCredential(redisClient, userId, cred) {
  if (!userId) throw new Error('userId required');
  const { credId, publicKey } = cred || {};
  if (!_isB64Url(credId)) throw new Error('credId (base64url) required');
  if (typeof publicKey !== 'string' || !publicKey) throw new Error('publicKey required');

  // Reverse-index conflict: credId already mapped to a *different* user?
  const idxRaw = await redisClient.get(_credIdIndex(credId));
  if (idxRaw) {
    try {
      const idx = JSON.parse(idxRaw);
      if (idx.userId && idx.userId !== userId) throw new Error('credential already registered to a different account');
    } catch (e) {
      if (e.message === 'credential already registered to a different account') throw e;
      // malformed index — overwrite below
    }
  }

  const arr = await _readArray(redisClient, userId);
  const now = new Date().toISOString();
  const cleanLabel = (cred.label || '').toString().slice(0, 64) || null;
  const existing = arr.find(e => e.credId === credId);

  if (existing) {
    existing.revoked_at = null;                       // re-enroll un-revokes
    existing.publicKey = publicKey;
    existing.counter = Number.isFinite(cred.counter) ? cred.counter : (existing.counter | 0);
    if (Array.isArray(cred.transports)) existing.transports = cred.transports;
    if (typeof cred.prfSupported === 'boolean') existing.prfSupported = cred.prfSupported;
    if (cred.aaguid) existing.aaguid = cred.aaguid;
    if (cleanLabel) existing.label = cleanLabel;
    await _writeArray(redisClient, userId, arr);
    await redisClient.set(_credIdIndex(credId), JSON.stringify({ userId }));
    return { entry: existing, reenrolled: true };
  }

  const entry = {
    credId,
    publicKey,
    counter: Number.isFinite(cred.counter) ? cred.counter : 0,
    transports: Array.isArray(cred.transports) ? cred.transports : [],
    prfSupported: !!cred.prfSupported,
    aaguid: cred.aaguid || '',
    label: cleanLabel,
    created_at: now,
    last_used_at: null,
    revoked_at: null,
  };
  arr.push(entry);
  await _writeArray(redisClient, userId, arr);
  await redisClient.set(_credIdIndex(credId), JSON.stringify({ userId }));
  return { entry, reenrolled: false };
}

async function getCredentials(redisClient, userId) {
  return _readArray(redisClient, userId);
}

async function getActiveCredentials(redisClient, userId) {
  return (await _readArray(redisClient, userId)).filter(e => !e.revoked_at);
}

// Count of usable passkeys — consumed by the lockout guard (account-recovery).
async function countActiveCredentials(redisClient, userId) {
  return (await getActiveCredentials(redisClient, userId)).length;
}

// Resolve a credential id (from an assertion) to its account + stored entry.
// Returns { userId, entry } or null. Revoked credentials do not resolve (their
// index is removed on revoke), so they cannot be used to authenticate.
async function lookupByCredId(redisClient, credId) {
  if (!_isB64Url(credId)) return null;
  const raw = await redisClient.get(_credIdIndex(credId));
  if (!raw) return null;
  let userId;
  try { userId = JSON.parse(raw).userId; } catch { return null; }
  if (!userId) return null;
  const entry = (await _readArray(redisClient, userId)).find(e => e.credId === credId);
  if (!entry || entry.revoked_at) return null;
  return { userId, entry };
}

// Persist a new signature counter after a successful assertion. No-op if the
// credential is gone. Counter regression handling (clone detection) is the
// caller's decision; this only stores.
async function updateCounter(redisClient, userId, credId, newCounter) {
  const arr = await _readArray(redisClient, userId);
  const entry = arr.find(e => e.credId === credId);
  if (!entry) return false;
  if (Number.isFinite(newCounter)) entry.counter = newCounter;
  entry.last_used_at = new Date().toISOString();
  await _writeArray(redisClient, userId, arr);
  return true;
}

// Revoke a credential: keep the history entry but drop the cred-id index so it
// can no longer authenticate. Returns { revoked, reason?, remaining_active }.
async function revokeCredential(redisClient, userId, credId) {
  if (!_isB64Url(credId)) throw new Error('credId (base64url) required');
  const arr = await _readArray(redisClient, userId);
  const entry = arr.find(e => e.credId === credId);
  if (!entry) return { revoked: false, reason: 'not_found' };
  if (entry.revoked_at) return { revoked: false, reason: 'already_revoked', remaining_active: arr.filter(e => !e.revoked_at).length };
  entry.revoked_at = new Date().toISOString();
  await _writeArray(redisClient, userId, arr);
  await redisClient.del(_credIdIndex(credId));
  return { revoked: true, remaining_active: arr.filter(e => !e.revoked_at).length };
}

module.exports = {
  HANDLE_BYTES,
  getOrCreateUserHandle,
  getUserHandle,
  lookupByHandle,
  storeCredential,
  getCredentials,
  getActiveCredentials,
  countActiveCredentials,
  lookupByCredId,
  updateCounter,
  revokeCredential,
};
