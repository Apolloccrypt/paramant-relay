'use strict';
const crypto = require('crypto');

const ALGO      = 'aes-256-gcm';
const KEY_LEN   = 32;
const NONCE_LEN = 12;

function getMasterKey() {
  const raw = process.env.PARAMANT_TOTP_MASTER_KEY;
  if (!raw) throw new Error('PARAMANT_TOTP_MASTER_KEY not set');
  const key = Buffer.from(raw, 'base64');
  if (key.length !== KEY_LEN) throw new Error(`PARAMANT_TOTP_MASTER_KEY must be ${KEY_LEN} bytes, got ${key.length}`);
  return key;
}

// `aad` (optional) binds the ciphertext to a context (e.g. the userId), so a
// Redis-write attacker can't lift one user's encrypted blob into another user's
// key and have it decrypt — the GCM tag covers the AAD. Callers pass a stable
// per-record string. Backward compatible: blobs written before AAD existed have
// none, so decryptSecret retries without AAD when an AAD-bound decrypt fails (the
// next write upgrades them).
function encryptSecret(plaintext, aad) {
  const key    = getMasterKey();
  const nonce  = crypto.randomBytes(NONCE_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, nonce);
  if (aad) cipher.setAAD(Buffer.from(String(aad), 'utf8'));
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  key.fill(0);
  return `${nonce.toString('base64')}:${enc.toString('base64')}:${tag.toString('base64')}`;
}

function _decrypt(parts, aad) {
  const nonce = Buffer.from(parts[0], 'base64');
  const ct    = Buffer.from(parts[1], 'base64');
  const tag   = Buffer.from(parts[2], 'base64');
  const key   = getMasterKey();
  const dec   = crypto.createDecipheriv(ALGO, key, nonce);
  if (aad) dec.setAAD(Buffer.from(String(aad), 'utf8'));
  dec.setAuthTag(tag);
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  key.fill(0);
  return plain.toString('utf8');
}

function decryptSecret(serialized, aad) {
  const parts = (serialized || '').split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted format');
  try {
    return _decrypt(parts, aad);
  } catch (e) {
    // Legacy blob written without AAD: retry unbound (only when we tried AAD).
    if (aad) return _decrypt(parts, null);
    throw e;
  }
}

module.exports = { encryptSecret, decryptSecret };
