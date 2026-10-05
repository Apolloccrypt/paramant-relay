'use strict';
const crypto = require('crypto');
const argon2 = require('argon2');
const { encryptSecret, decryptSecret } = require('./encryption');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
// No-ambiguous-char alphabet for backup codes (omits 0,1,I,O)
const BACKUP_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateTotpSecret() {
  // 20 random bytes → 32-char base32 (160 bits entropy)
  const bytes = crypto.randomBytes(20);
  let bits = 0, value = 0, output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return output;
}

function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const group = () => {
      const bytes = crypto.randomBytes(4);
      let s = '';
      for (let j = 0; j < 4; j++) s += BACKUP_ALPHABET[bytes[j] % BACKUP_ALPHABET.length];
      return s;
    };
    codes.push(`${group()}-${group()}-${group()}`);
  }
  return codes;
}

async function storeBackupCodes(redisClient, userId, codes) {
  const hashes = await Promise.all(codes.map(c =>
    argon2.hash(c, { type: argon2.argon2id, memoryCost: 65536, timeCost: 3 })
  ));
  const key = `paramant:user:backup_codes:${userId}`;
  if (hashes.length > 0) await redisClient.sAdd(key, hashes);
}

// Mint a fresh set of backup codes for a user: drop any existing set (codes are
// single-use, so a replace is correct both on activation and on explicit
// regenerate), generate a new batch, store the hashes, and return the plaintext
// codes to the caller exactly once. This is the ONLY place plaintext codes are
// produced, which is why activation can hand them straight to the user with no
// separate lookup — and why a reloaded or re-issued setup page can never strand
// the user on an empty set.
async function regenerateBackupCodes(redisClient, userId, count = 10) {
  await redisClient.del(`paramant:user:backup_codes:${userId}`);
  const codes = generateBackupCodes(count);
  await storeBackupCodes(redisClient, userId, codes);
  return codes;
}

async function consumeBackupCode(redisClient, userId, providedCode) {
  const key = `paramant:user:backup_codes:${userId}`;
  const hashes = await redisClient.sMembers(key);
  for (const hash of hashes) {
    if (await argon2.verify(hash, providedCode)) {
      await redisClient.sRem(key, hash);
      return { valid: true };
    }
  }
  return { valid: false };
}

// AAD binds the TOTP secret blob to this user, so a Redis-write attacker can't
// transplant one user's secret into another's key (decrypt is backward-compatible
// with pre-AAD blobs; see encryption.js).
function _totpAad(userId) { return `totp:${userId}`; }

async function storeUserTotpSecret(redisClient, userId, base32Secret) {
  const encrypted = encryptSecret(base32Secret, _totpAad(userId));
  await redisClient.set(`paramant:user:totp:${userId}`, encrypted);
}

async function getUserTotpSecret(redisClient, userId) {
  const encrypted = await redisClient.get(`paramant:user:totp:${userId}`);
  if (!encrypted) return null;
  return decryptSecret(encrypted, _totpAad(userId));
}

async function deleteUserTotp(redisClient, userId) {
  await redisClient.del([
    `paramant:user:totp:${userId}`,
    `paramant:user:backup_codes:${userId}`,
  ]);
}

module.exports = {
  generateTotpSecret,
  generateBackupCodes,
  storeBackupCodes,
  regenerateBackupCodes,
  consumeBackupCode,
  storeUserTotpSecret,
  getUserTotpSecret,
  deleteUserTotp,
};
