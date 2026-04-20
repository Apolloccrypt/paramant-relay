'use strict';
const crypto = require('crypto');
const { redis } = require('./redis');

const DIFFICULTY = 18;          // 2^18 ≈ 262k hashes, ~1-2s on modern CPU
const TTL = 300;                // 5 min to solve
const PREFIX = 'paramant:pow:';

function hasLeadingZeroBits(hexHash, bits) {
  const fullChars = Math.floor(bits / 4);
  const rem = bits % 4;
  for (let i = 0; i < fullChars; i++) {
    if (hexHash[i] !== '0') return false;
  }
  if (rem === 0) return true;
  const nibble = parseInt(hexHash[fullChars], 16);
  return (nibble & (0xF << (4 - rem))) === 0;
}

async function issueChallenge() {
  const id   = crypto.randomBytes(16).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');
  await redis().set(PREFIX + id, JSON.stringify({ salt, difficulty: DIFFICULTY, ts: Date.now() }), { EX: TTL });
  return { challenge_id: id, salt, difficulty: DIFFICULTY, ttl: TTL };
}

async function verifyChallenge(challengeId, nonce) {
  if (!challengeId || typeof challengeId !== 'string' || nonce === undefined || nonce === null) {
    return { valid: false, reason: 'missing_params' };
  }
  const raw = await redis().get(PREFIX + challengeId);
  if (!raw) return { valid: false, reason: 'expired_or_not_found' };
  const { salt, difficulty } = JSON.parse(raw);
  const hash = crypto.createHash('sha256').update(challengeId + salt + String(nonce)).digest('hex');
  if (!hasLeadingZeroBits(hash, difficulty)) return { valid: false, reason: 'invalid_proof' };
  await redis().del(PREFIX + challengeId); // one-shot
  return { valid: true };
}

module.exports = { issueChallenge, verifyChallenge };
