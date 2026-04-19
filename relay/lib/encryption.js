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

function encryptSecret(plaintext) {
  const key    = getMasterKey();
  const nonce  = crypto.randomBytes(NONCE_LEN);
  const cipher = crypto.createCipheriv(ALGO, key, nonce);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  key.fill(0);
  return `${nonce.toString('base64')}:${enc.toString('base64')}:${tag.toString('base64')}`;
}

function decryptSecret(serialized) {
  const parts = (serialized || '').split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted format');
  const nonce = Buffer.from(parts[0], 'base64');
  const ct    = Buffer.from(parts[1], 'base64');
  const tag   = Buffer.from(parts[2], 'base64');
  const key   = getMasterKey();
  const dec   = crypto.createDecipheriv(ALGO, key, nonce);
  dec.setAuthTag(tag);
  const plain = Buffer.concat([dec.update(ct), dec.final()]);
  key.fill(0);
  return plain.toString('utf8');
}

module.exports = { encryptSecret, decryptSecret };
