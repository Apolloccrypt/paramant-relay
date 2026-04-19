// test/test-verify-totp.js
// Usage: REDIS_URL=redis://... node test/test-verify-totp.js

'use strict';
const crypto = require('crypto');
const assert = require('assert');
const { createClient } = require('redis');

const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { output += ALPHA[(value >>> (bits - 5)) & 0x1f]; bits -= 5; }
  }
  if (bits > 0) output += ALPHA[(value << (5 - bits)) & 0x1f];
  return output;
}

function base32Decode(s) {
  let bits = 0, value = 0, output = [];
  s = s.toUpperCase().replace(/=+$/, '');
  for (const c of s) {
    const idx = ALPHA.indexOf(c);
    if (idx === -1) throw new Error(`Invalid Base32 character: '${c}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xFF); bits -= 8; }
  }
  return Buffer.from(output);
}

function totpCode(secret, counter, algorithm = 'sha1') {
  const key = base32Decode(secret);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const mac = crypto.createHmac(algorithm, key).update(buf).digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
  return code.toString().padStart(6, '0');
}

let redisClient;

async function verifyTotpGeneric(code, secret, opts = {}) {
  const algorithm = opts.algorithm || 'sha1';
  const window    = opts.window ?? 1;
  const replayKey = opts.replayKey;

  if (!secret)    return { valid: false, reason: 'no_secret' };
  if (!replayKey) return { valid: false, reason: 'no_replay_key' };
  if (!redisClient || !redisClient.isReady) return { valid: false, reason: 'redis_unavailable' };

  const codeStr = String(code || '');
  if (!/^\d{6}$/.test(codeStr)) return { valid: false, reason: 'invalid_format' };

  const tokenBuf = Buffer.from(codeStr, 'utf8');
  const counter  = Math.floor(Date.now() / 1000 / 30);

  let matchedCounter = null;
  for (let i = -window; i <= window; i++) {
    const c = counter + i;
    const expected = totpCode(secret, c, algorithm);
    const expectedBuf = Buffer.from(expected, 'utf8');
    const eq = tokenBuf.length === expectedBuf.length &&
               crypto.timingSafeEqual(tokenBuf, expectedBuf);
    if (eq) matchedCounter = c;
  }

  if (matchedCounter === null) return { valid: false, reason: 'invalid_code' };

  const replayFullKey = `${replayKey}:${codeStr}:${matchedCounter}`;
  const ttlSeconds    = (window + 2) * 30;
  const setResult = await redisClient.set(replayFullKey, '1', { NX: true, EX: ttlSeconds });

  if (setResult !== 'OK') return { valid: false, reason: 'replay' };
  return { valid: true, counter: matchedCounter };
}

async function test1_valid_sha1_code() {
  const secret = base32Encode(crypto.randomBytes(20));
  const counter = Math.floor(Date.now() / 1000 / 30);
  const code = totpCode(secret, counter, 'sha1');
  const result = await verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 'test:t1' });
  assert.strictEqual(result.valid, true, 'valid SHA-1 code should pass');
  console.log('✓ test1: valid SHA-1 code accepted');
}

async function test2_valid_sha256_code() {
  const secret = base32Encode(crypto.randomBytes(20));
  const counter = Math.floor(Date.now() / 1000 / 30);
  const code = totpCode(secret, counter, 'sha256');
  const result = await verifyTotpGeneric(code, secret, { algorithm: 'sha256', replayKey: 'test:t2' });
  assert.strictEqual(result.valid, true, 'valid SHA-256 code should pass');
  console.log('✓ test2: valid SHA-256 code accepted');
}

async function test3_invalid_code() {
  const secret = base32Encode(crypto.randomBytes(20));
  const result = await verifyTotpGeneric('000000', secret, { algorithm: 'sha1', replayKey: 'test:t3' });
  assert.strictEqual(result.valid, false);
  assert.strictEqual(result.reason, 'invalid_code');
  console.log('✓ test3: invalid code rejected');
}

async function test4_replay_rejected() {
  const secret = base32Encode(crypto.randomBytes(20));
  const counter = Math.floor(Date.now() / 1000 / 30);
  const code = totpCode(secret, counter, 'sha1');
  const first = await verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 'test:t4' });
  assert.strictEqual(first.valid, true, 'first use should pass');
  const second = await verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 'test:t4' });
  assert.strictEqual(second.valid, false);
  assert.strictEqual(second.reason, 'replay');
  console.log('✓ test4: replay rejected');
}

async function test5_namespace_isolation() {
  const secret = base32Encode(crypto.randomBytes(20));
  const counter = Math.floor(Date.now() / 1000 / 30);
  const code = totpCode(secret, counter, 'sha1');
  const r1 = await verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 'test:t5:admin' });
  const r2 = await verifyTotpGeneric(code, secret, { algorithm: 'sha1', replayKey: 'test:t5:user:42' });
  assert.strictEqual(r1.valid, true);
  assert.strictEqual(r2.valid, true);
  console.log('✓ test5: namespaces isolated (admin vs user replay separate)');
}

async function test6_invalid_format() {
  const secret = base32Encode(crypto.randomBytes(20));
  for (const bad of ['', '12345', '1234567', 'abcdef', '12 345', null]) {
    const r = await verifyTotpGeneric(bad, secret, { algorithm: 'sha1', replayKey: 'test:t6' });
    assert.strictEqual(r.valid, false, `"${bad}" should be rejected`);
    assert.strictEqual(r.reason, 'invalid_format', `"${bad}" reason should be invalid_format`);
  }
  console.log('✓ test6: malformed inputs rejected with invalid_format');
}

async function test7_window_tolerance() {
  const secret  = base32Encode(crypto.randomBytes(20));
  const counter = Math.floor(Date.now() / 1000 / 30);
  const rMinus = await verifyTotpGeneric(totpCode(secret, counter - 1, 'sha1'), secret,
    { algorithm: 'sha1', window: 1, replayKey: 'test:t7:a' });
  assert.strictEqual(rMinus.valid, true, '-1 window code should accept');
  const rPlus = await verifyTotpGeneric(totpCode(secret, counter + 1, 'sha1'), secret,
    { algorithm: 'sha1', window: 1, replayKey: 'test:t7:b' });
  assert.strictEqual(rPlus.valid, true, '+1 window code should accept');
  console.log('✓ test7: ±1 window tolerance works');
}

async function test8_algorithm_mismatch() {
  const secret = base32Encode(crypto.randomBytes(20));
  const sha1Code = totpCode(secret, Math.floor(Date.now() / 1000 / 30), 'sha1');
  const result = await verifyTotpGeneric(sha1Code, secret, { algorithm: 'sha256', replayKey: 'test:t8' });
  assert.strictEqual(result.valid, false);
  console.log('✓ test8: algorithm mismatch rejects code');
}

(async () => {
  const url = process.env.REDIS_URL || 'redis://localhost:6379';
  redisClient = createClient({ url });
  redisClient.on('error', (e) => console.error('redis:', e.message));
  await redisClient.connect();

  for await (const key of redisClient.scanIterator({ MATCH: 'test:*' })) {
    await redisClient.del(key);
  }

  try {
    await test1_valid_sha1_code();
    await test2_valid_sha256_code();
    await test3_invalid_code();
    await test4_replay_rejected();
    await test5_namespace_isolation();
    await test6_invalid_format();
    await test7_window_tolerance();
    await test8_algorithm_mismatch();
    console.log('\nAll 8 tests passed.');
  } catch (err) {
    console.error('\nTest failed:', err);
    process.exit(1);
  } finally {
    for await (const key of redisClient.scanIterator({ MATCH: 'test:*' })) {
      await redisClient.del(key);
    }
    await redisClient.quit();
  }
})();
