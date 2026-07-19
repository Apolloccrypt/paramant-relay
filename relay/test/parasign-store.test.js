'use strict';
// ParaSign durable side-store (lib/parasign-store.js). Proves the encryption
// invariants and both backends. The redis-backed checks (durability + TTL) run
// only when a throwaway redis is reachable (REDIS_URL, default 127.0.0.1:6399);
// otherwise they skip so the default suite stays green without a container.
//   docker run -d --rm -p 6399:6379 --name parasign-test-redis redis:alpine
//   REDIS_URL=redis://127.0.0.1:6399 node --test test/parasign-store.test.js

const assert = require('assert');
const crypto = require('crypto');
const { createParaSignStore, normalizeKey, seal, unseal } = require('../lib/parasign-store');

const KEY = crypto.randomBytes(32);
let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function tryRedis() {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6399';
  let createClient;
  try { ({ createClient } = require('redis')); } catch { return null; }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); return rc; } catch { try { await rc.disconnect(); } catch {} return null; }
}

async function main() {
  // 1. seal/unseal round-trip + AAD binding
  {
    const pt = Buffer.from('%PDF-1.4 binary\x00\x01\x02payload');
    const sealed = seal(pt, KEY, 'parasign:blob:abc');
    assert.ok(typeof sealed === 'string' && sealed.length > 0, 'sealed is a base64 string');
    assert.ok(unseal(sealed, KEY, 'parasign:blob:abc').equals(pt), 'round-trips under the same AAD');
    assert.throws(() => unseal(sealed, KEY, 'parasign:blob:OTHER'), 'lift to another AAD fails (GCM)');
    assert.throws(() => unseal(sealed, crypto.randomBytes(32), 'parasign:blob:abc'), 'wrong key fails');
    ok('seal/unseal AES-256-GCM + AAD binding');
  }

  // 2. normalizeKey
  {
    assert.ok(normalizeKey(Buffer.alloc(32)).length === 32, 'buffer 32 accepted');
    assert.strictEqual(normalizeKey(Buffer.alloc(16)), null, 'wrong-length buffer rejected');
    assert.ok(normalizeKey(Buffer.alloc(32).toString('base64')).length === 32, 'base64 accepted');
    assert.strictEqual(normalizeKey(''), null, 'empty rejected');
    assert.strictEqual(normalizeKey(null), null, 'null rejected');
    ok('normalizeKey');
  }

  // 3. memory backend (no redis/key): put/get/del blob + meta
  {
    const s = createParaSignStore({});
    assert.strictEqual(s.backend, 'memory', 'memory backend without redis/key');
    const pdf = Buffer.from('%PDF-1.7 hello');
    await s.putBlob('id1', pdf, 60_000);
    assert.ok((await s.getBlob('id1')).equals(pdf), 'blob round-trips');
    await s.putMeta('id1', { webhook_url: 'https://x', a: 1 }, 60_000);
    assert.deepStrictEqual(await s.getMeta('id1'), { webhook_url: 'https://x', a: 1 }, 'meta round-trips');
    await s.putStamped('id1', Buffer.from('%PDF-stamped'), 60_000);
    assert.ok((await s.getStamped('id1')).toString() === '%PDF-stamped', 'stamped round-trips');
    await s.delBlob('id1');
    assert.strictEqual(await s.getBlob('id1'), null, 'delBlob clears blob');
    assert.strictEqual(await s.getStamped('id1'), null, 'delBlob also clears stamped');
    ok('memory backend put/get/del');
  }

  // 4. redis backend: DURABILITY (survives a fresh store instance) + TTL
  const rc = await tryRedis();
  if (!rc) {
    console.log('  skip - redis backend checks (no reachable redis at REDIS_URL/127.0.0.1:6399)');
  } else {
    try {
      const id = 'durable_' + crypto.randomBytes(6).toString('hex');
      const s1 = createParaSignStore({ redis: rc, encKey: KEY });
      assert.strictEqual(s1.backend, 'redis', 'redis backend when redis+key present');
      const pdf = crypto.randomBytes(2048);
      await s1.putBlob(id, pdf, 60_000);
      await s1.putMeta(id, { webhook_url: 'https://hook.example', accountId: 'acct_1' }, 60_000);

      // A SEPARATE store instance (simulating a relay restart) reads it back.
      const s2 = createParaSignStore({ redis: rc, encKey: KEY });
      assert.ok((await s2.getBlob(id)).equals(pdf), 'blob survives a fresh store instance (restart-durable)');
      assert.strictEqual((await s2.getMeta(id)).accountId, 'acct_1', 'meta survives restart');

      // At-rest value is ciphertext, not the plaintext PDF.
      const raw = await rc.get(`psign:blob:${id}`);
      assert.ok(raw && !Buffer.from(raw, 'base64').includes(pdf.slice(0, 16)), 'at-rest value is encrypted, not plaintext');

      // A store with the WRONG key cannot read it (fails closed -> null).
      const sWrong = createParaSignStore({ redis: rc, encKey: crypto.randomBytes(32) });
      assert.strictEqual(await sWrong.getBlob(id), null, 'wrong key cannot decrypt (returns null)');

      // TTL: a short PX expires the key.
      const tid = 'ttl_' + crypto.randomBytes(6).toString('hex');
      await s1.putBlob(tid, Buffer.from('%PDF-x'), 300);
      assert.ok(await s1.getBlob(tid), 'present before TTL');
      await sleep(600);
      assert.strictEqual(await s1.getBlob(tid), null, 'gone after TTL (PX honoured)');

      await rc.del(`psign:blob:${id}`); await rc.del(`psign:meta:${id}`);
      ok('redis backend: encrypted-at-rest, restart-durable, wrong-key-fails, TTL honoured');
    } finally { try { await rc.disconnect(); } catch {} }
  }
}

main()
  .then(() => console.log(`\nparasign-store: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
