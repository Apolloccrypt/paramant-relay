'use strict';
// sweep-pdf B4: a co-sign document over the 5 MB capsule limit answered
// payload_too_large (a code the page does not know) and left the request with
// its parties and no document. And a relay 429 on the signer's document read
// came back as 404 "document not available".
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
const EMAIL = 'sender@example.test';
let rc = null; let srv = null; let relay = null;
before(async () => {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
  const { createClient } = require('redis');
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); } catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": ${e.message}`);
  }
  rc = c;
  const state = defaultRelayState([{ key: KEY, email: EMAIL, active: true, plan: 'pro' }]);
  state.route = (method, p) => {
    if (method === 'POST' && /\/cancel$/.test(p)) return { status: 200, body: { ok: true } };
    if (method === 'GET' && /^\/v2\/envelopes\/[A-Za-z0-9_-]+$/.test(p)) return { status: 429, headers: { 'Retry-After': '42' }, body: { error: 'Too many requests' } };
    return null;
  };
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay, env: { MAX_BLOB: '1048576' } });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

async function session() {
  const t = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${t}`, JSON.stringify({ user_id: KEY, email: EMAIL, created_at: Date.now(), last_seen: Date.now(), ua: UA, primary_api_key: KEY, legacy_revealable: true }), { EX: 600 });
  return { Cookie: `paramant_user_session=${t}`, 'User-Agent': UA, Origin: 'http://127.0.0.1' };
}

test('a document over the limit is document_too_large with the limit, and the empty request is withdrawn', async () => {
  if (!srv) return;
  const id = 'env' + crypto.randomBytes(12).toString('hex');
  const r = await fetch(`${srv.base}/api/user/envelopes/${id}/document`, {
    method: 'POST', headers: { ...(await session()), 'Content-Type': 'application/octet-stream', 'X-Capsule-Sha256': 'a'.repeat(64) },
    body: Buffer.alloc(1048576 + 50000, 1),
  });
  assert.strictEqual(r.status, 413);
  const j = await r.json();
  assert.strictEqual(j.error, 'document_too_large');
  assert.strictEqual(j.max_bytes, 1048576);
  assert.ok(relay.state.calls.some((c) => c.method === 'POST' && c.path === `/v2/envelopes/${id}/cancel`), 'the empty envelope was withdrawn');
});

test('a relay 429 on the document read is a 429 with Retry-After, not a 404', async () => {
  if (!srv) return;
  const id = 'env' + crypto.randomBytes(12).toString('hex');
  const r = await fetch(`${srv.base}/api/user/envelopes/${id}/document?p=0&t=${'A'.repeat(43)}`, { headers: await session() });
  assert.strictEqual(r.status, 429);
  assert.strictEqual(r.headers.get('retry-after'), '42');
});
