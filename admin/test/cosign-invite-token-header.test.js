'use strict';
// Acceptatie r5, B. The co-sign page put the invite token in ?t= of
// /api/user/envelopes/:id/document and /receipt, and this proxy passed it on
// in ?t= to the relay: two access logs held it. The page now sends
// X-Parasign-Invite-Token; the proxy reads that header and hands it to the
// relay as a header too. ?t= is still read for a page loaded before the change.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
const EMAIL = 'signer@example.test';
const TOKEN = 'T'.repeat(43);
const EMAIL_HASH = crypto.createHash('sha3-256').update('paramant/party-email/v1\x00', 'utf8').update(EMAIL, 'utf8').digest('hex');
let rc = null; let srv = null; let relay = null;
const seen = [];

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
  state.route = (method, p, headers, _body, u) => {
    if (!/^\/v2\/envelopes\//.test(p)) return null;
    seen.push({ method, path: p, search: u.search, token: headers['x-parasign-invite-token'] || '' });
    const tok = headers['x-parasign-invite-token'] || u.searchParams.get('t') || '';
    if (tok !== TOKEN) return { status: 404, body: { error: 'not found' } };
    if (method === 'GET' && /^\/v2\/envelopes\/[A-Za-z0-9_-]+$/.test(p)) return { status: 200, body: { envelope: { id: 'x', party: { email_hash: EMAIL_HASH } } } };
    if (method === 'GET' && /\/document$/.test(p)) return { status: 200, body: { capsule: 'stub' } };
    if (method === 'GET' && /\/participant-receipt$/.test(p)) return { status: 200, body: { psign: 'stub' } };
    return null;
  };
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

async function session() {
  const t = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${t}`, JSON.stringify({ user_id: KEY, email: EMAIL, created_at: Date.now(), last_seen: Date.now(), ua: UA, primary_api_key: KEY, legacy_revealable: true }), { EX: 600 });
  return { Cookie: `paramant_user_session=${t}`, 'User-Agent': UA, Origin: 'http://127.0.0.1' };
}

for (const route of ['document', 'receipt']) {
  test(`${route}: the invite token in a header is enough, and goes on to the relay as a header`, async () => {
    if (!srv) return;
    const id = 'env' + crypto.randomBytes(12).toString('hex');
    seen.length = 0;
    const r = await fetch(`${srv.base}/api/user/envelopes/${id}/${route}?p=0`, { headers: { ...(await session()), 'X-Parasign-Invite-Token': TOKEN } });
    assert.strictEqual(r.status, 200, await r.text());
    assert.ok(seen.length >= (route === 'document' ? 2 : 1), 'the proxy asked the relay');
    for (const c of seen) {
      assert.doesNotMatch(c.search, /[?&]t=/, `${c.path}${c.search}: the token is not in the relay URL`);
      assert.strictEqual(c.token, TOKEN, `${c.path}: the token went as a header`);
    }
  });

  test(`${route}: a page loaded before the change (?t=) still works`, async () => {
    if (!srv) return;
    const id = 'env' + crypto.randomBytes(12).toString('hex');
    seen.length = 0;
    const r = await fetch(`${srv.base}/api/user/envelopes/${id}/${route}?p=0&t=${TOKEN}`, { headers: await session() });
    assert.strictEqual(r.status, 200, await r.text());
    for (const c of seen) assert.doesNotMatch(c.search, /[?&]t=/, `${c.path}${c.search}: not passed on in a query`);
  });
}
