'use strict';
// A mail outage must not eat signups (sweep-chaos, mail-fail). The pending
// signup used to be deleted when the verification mail failed: the form said
// "check your inbox", nothing came, and the retry hit the rate limit. Now it
// is kept and the mail is queued for another try.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, solvePow } = require('./_admin-server');

let rc = null; let srv = null;
const RUN = crypto.randomBytes(4).toString('hex');
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
  const relay = await stubRelay(defaultRelayState([]));
  // No mail carrier configured: every send throws, which is the outage.
  srv = await boot({ redisUrl: url, relay, env: { MAIL_PROVIDER: 'resend', RESEND_API_KEY: '' } });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

test('signup during a mail outage keeps the pending signup and queues the mail', async () => {
  if (!srv) return;
  const email = `outage_${RUN}@posteo.de`;
  const from = '198.51.100.77';
  const ch = await srv.get('/api/captcha/challenge', { headers: { 'X-Real-IP': from } });
  const nonce = solvePow(ch.json.challenge_id, ch.json.salt, ch.json.difficulty);
  const r = await srv.post('/api/user/signup', { headers: { 'X-Real-IP': from }, body: { email, dpa_accepted: true, challenge_id: ch.json.challenge_id, nonce } });
  assert.strictEqual(r.status, 200, r.text);
  await new Promise((res) => setTimeout(res, 800));
  let pending = 0;
  for await (const k of rc.scanIterator({ MATCH: 'paramant:signup:pending:*', COUNT: 1000 })) {
    for (const key of [].concat(k)) { const v = await rc.get(key); if (v && v.includes(email)) pending++; }
  }
  assert.strictEqual(pending, 1, 'the pending signup survived the failed mail');
  const due = await rc.zRange('paramant:mailretry:due', 0, -1);
  assert.ok(due.length >= 1, 'and the mail is queued for another try');
});
