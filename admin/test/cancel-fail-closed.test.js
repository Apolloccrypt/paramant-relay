'use strict';
// Review 573 L3: POST /user/billing/cancel asks relay-main whether anything
// collects. When relay-main was down, the route carried on, wrote a cancel
// date and mailed "uw plan is opgezegd". It fails closed now: 503, no date,
// no mail, an honest message.
// Run: node --test admin/test/cancel-fail-closed.test.js
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { boot, killAll, freePort } = require('./_admin-server');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
let rc = null; let down = null; let srvDown = null; let srvGone = null;
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
  const port = await freePort();
  down = http.createServer((req, res) => { res.writeHead(503, { 'Content-Type': 'application/json' }); res.end('{"error":"down"}'); });
  await new Promise((r) => down.listen(port, '127.0.0.1', r));
  srvDown = await boot({ redisUrl: url, relay: { base: `http://127.0.0.1:${port}` } });
  // Nothing listens here: the request itself fails.
  srvGone = await boot({ redisUrl: url, relay: { base: `http://127.0.0.1:${await freePort()}` } });
});
after(async () => { await killAll(); if (down) down.close(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

async function cancelWith(srv) {
  const user = 'pgp_' + crypto.randomBytes(16).toString('hex');
  const token = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({ user_id: user, email: 'demo@example.com', created_at: Date.now(), last_seen: Date.now(), ua: UA, primary_api_key: user }), { EX: 600 });
  const r = await fetch(`${srv.base}/api/user/billing/cancel`, {
    method: 'POST',
    headers: { Cookie: `paramant_user_session=${token}`, 'User-Agent': UA, Origin: srv.base, 'Content-Type': 'application/json' },
    body: '{}',
  });
  const body = await r.json().catch(() => null);
  const marker = await rc.get(`paramant:user:plan_cancel_at:${user}`);
  await rc.del([`paramant:user:session:${token}`, `paramant:user:plan_cancel_at:${user}`]);
  return { status: r.status, body, marker };
}

for (const [name, get] of [['relay-main answers 503', () => srvDown], ['relay-main unreachable', () => srvGone]]) {
  test(`${name}: cancel fails closed, no date written, honest message`, async () => {
    if (!rc) return;
    const out = await cancelWith(get());
    assert.strictEqual(out.status, 503, JSON.stringify(out.body));
    assert.strictEqual(out.body && out.body.error, 'cancel_check_unavailable');
    assert.match(out.body.message, /geen mail verstuurd/);
    assert.strictEqual(out.marker, null, 'no cancel date may be written');
  });
}
