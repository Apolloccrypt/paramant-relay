'use strict';
// An outage is not "signed out" (sweep-chaos 5). With the relay answering 503
// the account routes used to return 200 with an empty account (no plan, no
// name), which the pages drew as a stranger; session/verify threw a 500 when
// redis was gone. Both say 503 now, and 401 stays for a missing session only.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { boot, killAll, freePort } = require('./_admin-server');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
let rc = null; let srv = null; let down = null;
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
  srv = await boot({ redisUrl: url, relay: { base: `http://127.0.0.1:${port}` } });
});
after(async () => { await killAll(); if (down) down.close(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

test('relay down: /user/me and /user/account answer 503, not an empty account', async () => {
  if (!srv) return;
  const token = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({ user_id: 'pgp_outage', email: 'o@example.test', created_at: Date.now(), last_seen: Date.now(), ua: UA, primary_api_key: 'pgp_outage' }), { EX: 600 });
  const h = { Cookie: `paramant_user_session=${token}`, 'User-Agent': UA };
  const me = await fetch(`${srv.base}/api/user/me`, { headers: h });
  assert.strictEqual(me.status, 503);
  const acct = await fetch(`${srv.base}/api/user/account`, { headers: h });
  assert.strictEqual(acct.status, 503);
  const none = await fetch(`${srv.base}/api/user/me`, { headers: { 'User-Agent': UA } });
  assert.strictEqual(none.status, 401, 'no session is still 401');
});
