'use strict';
// Account-changing actions need a fresh second factor, not just the cookie.
// sweep-acct finding 2: with a stolen session cookie alone, back-up codes
// could be regenerated (a way back in after "sign out everywhere") and the
// account deleted. Finding 3: 2FA could be reset with the mailbox alone.
// Finding 5 / ACCT-37: a self-service delete left user:meta (the email) and
// the open envelopes behind.
// Needs a redis (REDIS_URL), like the rest of this directory.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const DEFAULT_REDIS = 'redis://127.0.0.1:6379';
const SUFFIX = crypto.randomBytes(4).toString('hex');
const KEY = `pgp_f2a_${SUFFIX}`;
const EMAIL = `f2a-${SUFFIX}@example.test`;
const ORIGIN = 'http://127.0.0.1';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

let rc = null; let srv = null; let relay = null;

before(async () => {
  const url = process.env.REDIS_URL || DEFAULT_REDIS;
  const { createClient } = require('redis');
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  rc = c;
  const state = defaultRelayState([{ key: KEY, email: EMAIL, active: true, plan: 'pro', created: '2026-01-02T03:04:05.000Z' }]);
  state.consumeBackup = (b) => ({ valid: b.code === 'GOODCODE1' });
  state.route = (method, p) => {
    if (p === '/v2/user/regenerate-backup') return { status: 200, body: { backup_codes: ['NEW1', 'NEW2'] } };
    if (method === 'DELETE' && p === '/v2/user/webauthn/credential') return { status: 200, body: { revoked: true, remaining_active: 0 } };
    if (p === '/v2/admin/envelopes/void-account') return { status: 200, body: { ok: true, voided: 2 } };
    if (p.startsWith('/v2/admin/keys/') || p === '/v2/user/delete-totp' || p === '/v2/reload-users') return { status: 200, body: { ok: true } };
    return null;
  };
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

async function plant(extra = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:user:session:${token}`, JSON.stringify({
    user_id: KEY, email: EMAIL, created_at: Date.now(), last_seen: Date.now(), ip: '203.0.113.9', ua: UA,
    primary_api_key: KEY, legacy_revealable: true, ...extra,
  }), { EX: 3600 });
  return token;
}
const call = (token, method, path, body) => fetch(`${srv.base}${path}`, {
  method, headers: { Cookie: `paramant_user_session=${token}`, 'User-Agent': UA, Origin: ORIGIN, 'Content-Type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
});

test('ACCT-25/26: /user/me has created_at from the relay record, the session list a readable device', async () => {
  if (!srv) return;
  const t = await plant();
  const me = await (await call(t, 'GET', '/api/user/me')).json();
  assert.strictEqual(me.created_at, '2026-01-02T03:04:05.000Z');
  const acct = await (await call(t, 'GET', '/api/user/account')).json();
  assert.ok(acct.sessions.some((x) => x.user_agent_short === 'Chrome on Windows'), JSON.stringify(acct.sessions));
});

test('back-up codes: no factor 400, wrong factor 403, TOTP 200', async () => {
  if (!srv) return;
  const t = await plant();
  assert.strictEqual((await call(t, 'POST', '/api/user/account/backup-codes/regenerate', {})).status, 400);
  assert.strictEqual((await call(t, 'POST', '/api/user/account/backup-codes/regenerate', { totp: '000000' })).status, 403);
  const ok = await call(t, 'POST', '/api/user/account/backup-codes/regenerate', { totp: '123456' });
  assert.strictEqual(ok.status, 200);
  assert.deepStrictEqual((await ok.json()).backup_codes, ['NEW1', 'NEW2']);
});

test('delete account: needs a factor; then voids open envelopes and clears user:meta', async () => {
  if (!srv) return;
  await rc.set(`paramant:user:meta:${KEY}`, JSON.stringify({ email: EMAIL, created_at: Date.now() }));
  const t = await plant();
  const none = await call(t, 'DELETE', '/api/user/account', {});
  assert.strictEqual(none.status, 400, 'session alone is not enough');
  assert.ok(await rc.get(`paramant:user:meta:${KEY}`), 'nothing was deleted on a refused call');
  const t2 = await plant();
  const ok = await call(t2, 'DELETE', '/api/user/account', { backup_code: 'GOODCODE1' });
  assert.strictEqual(ok.status, 200, await ok.text());
  assert.strictEqual(await rc.get(`paramant:user:meta:${KEY}`), null, 'user:meta (the email) is gone');
  assert.ok(relay.state.calls.some((c) => c.path === '/v2/admin/envelopes/void-account' && c.body && c.body.key === KEY), 'open envelopes were voided');
});

test('2FA reset without a session needs a back-up code, not just the mailbox', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/user/auth/request-totp-reset`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
    body: JSON.stringify({ email: EMAIL, challenge_id: 'x', nonce: 'y' }),
  });
  assert.strictEqual(r.status, 400);
  assert.strictEqual((await r.json()).error, 'backup_code_required');
});

test('2FA reset from the account page needs a factor unless the session came from a back-up code', async () => {
  if (!srv) return;
  const t = await plant();
  assert.strictEqual((await call(t, 'POST', '/api/user/account/totp/reset', {})).status, 400);
});

test('remove a passkey: route exists, needs a fresh factor', async () => {
  if (!srv) return;
  const t = await plant();
  const cred = 'cred_' + 'a'.repeat(30);
  assert.strictEqual((await call(t, 'DELETE', `/api/user/account/webauthn/credentials/${cred}`, {})).status, 400);
  const ok = await call(t, 'DELETE', `/api/user/account/webauthn/credentials/${cred}`, { totp: '123456' });
  assert.strictEqual(ok.status, 200, await ok.text());
  assert.ok(relay.state.calls.some((c) => c.method === 'DELETE' && c.path === '/v2/user/webauthn/credential' && c.body.cred_id === cred));
});
