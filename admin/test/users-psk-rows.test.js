'use strict';
// ADMIN-06-psk: a psk_ key (ParaSign /v1 API key, minted by mint-parasign or
// the account page) is a key of an account, not an account. The Users list
// showed it as a row of its own, and every action on it answered invalid_key.
// It is now counted on the row of the account it belongs to.
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState } = require('./_admin-server');

const PGP = 'pgp_' + crypto.randomBytes(32).toString('hex');
const PSK = 'psk_live_' + crypto.randomBytes(24).toString('hex');
const PSK_OFF = 'psk_test_' + crypto.randomBytes(24).toString('hex');
let rc = null; let srv = null; let SID = null;

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
  const acct = { key: PGP, kid: 'k_' + crypto.randomBytes(6).toString('hex'), account_id: PGP, email: 'jan@bakkerij.test', plan: 'pro', active: true };
  const psk = { key: PSK, kid: 'k_' + crypto.randomBytes(6).toString('hex'), account_id: PGP, email: 'jan@bakkerij.test', label: 'parasign-api', plan: 'pro', active: true };
  const pskRevoked = { ...psk, key: PSK_OFF, kid: 'k_' + crypto.randomBytes(6).toString('hex'), active: false };
  const relay = await stubRelay(defaultRelayState([acct, psk, pskRevoked]));
  srv = await boot({ redisUrl: url, relay, env: { RELAY_MAIN: relay.base, RELAY_LEGAL: relay.base, RELAY_FINANCE: relay.base, RELAY_IOT: relay.base } });
  SID = crypto.randomBytes(16).toString('hex');
  await rc.set(`paramant:admin:session:${SID}`, '1', { EX: 600 });
});
after(async () => { await killAll(); if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } } });

test('psk_ keys are not account rows; the account row counts its active ones', async () => {
  if (!srv) return;
  const r = await fetch(`${srv.base}/api/admin/users`, { headers: { 'X-Session': SID } });
  const j = await r.json();
  assert.strictEqual(r.status, 200, JSON.stringify(j));
  assert.strictEqual(j.users.length, 1, 'rows: ' + JSON.stringify(j.users.map((u) => u.key)));
  assert.ok(!j.users.some((u) => String(u.key).startsWith('psk_')), 'a psk_ key is listed as an account');
  assert.strictEqual(j.users[0].parasign_keys, 1, 'the active psk_ key is counted on its account');
  assert.strictEqual(j.counts.total, 1);
});
