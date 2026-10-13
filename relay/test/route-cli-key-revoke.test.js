'use strict';
// ADMIN-45: the web-CLI "key revoke" posted {key_prefix}; the relay only knows
// the exact key, so every revoke failed with 404 and the key stayed valid.
// The script now resolves the prefix to one key and revokes it everywhere.
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const path = require('path');
const { execFileSync } = require('child_process');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const SCRIPT = path.join(__dirname, '..', '..', 'scripts', 'cli', 'paramant-key-revoke.sh');
const ADMIN = 'adm_' + crypto.randomBytes(16).toString('hex');
const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
const KEY2 = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0;
after(async () => { await killAll(); summary('route-cli-key-revoke', checks); });

test('revoke by prefix revokes that one key', async () => {
  const srv = await boot({ tag: 'clirevoke', env: { ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: 'int_' + ADMIN },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'a@example.test' }, { key: KEY2, plan: 'pro', active: true, email: 'b@example.test' }] } });
  let failed = false;
  try { execFileSync('bash', [SCRIPT, 'pgp_'], { env: { PATH: process.env.PATH, RELAY_URL: srv.base, ADMIN_TOKEN: ADMIN }, encoding: 'utf8' }); }
  catch (e) { failed = /keys start with that prefix/.test(e.stdout); }
  assert.ok(failed, 'an ambiguous prefix is refused');
  const out = execFileSync('bash', [SCRIPT, KEY.slice(0, 16)], { env: { PATH: process.env.PATH, RELAY_URL: srv.base, RELAY_SECTORS: `health=${srv.base}`, ADMIN_TOKEN: ADMIN }, encoding: 'utf8' });
  assert.match(out, /\[OK\] key pgp_/);
  const ck = await srv.get('/v2/check-key', { headers: { 'X-Api-Key': KEY } });
  assert.notStrictEqual(ck.json && ck.json.valid, true, 'the revoked key still checks out');
  const ck2 = await srv.get('/v2/check-key', { headers: { 'X-Api-Key': KEY2 } });
  assert.strictEqual(ck2.json && ck2.json.valid, true, 'the other key is untouched');
  await srv.stop();
  checks++;
});
