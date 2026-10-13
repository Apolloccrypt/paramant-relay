'use strict';
// SELF-11-A: revoking the last active key with deploy/paramant-admin.py and
// reloading answered 409 sanity_check_failed, and the revoked key went on
// working. The 409 guards against a half-written users.json (the 2026-05-08
// race: readable but empty); a file in which every key is present and marked
// active:false is the operator's intent and must be applied. An empty key list
// is still refused.
const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');

const ADMIN = 'admin-token-reload-last-key-' + crypto.randomBytes(8).toString('hex');
const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
after(() => killAll());

const reload = (srv) => srv.req('POST', '/v2/reload-users', { headers: { 'X-Api-Key': ADMIN }, body: {} });
const valid = async (srv) => (await srv.req('GET', '/v2/check-key', { headers: { 'X-Api-Key': KEY } })).json?.valid;

test('revoking the last key and reloading makes it invalid; an empty file is still refused', async () => {
  const srv = await boot({
    tag: 'reload-last-key', usersFile: true,
    users: { api_keys: [{ key: KEY, plan: 'pro', label: 'only', active: true, created: new Date().toISOString() }] },
    env: { ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: 'internal-reload-last-key' },
  });
  assert.strictEqual(await valid(srv), true, 'the key works before the revoke');

  // An empty list: the race the guard is for. Still a 409, key still valid.
  fs.writeFileSync(srv.env.USERS_FILE, JSON.stringify({ api_keys: [] }));
  const empty = await reload(srv);
  assert.strictEqual(empty.status, 409, empty.text);
  assert.strictEqual(await valid(srv), true);

  // What paramant-admin.py revoke writes: the entry stays, active:false.
  fs.writeFileSync(srv.env.USERS_FILE, JSON.stringify({ api_keys: [{ key: KEY, plan: 'pro', label: 'only', active: false, revoked_at: new Date().toISOString() }] }));
  const r = await reload(srv);
  assert.strictEqual(r.status, 200, 'revoking the last key was refused: ' + r.text);
  assert.strictEqual(r.json.loaded, 0);
  assert.notStrictEqual(await valid(srv), true, 'the revoked last key still works');
});
