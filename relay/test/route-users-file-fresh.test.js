'use strict';
// users.json on a fresh relay, and the setup wizard that writes into it.
//
// WHY. SELF-05 (fase 1): a fresh relay had no users.json. Every persist read
// the missing file, failed with ENOENT inside a queue that swallowed the
// error, and the log still said persisted:true. After a restart the setup
// admin key was gone and the wizard stood open again, anonymously: whoever
// opened /setup first walked off with an enterprise key.
// Run: node --test relay/test/route-users-file-fresh.test.js
const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
const dirs = [];
function scratch(tag) { const d = fs.mkdtempSync(path.join(os.tmpdir(), `usersfresh-${tag}-`)); dirs.push(d); return d; }
after(async () => {
  summary('route-users-file-fresh', checks);
  await killAll();
  for (const d of dirs) { try { fs.chmodSync(d, 0o700); fs.rmSync(d, { recursive: true, force: true }); } catch (_) { /* gone */ } }
});

const setupBody = { sectors: ['general'], adminEmail: 'ops@example.test' };

test('fresh relay: users.json is created, setup needs the token, the admin key survives a restart', async () => {
  const dir = scratch('setup');
  const usersFile = path.join(dir, 'data', 'users.json');
  const env = { USERS_FILE: usersFile, USERS_JSON: '', SETUP_ENV_FILE: path.join(dir, 'setup.env') };
  let srv = await boot({ tag: 'ufresh', dir, captureLog: true, env });
  assert.ok(fs.existsSync(usersFile), 'users.json exists on a fresh relay');
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(usersFile, 'utf8')).api_keys, []);

  const anon = await srv.post('/v2/setup/apply', { body: setupBody });
  assert.strictEqual(anon.status, 401, 'anonymous setup is refused');
  assert.strictEqual(anon.json.error, 'setup_token_required');
  const wrong = await srv.post('/v2/setup/apply', { headers: { 'X-Setup-Token': 'pst_nope' }, body: setupBody });
  assert.strictEqual(wrong.status, 401);

  const tokenFile = path.join(dir, 'data', 'setup-token');
  const token = fs.readFileSync(tokenFile, 'utf8').trim();
  assert.match(srv.log(), new RegExp(token), 'the token is in the relay log for the operator');
  const ok = await srv.post('/v2/setup/apply', { headers: { 'X-Setup-Token': token }, body: setupBody });
  assert.strictEqual(ok.status, 200, JSON.stringify(ok.json));
  const adminKey = ok.json.admin_api_key;
  assert.ok(JSON.parse(fs.readFileSync(usersFile, 'utf8')).api_keys.some((k) => k.key === adminKey), 'admin key on disk');
  assert.ok(!fs.existsSync(tokenFile), 'token is single-use');

  srv = await srv.restart();
  const chk = await srv.get('/v2/setup/check');
  assert.strictEqual(chk.json.setupMode, false, 'after a restart the wizard stays closed');
  const again = await srv.post('/v2/setup/apply', { headers: { 'X-Setup-Token': token }, body: setupBody });
  assert.strictEqual(again.status, 409);
  await srv.stop();
  did();
});

test('a key that cannot be written is not reported as created, and the log does not say persisted:true', async () => {
  if (process.getuid && process.getuid() === 0) return; // root ignores the read-only dir
  const dir = scratch('ro');
  const roDir = path.join(dir, 'ro');
  fs.mkdirSync(roDir);
  const usersFile = path.join(roDir, 'users.json');
  fs.writeFileSync(usersFile, JSON.stringify({ api_keys: [{ key: 'pgp_' + 'a'.repeat(64), plan: 'pro', active: true }] }));
  const ADMIN = 'admin-users-fresh-0123456789abcdef';
  const INTERNAL = 'int-users-fresh-0123456789abcdef';
  const srv = await boot({ tag: 'uro', dir, captureLog: true, env: { USERS_FILE: usersFile, USERS_JSON: '', ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: INTERNAL } });
  fs.chmodSync(roDir, 0o500);
  const r = await srv.post('/v2/admin/keys', { headers: { 'X-Admin-Token': ADMIN, Authorization: `Bearer ${ADMIN}`, 'X-Internal-Auth': INTERNAL }, body: { plan: 'pro', label: 'ro-test', email: 'x@example.test' } });
  fs.chmodSync(roDir, 0o700);
  assert.strictEqual(r.status, 503, JSON.stringify(r.json));
  assert.strictEqual(r.json.error, 'key_not_persisted');
  assert.doesNotMatch(srv.log(), /"key_created_via_admin"[^\n]*"persisted":true/);
  assert.match(srv.log(), /key_persist_failed/);
  await srv.stop();
  did();
});
