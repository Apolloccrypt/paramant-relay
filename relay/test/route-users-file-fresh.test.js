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
  assert.ok(!srv.log().includes(token), 'the token is never written to the log, only its file is named');
  assert.match(srv.log(), /setup_token_ready/, 'the log says the token file exists');
  assert.strictEqual(fs.statSync(tokenFile).mode & 0o777, 0o600, 'the token file is mode 0600');
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

// Review #555 B3: a setup-token was committed to git, and the relay READ an
// existing file before making one. Anyone running a checkout from relay/
// (USERS_FILE=./users.json) then accepted a public token. A file that is
// already there must never be loaded, whatever its mode.
test('a setup-token file that was already there is never accepted', async () => {
  const dir = scratch('planted');
  const dataDir = path.join(dir, 'data');
  fs.mkdirSync(dataDir, { recursive: true });
  const usersFile = path.join(dataDir, 'users.json');
  const planted = 'pst_a561b67c50a0a502321eb9af48d13506819342c35e9a0faf';
  const tokenFile = path.join(dataDir, 'setup-token');
  fs.writeFileSync(tokenFile, planted + '\n', { mode: 0o600 });
  const env = { USERS_FILE: usersFile, USERS_JSON: '', SETUP_ENV_FILE: path.join(dir, 'setup.env') };
  const srv = await boot({ tag: 'uplanted', dir, captureLog: true, env });
  const r = await srv.post('/v2/setup/apply', { headers: { 'X-Setup-Token': planted }, body: setupBody });
  assert.strictEqual(r.status, 401, 'a planted token is refused: ' + JSON.stringify(r.json));
  const fresh = fs.readFileSync(tokenFile, 'utf8').trim();
  assert.notStrictEqual(fresh, planted, 'the planted file is replaced by a fresh token');
  assert.match(fresh, /^pst_[0-9a-f]{48}$/);
  assert.strictEqual(fs.statSync(tokenFile).mode & 0o777, 0o600);
  assert.ok(!srv.log().includes(fresh) && !srv.log().includes(planted), 'no token in the log');
  await srv.stop();
  did();
});

test('no setup-token is tracked in git', () => {
  const { execFileSync } = require('child_process');
  let tracked = '';
  try { tracked = execFileSync('git', ['ls-files', '--', ':(glob)**/setup-token'], { cwd: path.join(__dirname, '..', '..'), encoding: 'utf8' }); } catch (_) { return; }
  assert.strictEqual(tracked.trim(), '', 'setup-token files in git: ' + tracked);
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
