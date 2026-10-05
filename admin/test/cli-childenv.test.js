'use strict';
// Unit test for cli-commands.buildChildEnv: the least-privilege environment for
// spawned web-CLI handlers. Proves the high-sensitivity secrets are NOT
// broadcast to every command, and ADMIN_TOKEN reaches only the commands that
// declare needsAdminToken.
// Run: node admin/test/cli-childenv.test.js (no deps, non-zero exit on fail).

const assert = require('assert');
const { buildChildEnv, COMMANDS } = require('../lib/cli-commands');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

const PROC = {
  PATH: '/usr/bin', HOME: '/root',
  ADMIN_TOKEN: 'secret-admin', REDIS_URL: 'redis://x', REDIS_PASSWORD: 'p',
  RESEND_API_KEY: 'resend', PARAMANT_API_KEY: 'pgp_secret', PARAMANT_SIGNING_KEY: 'sk',
  RELAY_PORT: '3000', NATS_MONITOR_URL: 'http://nats', COMPOSE_CMD: 'docker compose',
  BACKUP_DIR: '/b', SECTOR_X: 'y', PORT: '4200', NODE_ENV: 'production',
};
const SECTORS = { health: 'http://health', finance: 'http://finance' };
const TOK = 'secret-admin';

// 1. A read command carries NONE of the high-sensitivity secrets.
const r = buildChildEnv(COMMANDS['status'], PROC, SECTORS, TOK);
assert.strictEqual(r.ADMIN_TOKEN, undefined, 'read: no ADMIN_TOKEN');
assert.strictEqual(r.REDIS_URL, undefined, 'no REDIS_URL');
assert.strictEqual(r.REDIS_PASSWORD, undefined, 'no REDIS_PASSWORD');
assert.strictEqual(r.RESEND_API_KEY, undefined, 'no RESEND_API_KEY');
assert.strictEqual(r.PARAMANT_API_KEY, undefined, 'no PARAMANT_API_KEY');
assert.strictEqual(r.PARAMANT_SIGNING_KEY, undefined, 'no PARAMANT_SIGNING_KEY');
ok('read command env carries no secrets');

// 2. Non-secret operational vars ARE present, plus the derived relay locators.
assert.strictEqual(r.RELAY_PORT, '3000', 'RELAY_* kept');
assert.strictEqual(r.NATS_MONITOR_URL, 'http://nats', 'NATS_* kept');
assert.strictEqual(r.COMPOSE_CMD, 'docker compose', 'COMPOSE_* kept');
assert.strictEqual(r.BACKUP_DIR, '/b', 'BACKUP_* kept');
assert.strictEqual(r.RELAY_URL, 'http://health', 'RELAY_URL derived');
assert.ok(r.RELAY_SECTORS.includes('finance=http://finance'), 'RELAY_SECTORS derived');
ok('read command env carries operational vars');

// 3. ADMIN_TOKEN reaches ONLY the commands that declare needsAdminToken.
for (const name of ['key add', 'key list', 'key revoke', 'audit recent', 'backup create']) {
  assert.ok(COMMANDS[name], 'command exists: ' + name);
  const e = buildChildEnv(COMMANDS[name], PROC, SECTORS, TOK);
  assert.strictEqual(e.ADMIN_TOKEN, TOK, name + ' gets ADMIN_TOKEN');
  assert.strictEqual(e.REDIS_URL, undefined, name + ' still has no REDIS');
}
ok('ADMIN_TOKEN present only for needsAdminToken commands');

// 4. Commands that must NEVER receive ADMIN_TOKEN (incl. config show, which
//    surfaces env -> cannot leak a token it never holds).
for (const name of ['status', 'health', 'logs', 'config show', 'relay list', 'nats status', 'restart']) {
  assert.ok(COMMANDS[name], 'command exists: ' + name);
  const e = buildChildEnv(COMMANDS[name], PROC, SECTORS, TOK);
  assert.strictEqual(e.ADMIN_TOKEN, undefined, name + ' must NOT get ADMIN_TOKEN');
}
ok('no ADMIN_TOKEN for read/infra commands, incl. config show');

// 5. Defensive: a missing/odd command never throws and never leaks.
const e0 = buildChildEnv(undefined, PROC, SECTORS, TOK);
assert.strictEqual(e0.ADMIN_TOKEN, undefined, 'undefined cmd: no token');
ok('undefined command is safe');

console.log('cli-childenv:', passed, 'groups passed');
