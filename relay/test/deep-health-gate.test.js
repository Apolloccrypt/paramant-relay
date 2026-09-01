'use strict';
// /v2/health/deep across relay modes. The handler aggregates version, loaded
// key count, free disk and cert age. In `full` mode that is deliberately
// public (the setup wizard and /all-systems-go read it); in `ghost_pipe` and
// `iot` the same payload is an information leak, and before this gate existed
// the mode allowlist simply dropped the route ("Not available in this relay
// mode") — so production had NO deep readiness check at all, which is what the
// 2026-09-01 audit found. The fix: the route is mode-allowed everywhere, but
// outside `full` it sits behind the X-Internal-Auth header that already gates
// the user endpoints. Missing token config keeps it closed.
//
// Boots relay.js three times (ghost_pipe+token, ghost_pipe without token,
// full) and asserts: authed internal read works in production mode, the open
// internet gets 401 (not a silent drop, not the old "Not available" error),
// unconfigured token stays closed, and full mode stays public.
// Run: node relay/test/deep-health-gate.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const { spawn } = require('child_process');
const path = require('path');

const RELAY_DIR = path.join(__dirname, '..');
const TOKEN = 'deephealth-test-token';
const children = [];

function boot(port, extraEnv) {
  const child = spawn('node', ['relay.js'], {
    cwd: RELAY_DIR,
    env: {
      ...process.env,
      PORT: String(port),
      USERS_JSON: '{"api_keys":[]}',
      RELAY_REDIS_URL: '',
      NATS_URL: '',
      ...extraEnv,
    },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  children.push(child);
  return child;
}

async function waitHealthy(port) {
  const deadline = Date.now() + 15000;
  for (;;) {
    try { const r = await fetch(`http://127.0.0.1:${port}/health`); if (r.ok) return; } catch (_) { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('relay did not become healthy in time');
    await new Promise((r) => setTimeout(r, 250));
  }
}

async function deep(port, headers) {
  const r = await fetch(`http://127.0.0.1:${port}/v2/health/deep`, { headers: headers || {} });
  let j = null;
  try { j = await r.json(); } catch (_) { /* non-JSON */ }
  return { status: r.status, body: j };
}

after(() => { for (const c of children) c.kill('SIGKILL'); });

test('ghost_pipe: internal auth reads the deep check, the open internet gets 401', async () => {
  const port = 34500 + (process.pid % 400);
  boot(port, { RELAY_MODE: 'ghost_pipe', INTERNAL_AUTH_TOKEN: TOKEN });
  await waitHealthy(port);

  // Unauthenticated: closed, and closed the RIGHT way — a 401 from the gate,
  // not the old mode-allowlist drop that said "Not available in this relay
  // mode" and left production without any readiness signal.
  const anon = await deep(port);
  assert.strictEqual(anon.status, 401, 'unauthenticated read must be refused');
  assert.strictEqual(anon.body.error, 'unauthorized');

  // Authenticated: the full aggregated check, same shape full mode serves.
  const authed = await deep(port, { 'X-Internal-Auth': TOKEN });
  assert.strictEqual(authed.status, 200, 'internal-authed read must work in production mode');
  assert.ok(['green', 'yellow', 'red'].includes(authed.body.overall), 'overall verdict present');
  assert.ok(Array.isArray(authed.body.checks) && authed.body.checks.length > 0, 'checks array present');
  const names = authed.body.checks.map((c) => c.name);
  for (const expected of ['relay', 'crypto', 'storage', 'memory']) {
    assert.ok(names.includes(expected), `check "${expected}" present`);
  }

  // A wrong token is not a lucky token.
  const wrong = await deep(port, { 'X-Internal-Auth': TOKEN + 'x' });
  assert.strictEqual(wrong.status, 401, 'wrong token must be refused');
});

test('ghost_pipe without INTERNAL_AUTH_TOKEN: stays closed, never open-by-default', async () => {
  const port = 34900 + (process.pid % 400);
  boot(port, { RELAY_MODE: 'ghost_pipe', INTERNAL_AUTH_TOKEN: '' });
  await waitHealthy(port);
  const anon = await deep(port);
  assert.strictEqual(anon.status, 401, 'missing token config must read as closed');
  // Even presenting the header cannot open a gate with no configured token.
  const tried = await deep(port, { 'X-Internal-Auth': '' });
  assert.strictEqual(tried.status, 401, 'empty token must not match empty config');
});

test('full mode: stays public for the setup wizard', async () => {
  const port = 35300 + (process.pid % 400);
  boot(port, { RELAY_MODE: 'full' });
  await waitHealthy(port);
  const anon = await deep(port);
  assert.strictEqual(anon.status, 200, 'full mode must keep the public read');
  assert.ok(Array.isArray(anon.body.checks) && anon.body.checks.length > 0);
});
