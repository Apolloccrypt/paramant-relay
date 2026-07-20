'use strict';
// Route-auth CONTRACT: locks the per-route auth gate of the critical relay
// routes via REAL HTTP against a locally booted relay.js.
//
// Born from the 2026-07-20 regression: a comma-operator bug
//     if (path === '/v2/envelopes','/v2/billing' && req.method === 'POST')
// collapses via the comma operator to the truthy string '/v2/billing', so the
// create-envelope guard matched EVERY POST and returned 401 "API key required".
// The keyless internal POST /v2/envelopes/:id/sign hit that create gate and 401'd,
// surfacing as "Please sign in to sign documents" for a logged-in user. No test
// guarded the auth contract per route. These do. Re-widen a gate and they go red.
//
// Boot: spawns relay.js on an ephemeral port. Needs the relay deps installed (the
// `redis` client module resolvable); skips cleanly otherwise, same policy as
// parasign-open-api-e2e.test.js. A running redis + ML-DSA-65 engine let the sign
// handler reach its own 400/404; WITHOUT them the sign route still returns 503
// (store unavailable) which is what matters here: it is NEVER 401. The exact
// regression is caught in either environment.
//
//   Full assertions:  docker run -d --rm -p 6399:6379 --name r redis:alpine
//                     REDIS_URL=redis://127.0.0.1:6399 node --test test/route-auth-contract.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const http = require('http');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

// A dummy envelope id that satisfies the relay's id shape /^[A-Za-z0-9_-]{20,64}$/,
// so a keyless /sign request gets PAST the id check and reaches the handler body.
const DUMMY_ID = 'contract-dummy-envelope-000000';

let child = null;
let BASE = null;
let bootFailed = null;
let stderrTail = '';

function haveRelayDeps() {
  try { require.resolve('redis'); return true; } catch { return false; }
}

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on('error', reject);
    s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => resolve(p)); });
  });
}

function req(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
    const u = new URL(BASE + urlPath);
    const r = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search, method,
      headers: Object.assign({ 'Content-Type': 'application/json' }, data ? { 'Content-Length': data.length } : {}),
    }, (res) => {
      let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => resolve({ code: res.statusCode, body: b }));
    });
    r.on('error', reject);
    r.setTimeout(8000, () => r.destroy(new Error('request timeout')));
    if (data) r.write(data);
    r.end();
  });
}

function health(base) {
  return new Promise((resolve) => {
    const rq = http.get(base + '/health', (res) => { res.resume(); resolve(res.statusCode); });
    rq.on('error', () => resolve(0));
    rq.setTimeout(1000, () => { rq.destroy(); resolve(0); });
  });
}

before(async () => {
  if (!haveRelayDeps()) { bootFailed = 'relay deps not installed (require.resolve("redis") failed) — run npm install in relay/'; return; }
  const port = await freePort();
  BASE = `http://127.0.0.1:${port}`;
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-authct-'));
  const env = Object.assign({}, process.env, {
    PORT: String(port),
    HOST: '127.0.0.1',
    RELAY_MODE: 'full',
    REDIS_URL: process.env.REDIS_URL || 'redis://127.0.0.1:6399',
    ADMIN_TOKEN: 'contract-admin-token',
    INTERNAL_AUTH_TOKEN: 'contract-internal-token',
    PARAMANT_TOTP_MASTER_KEY: process.env.PARAMANT_TOTP_MASTER_KEY || crypto.randomBytes(32).toString('base64'),
    RELAY_IDENTITY_FILE: path.join(work, 'relay-identity.json'),
    USERS_FILE: path.join(work, 'users.json'),
  });
  child = spawn(process.execPath, ['relay.js'], { cwd: path.join(__dirname, '..'), env, stdio: ['ignore', 'ignore', 'pipe'] });
  child.stderr.on('data', (c) => { stderrTail = (stderrTail + c.toString()).slice(-800); });
  child.on('error', (e) => { bootFailed = 'spawn error: ' + e.message; });

  const deadline = Date.now() + 12000;
  let up = false;
  while (Date.now() < deadline) {
    if (bootFailed) break;
    if ((await health(BASE)) === 200) { up = true; break; }
    await new Promise((r) => setTimeout(r, 200));
  }
  if (!up && !bootFailed) bootFailed = 'relay did not become healthy in 12s. stderr tail:\n' + stderrTail;
  if (bootFailed && child) { try { child.kill('SIGKILL'); } catch (_) {} child = null; }
});

after(() => { if (child) { try { child.kill('SIGKILL'); } catch (_) {} child = null; } });

// ── THE regression: keyless /sign must reach the sign handler, never the auth gate.
test('POST /v2/envelopes/:id/sign without X-Api-Key reaches the sign handler (never 401)', async (t) => {
  if (bootFailed) { t.skip(bootFailed); return; }
  const r = await req('POST', `/v2/envelopes/${DUMMY_ID}/sign`, {});
  assert.notStrictEqual(r.code, 401, `sign must NEVER be 401 (the 2026-07-20 regression). got 401: ${r.body}`);
  assert.ok([400, 404, 503].includes(r.code), `sign should reach its own handler (400/404) or a store-unavailable 503, got ${r.code}: ${r.body}`);
  if (r.code === 400) assert.match(r.body, /party_index/, `expected the sign handler's own validation error, got: ${r.body}`);
});

test('POST /v2/envelopes/:id/sign without X-Api-Key reaches the store (404 not_found on a dummy id)', async (t) => {
  if (bootFailed) { t.skip(bootFailed); return; }
  const r = await req('POST', `/v2/envelopes/${DUMMY_ID}/sign`, { party_index: 0, signer_public_key: 'AA', signature: 'AA' });
  assert.notStrictEqual(r.code, 401, `sign must NEVER be 401. got 401: ${r.body}`);
  assert.ok([404, 503].includes(r.code), `a well-formed keyless sign on a non-existent id is 404 not_found (store up) or 503 (store down), got ${r.code}: ${r.body}`);
  if (r.code === 404) assert.match(r.body, /not_found/, `expected not_found, got: ${r.body}`);
});

// ── The gates that MUST stay closed to keyless callers.
test('POST /v2/envelopes (create) without X-Api-Key is 401', async (t) => {
  if (bootFailed) { t.skip(bootFailed); return; }
  const r = await req('POST', '/v2/envelopes', { doc_hash: 'deadbeef' });
  assert.strictEqual(r.code, 401, `create must require an API key, got ${r.code}: ${r.body}`);
});

test('POST /v2/inbound without X-Api-Key is 401', async (t) => {
  if (bootFailed) { t.skip(bootFailed); return; }
  const r = await req('POST', '/v2/inbound', { hash: 'x' });
  assert.strictEqual(r.code, 401, `inbound must require an API key, got ${r.code}: ${r.body}`);
});

test('POST /v2/billing/checkout without X-Api-Key is 401', async (t) => {
  if (bootFailed) { t.skip(bootFailed); return; }
  const r = await req('POST', '/v2/billing/checkout', { product: 'parasign', plan: 'pro', interval: 'month' });
  assert.strictEqual(r.code, 401, `billing checkout must require an API key, got ${r.code}: ${r.body}`);
});

// ── The gate that MUST stay open (public recipient endpoint).
test('GET /v2/envelopes/:id is public (never 401)', async (t) => {
  if (bootFailed) { t.skip(bootFailed); return; }
  const r = await req('GET', `/v2/envelopes/${DUMMY_ID}`);
  assert.notStrictEqual(r.code, 401, `public envelope status must not be 401, got 401: ${r.body}`);
  assert.ok([200, 404, 503].includes(r.code), `expected 200/404/503, got ${r.code}: ${r.body}`);
});
