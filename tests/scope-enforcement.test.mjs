// End-to-end HTTP test for v2 API-key scope enforcement (audit 4.1 / HOOG).
// Boots the real relay in-process (USERS_JSON env, no redis/crypto needed — the
// scope gate runs BEFORE every endpoint body) and asserts the scope→action
// matrix over live HTTP: read-only cannot write, send/sign are separated, full
// and legacy (no-scope) keys keep working.
//
//   node tests/scope-enforcement.test.mjs
import { spawn } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const RELAY = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'relay', 'relay.js');
const PORT = 3987;
const KEYS = {
  full:   'pgp_full_000000000000000000000000',
  ro:     'pgp_ro_0000000000000000000000000000',
  so:     'pgp_so_0000000000000000000000000000',
  si:     'pgp_si_0000000000000000000000000000',
  legacy: 'pgp_legacy_0000000000000000000000',
};
const USERS_JSON = JSON.stringify({ api_keys: [
  { key: KEYS.full,   plan: 'pro', active: true, scope: 'full' },
  { key: KEYS.ro,     plan: 'pro', active: true, scope: 'read-only' },
  { key: KEYS.so,     plan: 'pro', active: true, scope: 'send-only' },
  { key: KEYS.si,     plan: 'pro', active: true, scope: 'sign-only' },
  { key: KEYS.legacy, plan: 'pro', active: true }, // no scope → legacy → full
]});

const child = spawn(process.execPath, [RELAY], {
  env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1', RELAY_MODE: 'full',
         ADMIN_TOKEN: 'test-admin', USERS_JSON, REDIS_URL: '', NATS_URL: '' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

function req(method, p, key, body) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? '' : JSON.stringify(body);
    const r = http.request({ host: '127.0.0.1', port: PORT, path: p, method,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data),
                 ...(key ? { 'X-Api-Key': key } : {}) } }, (res) => {
      let buf = ''; res.on('data', c => buf += c); res.on('end', () => resolve({ status: res.statusCode, body: buf }));
    });
    r.on('error', reject); r.end(data);
  });
}

async function waitUp() {
  for (let i = 0; i < 100; i++) {
    try { await req('GET', '/health'); return; } catch { await new Promise(r => setTimeout(r, 100)); }
  }
  throw new Error('relay did not start');
}

function is403(r, label) {
  assert.equal(r.status, 403, `${label}: expected 403, got ${r.status} ${r.body}`);
  assert.match(r.body, /insufficient_scope/, `${label}: expected insufficient_scope, got ${r.body}`);
  console.log(`  ok  ${label} -> 403 insufficient_scope`);
}
function not403(r, label) {
  assert.notEqual(r.status, 403, `${label}: expected NOT 403, got 403 ${r.body}`);
  console.log(`  ok  ${label} -> ${r.status} (passed scope gate)`);
}

let failed = false;
try {
  await waitUp();
  console.log('read-only key:');
  is403(await req('POST', '/v2/inbound',        KEYS.ro, { x: 1 }), 'read-only POST /v2/inbound (send)');
  is403(await req('POST', '/v2/envelopes',      KEYS.ro, { x: 1 }), 'read-only POST /v2/envelopes (sign)');
  is403(await req('POST', '/v2/pubkey',         KEYS.ro, { x: 1 }), 'read-only POST /v2/pubkey (common)');
  is403(await req('POST', '/v2/admin/keys',     KEYS.ro, { x: 1 }), 'read-only POST /v2/admin/keys (admin)');
  not403(await req('GET', '/v2/audit',          KEYS.ro), 'read-only GET /v2/audit (read)');

  console.log('send-only key:');
  not403(await req('POST', '/v2/inbound',       KEYS.so, {}),       'send-only POST /v2/inbound (send)');
  not403(await req('POST', '/v2/pubkey',        KEYS.so, {}),       'send-only POST /v2/pubkey (common)');
  is403(await req('POST', '/v2/envelopes',      KEYS.so, {}),       'send-only POST /v2/envelopes (sign)');

  console.log('sign-only key:');
  not403(await req('POST', '/v2/envelopes',     KEYS.si, {}),       'sign-only POST /v2/envelopes (sign)');
  is403(await req('POST', '/v2/inbound',        KEYS.si, {}),       'sign-only POST /v2/inbound (send)');

  console.log('full key (existing behaviour):');
  not403(await req('POST', '/v2/inbound',       KEYS.full, {}),     'full POST /v2/inbound');
  not403(await req('POST', '/v2/envelopes',     KEYS.full, {}),     'full POST /v2/envelopes');
  not403(await req('POST', '/v2/admin/keys',    KEYS.full, {}),     'full POST /v2/admin/keys');

  console.log('legacy key (no scope field -> full, backward-compat):');
  not403(await req('POST', '/v2/inbound',       KEYS.legacy, {}),   'legacy POST /v2/inbound');
  not403(await req('POST', '/v2/envelopes',     KEYS.legacy, {}),   'legacy POST /v2/envelopes');

  console.log('\nALL SCOPE-ENFORCEMENT ASSERTIONS PASSED');
} catch (e) {
  failed = true; console.error('FAIL:', e.message);
} finally {
  child.kill('SIGKILL');
}
process.exit(failed ? 1 : 0);
