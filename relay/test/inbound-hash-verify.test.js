'use strict';
// Inbound hash-verification: the relay must reject an upload whose claimed
// SHA-256 does not match the payload bytes, on BOTH /v2/inbound and the keyless
// /v2/anon-inbound. The claimed hash is committed into the CT-log leaf
// (ctAppendTransfer -> blobLeafHash) and into the signed outbound delivery
// receipt, so an unverified claim would let a caller mint a relay-signed,
// CT-anchored lever+burn proof for bytes the relay never held. The honest
// client (frontend/js/parashare.page.js and extensions/shared/paramant-core.js)
// sends hash = sha256(exact payload bytes), so a correct upload is unaffected.
//
// Boots relay.js on a random port (keyless anon path + one pro API key via
// USERS_JSON), then posts a matching and a mismatching hash to each route.
// Run: node relay/test/inbound-hash-verify.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const RELAY_DIR = path.join(__dirname, '..');
const PORT = 34000 + (process.pid % 5000);
const BASE = `http://127.0.0.1:${PORT}`;
const API_KEY = 'pgp_hashverify_test';

let child;
let usersFile;

// A blob that does NOT start with the "PQHB" v1 magic, so peekInboundBlob()
// treats it as a passthrough (isV1 === false) and the hash check is the only
// gate under test here. Random suffix keeps each blob (and its hash) unique so
// the burn-on-read blobStore never dedup-collides (409) between cases.
function blob(tag) {
  return Buffer.from('not-a-v1-wire-blob:' + tag + ':' + crypto.randomBytes(8).toString('hex'));
}
function sha256hex(b) {
  return crypto.createHash('sha256').update(b).digest('hex');
}
async function post(route, body, headers) {
  const r = await fetch(BASE + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(headers || {}) },
    body: JSON.stringify(body),
  });
  let j = null;
  try { j = await r.json(); } catch (_) { /* non-JSON */ }
  return { status: r.status, body: j };
}

before(async () => {
  usersFile = path.join(os.tmpdir(), `hashverify-users-${process.pid}.json`);
  fs.writeFileSync(usersFile, '{}');
  child = spawn('node', ['relay.js'], {
    cwd: RELAY_DIR,
    env: {
      ...process.env,
      PORT: String(PORT),
      USERS_FILE: usersFile,
      RELAY_MODE: 'full',
      USERS_JSON: JSON.stringify({
        api_keys: [{ key: API_KEY, active: true, plan: 'pro', label: 'hashverify', email: 't@t' }],
      }),
      RELAY_REDIS_URL: '',
      NATS_URL: '',
    },
    stdio: ['ignore', 'ignore', 'ignore'],
  });
  const deadline = Date.now() + 15000;
  for (;;) {
    try { const r = await fetch(BASE + '/health'); if (r.ok) break; } catch (_) { /* not up yet */ }
    if (Date.now() > deadline) throw new Error('relay did not become healthy in time');
    await new Promise((r) => setTimeout(r, 250));
  }
});

after(() => {
  if (child) child.kill('SIGKILL');
  try { fs.unlinkSync(usersFile); } catch (_) { /* best effort */ }
});

test('anon-inbound accepts an upload whose hash matches the payload', async () => {
  const b = blob('anon-ok');
  const r = await post('/v2/anon-inbound', { hash: sha256hex(b), payload: b.toString('base64') });
  assert.strictEqual(r.status, 200, 'matching hash must be accepted');
  assert.strictEqual(r.body.ok, true);
});

test('anon-inbound rejects a hash that does not match the payload (400 hash_mismatch)', async () => {
  const b = blob('anon-bad');
  const r = await post('/v2/anon-inbound', { hash: 'f'.repeat(64), payload: b.toString('base64') });
  assert.strictEqual(r.status, 400, 'mismatching hash must be rejected before CT-append / store');
  assert.strictEqual(r.body.error, 'hash_mismatch');
});

test('inbound accepts an upload whose hash matches the payload', async () => {
  const b = blob('inbound-ok');
  const r = await post('/v2/inbound', { hash: sha256hex(b), payload: b.toString('base64') }, { 'X-Api-Key': API_KEY });
  assert.strictEqual(r.status, 200, 'matching hash must be accepted');
});

test('inbound rejects a hash that does not match the payload (400 hash_mismatch)', async () => {
  const b = blob('inbound-bad');
  const r = await post('/v2/inbound', { hash: 'e'.repeat(64), payload: b.toString('base64') }, { 'X-Api-Key': API_KEY });
  assert.strictEqual(r.status, 400, 'mismatching hash must be rejected before CT-append / store');
  assert.strictEqual(r.body.error, 'hash_mismatch');
});
