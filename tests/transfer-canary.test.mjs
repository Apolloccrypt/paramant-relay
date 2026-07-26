// Transfer canary: does the relay still move a file, end to end, right now.
//
// The heartbeat proves the pages initialise. This proves the product works:
// upload a blob, get it back byte for byte, and confirm it burned. It talks to
// the live relay over plain HTTP, so it also covers everything the browser
// suite cannot see: the relay process, nginx, rate limits, TLS, the CT log
// append, and disk.
//
// No secret required. The anonymous route is the free tier every visitor gets,
// so the canary measures what an unauthenticated user actually experiences. Set
// PARAMANT_API_KEY to also exercise the keyed route a paying customer uses.
//
//   node --test tests/transfer-canary.test.mjs
//   PARAMANT_RELAY_URL=https://relay.paramant.app node --test tests/transfer-canary.test.mjs
//
// It leaves nothing behind: burn-on-read destroys the blob, and the assertion
// that it is gone is itself part of the promise being tested.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

const RELAY = (process.env.PARAMANT_RELAY_URL || 'https://relay.paramant.app').replace(/\/$/, '');
const API_KEY = process.env.PARAMANT_API_KEY || '';
const TTL_MS = 600000;

const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// A distinct payload per run, so two canaries can never collide on one hash and
// burn each other's blob.
function payload(label) {
  return Buffer.from(`paramant transfer canary ${label} ${crypto.randomUUID()}`);
}

async function upload(route, body, headers = {}) {
  const r = await fetch(`${RELAY}${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000),
  });
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* keep the raw body in the message */ }
  return { status: r.status, json, text };
}

test('anonymous transfer: upload, download, burn', async () => {
  const blob = payload('anon');
  const hash = sha256hex(blob);

  const up = await upload('/v2/anon-inbound', { hash, payload: blob.toString('base64'), ttl_ms: TTL_MS });
  assert.equal(up.status, 200, `upload rejected: HTTP ${up.status} ${up.text.slice(0, 200)}`);
  assert.equal(up.json?.ok, true, 'relay did not accept the upload');
  assert.equal(up.json?.hash, hash, 'relay stored the blob under a different hash');
  assert.ok(up.json?.download_token, 'no download token, so the recipient has no way to fetch it');

  const dl = await fetch(`${RELAY}/v2/dl/${up.json.download_token}/get`, { signal: AbortSignal.timeout(30000) });
  assert.equal(dl.status, 200, `download failed: HTTP ${dl.status}`);
  const got = Buffer.from(await dl.arrayBuffer());
  assert.equal(sha256hex(got), hash, 'the bytes that came back are not the bytes that went in');

  // Burn-on-read is a promise on the front page, not an implementation detail.
  const again = await fetch(`${RELAY}/v2/dl/${up.json.download_token}/get`, { signal: AbortSignal.timeout(30000) });
  assert.equal(again.status, 410, `the blob survived its read: HTTP ${again.status}, burn-on-read is broken`);
});

test('a corrupted hash is refused before the blob is stored', async () => {
  const blob = payload('mismatch');
  const up = await upload('/v2/anon-inbound', {
    hash: 'f'.repeat(64),
    payload: blob.toString('base64'),
    ttl_ms: TTL_MS,
  });
  assert.equal(up.status, 400, `a payload that does not match its hash was accepted: HTTP ${up.status}`);
  assert.equal(up.json?.error, 'hash_mismatch');
});

test('keyed transfer: upload, download, burn', { skip: API_KEY ? false : 'PARAMANT_API_KEY not set' }, async () => {
  const blob = payload('keyed');
  const hash = sha256hex(blob);

  const up = await upload('/v2/inbound', { hash, payload: blob.toString('base64'), ttl_ms: TTL_MS }, { 'X-Api-Key': API_KEY });
  assert.equal(up.status, 200, `keyed upload rejected: HTTP ${up.status} ${up.text.slice(0, 200)}`);
  assert.equal(up.json?.ok, true, 'relay did not accept the keyed upload');

  const dl = await fetch(`${RELAY}/v2/outbound/${hash}`, {
    headers: { 'X-Api-Key': API_KEY },
    signal: AbortSignal.timeout(30000),
  });
  assert.equal(dl.status, 200, `keyed download failed: HTTP ${dl.status}`);
  const got = Buffer.from(await dl.arrayBuffer());
  assert.equal(sha256hex(got), hash, 'the bytes that came back are not the bytes that went in');
  assert.equal(dl.headers.get('x-paramant-burned'), 'true', 'the relay did not report the blob as burned');
});
