'use strict';
// Nothing burns without a complete delivery (matrix API-24-K, API-30-K,
// API-35-K, fase 2 eindmatrix).
//
// A download without a claim, the route every SDK and script in the field
// uses, burned the blob when the request came in (/v2/outbound) and answered
// X-Burned: true before a single byte had left (/v2/dl/:token/get). A receiver
// whose connection broke after the first 36 KB of a 4 MB file lost it: status
// said available:false and the next GET was 404.
//
// Now the read only counts once the whole body was delivered: the blob is
// hidden while it is being sent and destroyed after, and a reader that breaks
// off puts it back. A complete read still burns, and a second read right after
// it still finds nothing.
// Run: node --test relay/test/route-burn-after-delivery.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const net = require('net');
const http = require('http');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const KEY = 'pgp_pro_key_for_the_burn_after_delivery_suite';
let srv;
let checks = 0;
const did = () => { checks++; };

function bigBlob(mb) {
  const payload = crypto.randomBytes(mb * 1024 * 1024);
  return { payload, hash: crypto.createHash('sha256').update(payload).digest('hex') };
}
const upload = (b) => srv.post('/v2/inbound', {
  headers: { 'X-Api-Key': KEY },
  body: { hash: b.hash, payload: b.payload.toString('base64') },
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Reads the first chunk of the body and breaks the connection, like a receiver
// on a train going into a tunnel.
async function readFirstChunkAndAbort(path, headers = {}) {
  const ac = new AbortController();
  let got = 0;
  try {
    const r = await fetch(srv.base + path, { headers, signal: ac.signal });
    const rd = r.body.getReader();
    const c = await rd.read();
    got = c.value ? c.value.length : 0;
    ac.abort();
  } catch (_) { /* the abort itself */ }
  return got;
}

before(async () => {
  srv = await boot({
    tag: 'burn-after-delivery',
    env: { DELIVERY_SETTLE_MS: '500' },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'pro@example.test', account_id: 'acct_bad' }] },
  });
});
after(async () => { await killAll(); summary('route-burn-after-delivery', checks); });

test('GET /v2/outbound broken off after the first chunk keeps the blob', async () => {
  const b = bigBlob(4);
  assert.equal((await upload(b)).status, 200);
  const got = await readFirstChunkAndAbort(`/v2/outbound/${b.hash}`, { 'X-Api-Key': KEY });
  assert.ok(got > 0 && got < b.payload.length, `read ${got} of ${b.payload.length} bytes`);
  await sleep(1500);
  const st = await srv.get(`/v2/status/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(st.json.available, true, 'the receiver lost the file to a broken connection');
  const again = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(again.status, 200);
  assert.ok(again.buf.equals(b.payload), 'the second try must get the whole file');
  did();
});

test('a complete GET /v2/outbound still burns, and the next one is 404 at once', async () => {
  const b = bigBlob(1);
  assert.equal((await upload(b)).status, 200);
  const first = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(first.status, 200);
  assert.ok(first.buf.equals(b.payload));
  const second = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(second.status, 404);
  await sleep(1200);
  const st = await srv.get(`/v2/status/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(st.json.available, false);
  did();
});

test('the claimless /v2/dl link says nothing is burned yet, and a broken download keeps the link', async () => {
  const b = bigBlob(4);
  const up = await upload(b);
  const token = up.json.download_token;
  const got = await readFirstChunkAndAbort(`/v2/dl/${token}/get`, { 'User-Agent': 'curl/8.9.1' });
  assert.ok(got > 0 && got < b.payload.length);
  await sleep(1500);
  const info = await srv.get(`/v2/dl/${token}/info`);
  assert.equal(info.status, 200, 'the link died with the connection');
  assert.equal(info.json.used, false);
  const full = await srv.get(`/v2/dl/${token}/get`, { headers: { 'User-Agent': 'curl/8.9.1' } });
  assert.equal(full.status, 200);
  assert.notEqual(full.headers['x-burned'], 'true', 'X-Burned: true before delivery is not true');
  assert.equal(full.headers['x-burned'], 'on-delivery');
  assert.ok(full.buf.equals(b.payload));
  const again = await srv.get(`/v2/dl/${token}/get`, { headers: { 'User-Agent': 'curl/8.9.1' } });
  assert.equal(again.status, 410, 'a delivered link is spent');
  did();
});

// A proxy in front that reads every byte at once (docker's userland proxy on
// a published port, matrix API-35-K): the receiver behind it gives up, the
// proxy closes towards the relay cleanly, and no reset ever reaches us. The
// same key retrying right after still gets the file; later it is gone.
test('behind a proxy that swallows the bytes, a broken download can be retried by the same key', async () => {
  const b = bigBlob(2);
  assert.equal((await upload(b)).status, 200);
  const relayPort = Number(new URL(srv.base).port);
  const socks = new Set();
  const proxy = net.createServer((c) => {
    const u = net.connect(relayPort, '127.0.0.1');
    socks.add(c); socks.add(u);
    c.pipe(u);
    // Reads the relay as fast as it sends, whatever the receiver does, and
    // keeps what the receiver cannot take yet in its own memory.
    u.on('data', (d) => { if (!c.destroyed) c.write(d); });
    c.on('error', () => {}); u.on('error', () => {});
    // The receiver went away: close towards the relay cleanly, as docker-proxy does.
    c.on('close', () => { u.end(); setTimeout(() => u.destroy(), 2000).unref(); });
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const pport = proxy.address().port;
  // A receiver that reads one chunk through the proxy and hangs up.
  await new Promise((resolve) => {
    const rq = http.get({ host: '127.0.0.1', port: pport, path: `/v2/outbound/${b.hash}`, headers: { 'X-Api-Key': KEY }, agent: false }, (res) => {
      res.once('data', () => { setTimeout(() => { rq.destroy(); resolve(); }, 300); });
    });
    rq.on('error', () => resolve());
  });
  await sleep(100); // inside DELIVERY_SETTLE_MS (500 ms in this suite)
  const again = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(again.status, 200, 'the retry right after the broken download was refused');
  assert.ok(again.buf.equals(b.payload));
  // Now delivered for good: after the window nobody gets it.
  await sleep(1200);
  const gone = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(gone.status, 404);
  for (const x of socks) x.destroy();
  proxy.close();
  did();
});

test('a complete download on a connection that closes is gone after the window, also for the same key', async () => {
  const b = bigBlob(1);
  assert.equal((await upload(b)).status, 200);
  const body = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: Number(new URL(srv.base).port), path: `/v2/outbound/${b.hash}`, headers: { 'X-Api-Key': KEY, Connection: 'close' }, agent: false }, (res) => {
      const parts = []; res.on('data', (d) => parts.push(d)); res.on('end', () => resolve(Buffer.concat(parts)));
    }).on('error', reject);
  });
  assert.ok(body.equals(b.payload));
  const other = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': 'pgp_someone_else' } });
  assert.notEqual(other.status, 200, 'another key never gets the held bytes');
  await sleep(1200);
  const gone = await srv.get(`/v2/outbound/${b.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(gone.status, 404);
  did();
});
