'use strict';
// Nothing burns before the relay wrote the last byte (matrix API-24-K,
// API-30-K, API-35-K, fase 2 eindmatrix).
//
// A download without a claim, the route every SDK and script in the field
// uses, burned the blob when the request came in (/v2/outbound) and answered
// X-Burned: true before a single byte had left (/v2/dl/:token/get).
//
// Now the read only counts once the whole body was written: the blob is
// hidden while it is being sent and destroyed after, and a reader that breaks
// off before the last write puts it back. A complete read still burns, and a
// second read right after it still finds nothing.
//
// "Before the last write" is measured at the relay. Socket buffers take a few
// MB, so a reader that breaks off early only keeps a blob larger than that;
// the suites below use 16 MB for it. At the default MAX_BLOB of 5 MB a 4 MB
// blob is written in one go and a break after the first chunk counts (review
// #573, M3): the last test pins that, and the claim mode as the exact way.
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

// Reads the first chunk of the body, stops reading and breaks the connection,
// like a receiver on a train going into a tunnel. A raw socket that stops
// reading, so the relay's last write waits for it: fetch() keeps pulling
// from the socket after the first chunk, and on loopback the kernel buffers
// hold several MB, so 'finish' could fire before the abort (and once the
// last byte was written the read counts, review #565 B1).
function readFirstChunkAndAbort(path, headers = {}, on = srv) {
  const port = Number(new URL(on.base).port);
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    let got = 0; let hdr = false; let done = false;
    const end = () => { if (done) return; done = true; resolve(got); };
    s.on('connect', () => s.write(`GET ${path} HTTP/1.1\r\nHost: x\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`));
    s.once('data', (d) => {
      const i = d.indexOf('\r\n\r\n');
      hdr = i >= 0; got = hdr ? d.length - i - 4 : 0;
      s.pause();
      setTimeout(() => { s.destroy(); end(); }, 200);
    });
    s.on('error', end);
    s.on('close', end);
  });
}

before(async () => {
  srv = await boot({
    tag: 'burn-after-delivery',
    // Blobs bigger than the 5 MB default, so a reader that stops after the
    // first chunk is still waiting while the relay's last write is pending:
    // loopback socket buffers take several MB before 'finish'.
    env: { DELIVERY_SETTLE_MS: '500', MAX_BLOB: String(32 * 1024 * 1024) },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'pro@example.test', account_id: 'acct_bad' }] },
  });
});
after(async () => { await killAll(); summary('route-burn-after-delivery', checks); });

test('GET /v2/outbound broken off after the first chunk keeps the blob', async () => {
  const b = bigBlob(16);
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
  const b = bigBlob(16);
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

// Review #565, B1: a reader that takes every byte and then resets the
// connection on purpose (SO_LINGER 0) looks like a broken line. Putting the
// blob back on that reset let one link be downloaded without end (6 of 6 on
// both routes). Once the last byte was written the read counts.
function readAllThenReset(path, headers) {
  const port = Number(new URL(srv.base).port);
  return new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    let buf = Buffer.alloc(0); let hdrEnd = -1; let status = 0; let len = 0; let done = false;
    const end = (full) => { if (done) return; done = true; resolve({ status, full }); };
    s.on('connect', () => s.write(`GET ${path} HTTP/1.1\r\nHost: x\r\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}\r\n`).join('')}\r\n`));
    s.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (hdrEnd < 0) {
        const i = buf.indexOf('\r\n\r\n'); if (i < 0) return;
        hdrEnd = i + 4;
        const h = buf.subarray(0, i).toString();
        status = Number(h.split(' ')[1]);
        const m = h.match(/content-length:\s*(\d+)/i); len = m ? Number(m[1]) : 0;
        if (status !== 200) { s.destroy(); return end(false); }
      }
      if (buf.length - hdrEnd >= len) { s.resetAndDestroy(); end(true); }
    });
    s.on('error', () => end(false));
    s.on('close', () => end(false));
  });
}

for (const route of ['dl', 'outbound']) {
  test(`read every byte, then reset: /v2/${route} delivers exactly once`, async () => {
    const b = bigBlob(1);
    const up = await upload(b);
    assert.equal(up.status, 200);
    const path = route === 'dl' ? `/v2/dl/${up.json.download_token}/get` : `/v2/outbound/${b.hash}`;
    const headers = route === 'dl' ? { 'User-Agent': 'curl/8.9.1' } : { 'X-Api-Key': KEY };
    let full = 0;
    for (let i = 0; i < 4; i++) {
      const r = await readAllThenReset(path, headers);
      if (r.full) full++;
      else break;
      await sleep(800); // past DELIVERY_SETTLE_MS (500 ms in this suite)
    }
    assert.equal(full, 1, `${full} complete downloads of one burn-after-read blob`);
    did();
  });
}

// Review #565, H1: a download out of the retry hold closed cleanly inside the
// window again and set a new hold, so the same key could chain it (8 of 8).
// The hold is there once per blob.
test('the retry hold on /v2/outbound cannot be chained', async () => {
  const b = bigBlob(1);
  assert.equal((await upload(b)).status, 200);
  const port = Number(new URL(srv.base).port);
  let full = 0;
  for (let i = 0; i < 6; i++) {
    const r = await new Promise((resolve) => {
      http.get({ host: '127.0.0.1', port, path: `/v2/outbound/${b.hash}`, headers: { 'X-Api-Key': KEY, Connection: 'close' }, agent: false }, (res) => {
        const parts = []; res.on('data', (d) => parts.push(d));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(parts) }));
      }).on('error', () => resolve({ status: 0 }));
    });
    if (r.status !== 200) break;
    if (r.body.equals(b.payload)) full++;
    await sleep(100); // inside the window
  }
  assert.ok(full <= 2, `${full} complete downloads through the retry hold`);
  did();
});

// Broken off before the last byte costs nothing, but not without end: a
// link or blob is served at most DL_MAX_FETCHES (five) times in all, broken
// or not, on both routes. /v2/outbound used to count `> DL_MAX_FETCHES` and
// served a sixth time, /v2/dl `>=` and stopped at five (review #573, LAAG).
test('broken-off downloads are bounded at five on both routes', async () => {
  const b = bigBlob(16);
  const up = await upload(b);
  const token = up.json.download_token;
  for (let i = 0; i < 4; i++) await readFirstChunkAndAbort(`/v2/dl/${token}/get`, { 'User-Agent': 'curl/8.9.1' });
  await sleep(300);
  const info = await srv.get(`/v2/dl/${token}/info`);
  assert.equal(info.status, 200, 'after four broken GETs the link is still there');
  const fifthDl = await readFirstChunkAndAbort(`/v2/dl/${token}/get`, { 'User-Agent': 'curl/8.9.1' });
  assert.ok(fifthDl > 0, 'the fifth GET is served');
  await sleep(300);
  const dl = await srv.get(`/v2/dl/${token}/get`, { headers: { 'User-Agent': 'curl/8.9.1' } });
  assert.equal(dl.status, 410, 'the sixth claimless GET after five broken ones');

  const c = bigBlob(16);
  assert.equal((await upload(c)).status, 200);
  for (let i = 0; i < 4; i++) await readFirstChunkAndAbort(`/v2/outbound/${c.hash}`, { 'X-Api-Key': KEY });
  await sleep(300);
  const st = await srv.get(`/v2/status/${c.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(st.json.available, true, 'after four broken GETs the blob is still there');
  const fifthOut = await readFirstChunkAndAbort(`/v2/outbound/${c.hash}`, { 'X-Api-Key': KEY });
  assert.ok(fifthOut > 0, 'the fifth GET is served');
  await sleep(300);
  const out = await srv.get(`/v2/outbound/${c.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(out.status, 404, 'the sixth GET after five broken ones');
  did();
});

// Review #573, M3: what the docs promise at the default blob size. Socket
// buffers take a few MB, so a 4 MB blob under the default MAX_BLOB of 5 MB is
// written in full before a reader that stops after the first chunk breaks
// off: on both claimless routes that read counts. Only the claim mode keeps
// the link on a broken line at this size, and the docs say so.
test('at the default MAX_BLOB a 4 MB claimless read broken off after the first chunk counts; a claimed one does not', async () => {
  const small = await boot({
    tag: 'burn-after-delivery-default',
    env: { DELIVERY_SETTLE_MS: '500' },
    users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'pro@example.test', account_id: 'acct_bad' }] },
  });
  const put = async () => {
    const b = bigBlob(4);
    const up = await small.post('/v2/inbound', { headers: { 'X-Api-Key': KEY }, body: { hash: b.hash, payload: b.payload.toString('base64') } });
    assert.equal(up.status, 200, 'a 4 MB blob fits under the default MAX_BLOB');
    return { ...b, token: up.json.download_token };
  };
  const a = await put();
  const gotDl = await readFirstChunkAndAbort(`/v2/dl/${a.token}/get`, { 'User-Agent': 'curl/8.9.1' }, small);
  assert.ok(gotDl > 0 && gotDl < 1024 * 1024, `read ${gotDl} bytes before breaking off`);
  await sleep(1500);
  assert.equal((await small.get(`/v2/dl/${a.token}/info`)).status, 404, 'the claimless link is spent');

  const o = await put();
  const gotOut = await readFirstChunkAndAbort(`/v2/outbound/${o.hash}`, { 'X-Api-Key': KEY }, small);
  assert.ok(gotOut > 0 && gotOut < 1024 * 1024, `read ${gotOut} bytes before breaking off`);
  await sleep(1500);
  const st = await small.get(`/v2/status/${o.hash}`, { headers: { 'X-Api-Key': KEY } });
  assert.equal(st.json.available, false, 'the outbound read counted');

  const c = await put();
  const claim = crypto.randomBytes(16).toString('hex');
  await readFirstChunkAndAbort(`/v2/dl/${c.token}/get?claim=${claim}`, { 'User-Agent': 'curl/8.9.1' }, small);
  await sleep(1500);
  assert.equal((await small.get(`/v2/dl/${c.token}/info`)).status, 200, 'the claimed link is still there');
  did();
});
