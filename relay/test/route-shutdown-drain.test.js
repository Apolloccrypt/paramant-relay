'use strict';
// sweep-chaos 9: SIGTERM exited at once, so a request being handled at that
// moment got a dropped connection (502 behind nginx). The relay now drains:
// the request in flight finishes, and the process exits after it.
const { test, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const http = require('http');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
let checks = 0;
after(async () => { await killAll(); summary('route-shutdown-drain', checks); });

test('an upload in flight when SIGTERM arrives still completes', async () => {
  const srv = await boot({ tag: 'drain', users: { api_keys: [{ key: KEY, plan: 'pro', active: true, email: 'd@example.test' }] } });
  const payload = crypto.randomBytes(4096);
  const body = Buffer.from(JSON.stringify({ hash: crypto.createHash('sha256').update(payload).digest('hex'), payload: payload.toString('base64') }));
  const exited = new Promise((r) => srv.child.once('exit', r));
  const result = new Promise((resolve, reject) => {
    const req = http.request(`${srv.base}/v2/inbound`, { method: 'POST', headers: { 'X-Api-Key': KEY, 'Content-Type': 'application/json', 'Content-Length': body.length } }, (res) => {
      let t = ''; res.on('data', (c) => { t += c; }); res.on('end', () => resolve({ status: res.statusCode, text: t }));
    });
    req.on('error', reject);
    req.write(body.subarray(0, 100));
    setTimeout(() => {
      srv.child.kill('SIGTERM');
      setTimeout(() => { req.end(body.subarray(100)); }, 300);
    }, 200);
  });
  const r = await result;
  assert.strictEqual(r.status, 200, `the in-flight upload was cut off: ${r.status} ${r.text}`);
  await exited;
  checks++;
});
