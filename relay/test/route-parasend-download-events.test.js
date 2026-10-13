'use strict';
// The download half of "webhooks and mail on upload and download", the
// download route for scripts, and signed webhooks.
//   SEND-34: no webhook was ever sent on download (only blob_ready on upload).
//   SEND-33: the download mail fired only on GET /v2/outbound, never when the
//            receiver used the link (claim + ack).
//   fase 1:  /v2/dl/:token/get answered 403 to python-requests and Go.
//   sweep-api: a webhook registered without a secret went out unsigned.
// Webhooks only go to public HTTPS, so the target here is a name that cannot
// resolve: the attempt shows in the log as webhook_fail, which is what is
// counted (no network needed).
// Run: node --test relay/test/route-parasend-download-events.test.js
const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll } = require('./_relay-server');
const { summary } = require('./_requires');

const KEY = 'pgp_' + crypto.randomBytes(32).toString('hex');
let srv = null; let checks = 0;
before(async () => {
  srv = await boot({ tag: 'dl-events', captureLog: true, env: { MAIL_PROVIDER: 'dryrun' },
    users: { api_keys: [{ key: KEY, plan: 'pro', plan_parasend: 'pro', active: true, email: 'owner@example.test', account_id: 'acct_dl_events' }] } });
});
after(async () => { await killAll(); summary('route-parasend-download-events', checks); });

const H = { 'X-Api-Key': KEY };
async function upload(device) {
  const payload = crypto.randomBytes(2048);
  const hash = crypto.createHash('sha256').update(payload).digest('hex');
  const r = await srv.post('/v2/inbound', { headers: H, body: { hash, payload: payload.toString('base64'), meta: { device_id: device, file_id: 'f_' + crypto.randomBytes(6).toString('hex') } } });
  assert.strictEqual(r.status, 200, r.text);
  return r.json;
}
const fails = (host) => (srv.log().match(new RegExp(`webhook_fail[^\\n]*${host}`, 'g')) || []).length;
const downloadMails = () => (srv.log().match(/mail_dryrun[^\n]*was downloaded/g) || []).length;
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('webhook without a secret gets one, handed back once; a given secret is not echoed', async () => {
  const r = await srv.post('/v2/webhook', { headers: H, body: { device_id: 'dev1', url: 'https://hooks-dl.example.invalid/x' } });
  assert.strictEqual(r.status, 200, r.text);
  assert.match(r.json.secret || '', /^whsec_[0-9a-f]{48}$/);
  const own = await srv.post('/v2/webhook', { headers: H, body: { device_id: 'dev9', url: 'https://hooks-dl.example.invalid/y', secret: 'my-own-secret-value' } });
  assert.strictEqual(own.status, 200);
  assert.strictEqual(own.json.secret, undefined);
  checks++;
});

test('a link download (claim + ack) sends the download webhook and the download mail', async () => {
  const up = await upload('dev1');
  await wait(300);
  const afterUpload = fails('hooks-dl');
  assert.ok(afterUpload >= 1, 'upload webhook attempted');
  const mailsBefore = downloadMails();
  const claim = crypto.randomBytes(16).toString('hex');
  const g = await srv.get(`/v2/dl/${up.download_token}/get?claim=${claim}`);
  assert.strictEqual(g.status, 200);
  const ack = await srv.post(`/v2/dl/${up.download_token}/ack`, { body: { claim } });
  assert.strictEqual(ack.status, 200, ack.text);
  await wait(500);
  assert.ok(fails('hooks-dl') > afterUpload, 'no download webhook after the link download');
  assert.strictEqual(downloadMails(), mailsBefore + 1, 'one download mail for the link download');
  checks++;
});

test('python-requests and Go may download through /get; preview bots may not', async () => {
  const up = await upload('dev2');
  const py = await srv.get(`/v2/dl/${up.download_token}/get`, { headers: { 'User-Agent': 'python-requests/2.32.3' } });
  assert.strictEqual(py.status, 200, 'python-requests was refused');
  const up2 = await upload('dev2');
  const bot = await srv.get(`/v2/dl/${up2.download_token}/get`, { headers: { 'User-Agent': 'WhatsApp/2.23' } });
  assert.strictEqual(bot.status, 403);
  const go = await srv.get(`/v2/dl/${up2.download_token}/get`, { headers: { 'User-Agent': 'Go-http-client/1.1' } });
  assert.strictEqual(go.status, 200, 'Go was refused');
  checks++;
});
