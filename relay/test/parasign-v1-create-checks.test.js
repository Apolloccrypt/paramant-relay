'use strict';
// /v1 create, sweep-api A4-A6:
//   A4 a signer without a valid email (email binding), a bogus binding_mode and
//      both document fields at once were accepted with 201;
//   A5 no Idempotency-Key: a retry made a second envelope;
//   A6 the hourly quota was spent by malformed requests.
const { test } = require('node:test');
const assert = require('assert');
const api = require('../lib/parasign-open-api');

const KEY = 'psk_live_v1checks000000000000';
const apiKeys = new Map([[KEY, { active: true, parasign: true, account_id: 'acct_v1', plan: 'pro' }]]);
function fakeRes() {
  return { statusCode: null, headers: null, _body: '', writeHead(c, h) { this.statusCode = c; this.headers = h || {}; },
    end(b) { this._body = b == null ? '' : String(b); }, json() { try { return JSON.parse(this._body); } catch { return null; } } };
}
function deps(body, { headers = {}, rate = () => true, store = null } = {}) {
  return {
    req: { headers }, res: fakeRes(), method: 'POST', path: '/v1/envelopes', query: {}, clientIp: '203.0.113.9',
    authHeader: `Bearer ${KEY}`, publicOrigin: 'https://paramant.app', apiKeys, parasignEntitled: () => true,
    envStore: {}, store, envCreateRateOk: async () => rate(), readBody: async () => Buffer.from(body),
    J: (o) => JSON.stringify(o), log: () => {},
  };
}
const PDF = Buffer.from('%PDF-1.4 test').toString('base64');

test('malformed and invalid requests do not spend the hourly quota', async () => {
  let counted = 0;
  const rate = () => { counted++; return true; };
  for (const body of ['{bad', JSON.stringify({ document: { content_base64: PDF }, signers: [{ name: 'A' }] }),
    JSON.stringify({ document: { content_base64: PDF }, signers: [{ name: 'A', email: 'nope' }] }),
    JSON.stringify({ document: { content_base64: PDF, url: 'https://x.example/a.pdf' }, signers: [{ email: 'a@example.org' }] }),
    JSON.stringify({ document: { content_base64: PDF }, binding_mode: 'bogus', signers: [{ email: 'a@example.org' }] })]) {
    const d = deps(body, { rate });
    await api.route(d);
    assert.strictEqual(d.res.statusCode, 400, `${body.slice(0, 60)} -> ${d.res.statusCode} ${d.res._body}`);
  }
  assert.strictEqual(counted, 0, 'none of them touched the quota');
});

test('an email-bound signer without a valid address is a 400 that names the signer', async () => {
  const d = deps(JSON.stringify({ document: { content_base64: PDF }, signers: [{ email: 'a@example.org' }, { name: 'B' }] }));
  await api.route(d);
  assert.strictEqual(d.res.statusCode, 400);
  assert.strictEqual(d.res.json().error, 'invalid_signer_email');
  assert.strictEqual(d.res.json().signer_index, 1);
});

test('the same Idempotency-Key gets the first answer back, without a second create', async () => {
  const saved = new Map();
  const first = { id: 'envFirst000000000000001', status: 'sent' };
  const store = { async getMeta(k) { return saved.get(k) || null; }, async putMeta(k, v) { saved.set(k, v); } };
  // As if the first request had been answered and stored.
  const crypto = require('crypto');
  saved.set('idem:' + crypto.createHash('sha256').update(KEY).digest('hex').slice(0, 32) + ':retry-0001', { status: 201, body: first });
  let rated = 0;
  const d = deps(JSON.stringify({ document: { content_base64: PDF }, signers: [{ email: 'a@example.org' }] }),
    { headers: { 'idempotency-key': 'retry-0001' }, store, rate: () => { rated++; return true; } });
  await api.route(d);
  assert.strictEqual(d.res.statusCode, 201);
  assert.deepStrictEqual(d.res.json(), first);
  assert.strictEqual(d.res.headers['Idempotent-Replay'], 'true');
  assert.strictEqual(rated, 0, 'a replay creates nothing and costs nothing');
});

test('a 429 says how long is left in the hour, not a flat 3600', async () => {
  const d = deps(JSON.stringify({ document: { content_base64: PDF }, signers: [{ email: 'a@example.org' }] }), { rate: () => false });
  await api.route(d);
  assert.strictEqual(d.res.statusCode, 429);
  const left = Number(d.res.headers['Retry-After']);
  assert.ok(left > 0 && left <= 3600);
});

test('the same Idempotency-Key with a different body is refused (review #555)', async () => {
  const crypto = require('crypto');
  const saved = new Map();
  const store = { async getMeta(k) { return saved.get(k) || null; }, async putMeta(k, v) { saved.set(k, v); } };
  const firstBody = JSON.stringify({ document: { content_base64: PDF }, signers: [{ email: 'a@example.org' }] });
  saved.set('idem:' + crypto.createHash('sha256').update(KEY).digest('hex').slice(0, 32) + ':retry-0002',
    { status: 201, body: { id: 'envFirst000000000000002' }, body_hash: crypto.createHash('sha256').update(firstBody).digest('hex') });
  const other = deps(JSON.stringify({ document: { content_base64: PDF }, signers: [{ email: 'b@example.org' }] }), { headers: { 'idempotency-key': 'retry-0002' }, store });
  await api.route(other);
  assert.strictEqual(other.res.statusCode, 422, other.res._body);
  const same = deps(firstBody, { headers: { 'idempotency-key': 'retry-0002' }, store });
  await api.route(same);
  assert.strictEqual(same.res.statusCode, 201);
});
