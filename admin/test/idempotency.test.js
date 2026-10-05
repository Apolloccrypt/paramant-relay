'use strict';
// A double click made two envelopes and two rounds of invitation mails
// (sweep-chaos). The middleware lets the first request run and hands the twin
// the first one's answer.
const { test } = require('node:test');
const assert = require('assert');
const { middleware } = require('../lib/idempotency');

function fakeRedis() {
  const m = new Map();
  return {
    async set(k, v, o = {}) { if (o.NX && m.has(k)) return null; m.set(k, v); return 'OK'; },
    async get(k) { return m.has(k) ? m.get(k) : null; },
    async del(k) { m.delete(k); return 1; },
  };
}
function req(body, headers = {}) {
  return { userSession: { user_id: 'pgp_u' }, body, originalUrl: '/api/user/envelopes', get: (h) => headers[h.toLowerCase()] };
}
function res() {
  const r = { statusCode: 200, headers: {}, body: undefined };
  r.status = (c) => { r.statusCode = c; return r; };
  r.set = (k, v) => { r.headers[k] = v; return r; };
  r.json = (b) => { r.body = b; r.done && r.done(); return r; };
  return r;
}

test('two identical requests at once: the handler runs once, both get its answer', async () => {
  const redis = fakeRedis();
  const mw = middleware({ redis: () => redis, scope: 't', waitMs: 3000 });
  let runs = 0;
  const handler = async (rq, rs) => { runs++; await new Promise((x) => setTimeout(x, 200)); rs.json({ id: 'env_1' }); };
  const a = res(); const b = res();
  const run = (rq, rs) => new Promise((done) => { rs.done = done; mw(rq, rs, () => handler(rq, rs)); });
  await Promise.all([run(req({ x: 1 }), a), run(req({ x: 1 }), b)]);
  assert.strictEqual(runs, 1);
  assert.deepStrictEqual(a.body, { id: 'env_1' });
  assert.deepStrictEqual(b.body, { id: 'env_1' });
  assert.strictEqual(b.headers['Idempotent-Replay'], 'true');
});

test('a different body runs again; a failed first try can be retried', async () => {
  const redis = fakeRedis();
  const mw = middleware({ redis: () => redis, scope: 't' });
  let runs = 0;
  const go = (body, status) => new Promise((done) => {
    const rs = res(); rs.done = () => done(rs);
    mw(req(body), rs, () => { runs++; rs.status(status).json({ n: runs }); });
  });
  await go({ x: 1 }, 200);
  await go({ x: 2 }, 200);
  assert.strictEqual(runs, 2);
  await go({ x: 3 }, 502);
  await go({ x: 3 }, 200);
  assert.strictEqual(runs, 4, 'a 502 is not stored, so the retry runs');
});

test('a partial failure (207 or partial_failure) is not replayed: the retry runs again', async () => {
  // "Mislukte e-mails opnieuw sturen" posts the same body; it got the stored
  // failure back for two minutes and sent nothing (fase-1 herrun COSIGN-11-A).
  const redis = fakeRedis();
  const mw = middleware({ redis: () => redis, scope: 't' });
  let runs = 0;
  const go = (body, status, out) => new Promise((done) => {
    const rs = res(); rs.done = () => done(rs);
    mw(req(body), rs, () => { runs++; rs.status(status).json(out); });
  });
  await go({ inv: 1 }, 207, { partial_failure: true });
  const second = await go({ inv: 1 }, 200, { ok: true });
  assert.strictEqual(runs, 2);
  assert.deepStrictEqual(second.body, { ok: true });
  await go({ inv: 2 }, 200, { ok: false, partial_failure: true });
  await go({ inv: 2 }, 200, { ok: true });
  assert.strictEqual(runs, 4, 'partial_failure in a 200 body is not stored either');
});

test('the same Idempotency-Key with a different body is refused, not replayed (review #555)', async () => {
  const redis = fakeRedis();
  const mw = middleware({ redis: () => redis, scope: 't' });
  let runs = 0;
  const go = (body) => new Promise((done) => {
    const rs = res(); rs.done = () => done(rs);
    mw(req(body, { 'idempotency-key': 'client-key-0001' }), rs, () => { runs++; rs.status(200).json({ id: 'env_' + runs }); });
  });
  const first = await go({ to: 'a@example.com' });
  assert.deepStrictEqual(first.body, { id: 'env_1' });
  const second = await go({ to: 'b@example.com' });
  assert.strictEqual(second.statusCode, 422, JSON.stringify(second.body));
  assert.strictEqual(second.body.error, 'idempotency_key_reused');
  assert.strictEqual(runs, 1);
  const same = await go({ to: 'a@example.com' });
  assert.deepStrictEqual(same.body, { id: 'env_1' }, 'the same body still gets the first answer');
});
