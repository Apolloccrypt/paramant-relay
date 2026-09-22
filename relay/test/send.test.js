'use strict';

// A send to named recipients, end to end, against a store that behaves like the
// durable one. What these tests hold:
//
//   one file, not one per person
//   one collection per person, and the second click gets nothing
//   the file goes when the last person is settled, not when the first collects
//   withdrawing one person leaves the rest working
//   the plan decides how many people may be addressed
//   a sender's overview never carries a token or a hash

const assert = require('node:assert/strict');
const test = require('node:test');

const { createSendStore } = require('../lib/send');

// Stands in for parasign-store: same five calls, same shapes.
function nepStore() {
  const blobs = new Map();
  const meta = new Map();
  return {
    blobs, meta,
    async putBlob(id, buf, ttl) { blobs.set(id, { buf: Buffer.from(buf), ttl }); },
    async getBlob(id) { const r = blobs.get(id); return r ? Buffer.from(r.buf) : null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, obj, ttl) { meta.set(id, { obj: JSON.parse(JSON.stringify(obj)), ttl }); },
    async getMeta(id) { const r = meta.get(id); return r ? JSON.parse(JSON.stringify(r.obj)) : null; },
  };
}

const DRIE = ['anna@example.org', 'bob@example.org', 'carla@example.org'];
const INHOUD = Buffer.from('a confidential report');

// Collecting is two steps now: prove the mailbox, then take the file. Tests
// that only care about the outcome use this; the code itself has its own tests.
async function haalOp(sends, token) {
  const vraag = await sends.requestPickup(token);
  if (!vraag.ok) return vraag;
  return sends.collect(token, vraag.code);
}

function maakStore(extra) {
  const store = nepStore();
  return { store, sends: createSendStore(Object.assign({ store }, extra || {})) };
}

test('one file for thirty people, not thirty files', async () => {
  const { store, sends } = maakStore();
  const dertig = Array.from({ length: 30 }, (_, i) => `p${i}@example.org`);

  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: dertig,
                                 filename: 'rapport.pdf' });
  assert.equal(r.ok, true);
  assert.equal(r.count, 30);
  assert.equal(Object.keys(r.tokens).length, 30, 'thirty tokens');
  assert.equal(store.blobs.size, 1, 'and one blob');
});

test('a token collects once, and the second attempt gets nothing', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 filename: 'rapport.pdf' });

  const eerst = await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(eerst.ok, true);
  assert.equal(eerst.blob.toString(), 'a confidential report');
  assert.equal(eerst.email, 'bob@example.org');
  assert.equal(eerst.remaining, 2, 'two people still to come');

  const tweede = await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(tweede.ok, false);
  assert.equal(tweede.reason, 'already_collected');
});

test('one person collecting leaves the file for the others', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });

  await haalOp(sends, r.tokens['anna@example.org']);
  assert.equal(store.blobs.size, 1, 'the file is still there');

  const bob = await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(bob.ok, true, 'and the next person still gets it');
});

test('the file goes when the last person is settled', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });

  await haalOp(sends, r.tokens['anna@example.org']);
  await haalOp(sends, r.tokens['bob@example.org']);
  assert.equal(store.blobs.size, 1);

  const laatste = await haalOp(sends, r.tokens['carla@example.org']);
  assert.equal(laatste.settled, true);
  assert.equal(store.blobs.size, 0, 'nobody is waiting, so the file is gone');

  // The record survives: the sender must still be able to see who collected.
  const view = await sends.overview(r.id);
  assert.equal(view.collected, 3);
});

test('withdrawing one person does not touch the rest', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });

  assert.equal((await sends.revoke(r.id, 'carla@example.org')).ok, true);
  const carla = await haalOp(sends, r.tokens['carla@example.org']);
  assert.equal(carla.ok, false);
  assert.equal(carla.reason, 'revoked');

  assert.equal((await haalOp(sends, r.tokens['anna@example.org'])).ok, true);
});

test('withdrawing the last outstanding person drops the file', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });

  await haalOp(sends, r.tokens['anna@example.org']);
  await haalOp(sends, r.tokens['bob@example.org']);
  const uit = await sends.revoke(r.id, 'carla@example.org');
  assert.equal(uit.settled, true);
  assert.equal(store.blobs.size, 0, 'nobody can still collect, so nothing is kept');
});

test('a fresh invitation kills the old link', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });
  const oud = r.tokens['bob@example.org'];

  const nieuw = await sends.reinvite(r.id, 'bob@example.org');
  assert.equal(nieuw.ok, true);
  assert.notEqual(nieuw.token, oud);

  const metOud = await haalOp(sends, oud);
  assert.equal(metOud.ok, false, 'the link the sender replaced must be dead');
  assert.equal((await haalOp(sends, nieuw.token)).ok, true);
});

test('the plan decides how many people may be addressed', async () => {
  const { sends } = maakStore();
  const twintig = Array.from({ length: 20 }, (_, i) => `p${i}@example.org`);

  const gratis = await sends.create({ plan: 'community', blob: INHOUD, addresses: twintig });
  assert.equal(gratis.ok, false);
  assert.equal(gratis.reason, 'over_limit');
  assert.equal(gratis.limit, 1);

  assert.equal((await sends.create({ plan: 'business', blob: INHOUD, addresses: twintig })).ok, true);
});

test('a bad address is refused before anything is stored', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD,
                                 addresses: ['ok@example.org', 'a@x.org\nBcc: derde@x.org'] });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'invalid_address');
  assert.equal(store.blobs.size, 0, 'no file is written for a send that cannot go out');
  assert.equal(store.meta.size, 0);
});

test('an unknown token says so without revealing whether the send exists', async () => {
  const { sends } = maakStore();
  await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });
  for (const bad of ['', 'x', 'a'.repeat(500), null, undefined]) {
    const r = await haalOp(sends, bad);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'unknown_token');
  }
});

test('a file that is already gone does not count as collected', async () => {
  const { store, sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE });
  store.blobs.clear();                       // the window closed, or a restart

  const p = await haalOp(sends, r.tokens['anna@example.org']);
  assert.equal(p.ok, false);
  assert.equal(p.reason, 'expired');

  const view = await sends.overview(r.id);
  assert.equal(view.collected, 0,
    'a collection that handed nothing over must not show as one');
});

test('the window is capped by the plan, not by what the sender asks', async () => {
  const { sends } = maakStore();
  const jaar = 365 * 24 * 3600 * 1000;

  const gratis = await sends.create({ plan: 'community', blob: INHOUD,
                                      addresses: ['a@example.org'], ttlMs: jaar });
  assert.ok(gratis.expires_at - Date.now() <= 3_600_000 + 1000, 'community is one hour');

  const zaak = await sends.create({ plan: 'business', blob: INHOUD,
                                    addresses: DRIE, ttlMs: jaar });
  assert.ok(zaak.expires_at - Date.now() <= 604_800_000 + 1000, 'business is seven days');
});

test('the overview shows people, never a token or a hash', async () => {
  const { sends } = maakStore();
  const r = await sends.create({ plan: 'business', blob: INHOUD, addresses: DRIE,
                                 filename: 'rapport.pdf' });
  const view = await sends.overview(r.id);
  const raw = JSON.stringify(view);

  assert.equal(view.total, 3);
  assert.equal(view.outstanding, 3);
  assert.equal(view.filename, 'rapport.pdf');
  assert.ok(!raw.includes('token'), 'no token anywhere in what the sender sees');
  assert.ok(!raw.includes('hash'));
  for (const t of Object.values(r.tokens)) assert.ok(!raw.includes(t));
});

test('a send nobody knows gets a refusal, not a crash', async () => {
  const { sends } = maakStore();
  for (const id of ['nope', '', null, undefined]) {
    assert.equal((await sends.overview(id)).ok, false);
    assert.equal((await sends.revoke(id, 'a@example.org')).ok, false);
    assert.equal((await sends.reinvite(id, 'a@example.org')).ok, false);
  }
});
