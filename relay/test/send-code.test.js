'use strict';

// Proving the mailbox before handing over the file.
//
// A token proves a link was used, not who used it. A forwarded mail or a shared
// mailbox looks exactly like the right person collecting, and knowing who
// collected is the thing a sender is paying for. So collecting is two steps: a
// short code to the same address the invitation went to, then the file.
//
// What these tests hold: the code never travels back to whoever asked for it,
// a wrong code costs a try, three wrong codes close the door, a code cannot be
// replayed, and asking for a code does not burn the link.

const assert = require('node:assert/strict');
const test = require('node:test');

const { createSendStore, maskEmail, CODE_TRIES, CODE_DIGITS } = require('../lib/send');

function nepStore() {
  const blobs = new Map(), meta = new Map();
  return {
    blobs, meta,
    async putBlob(id, buf) { blobs.set(id, Buffer.from(buf)); },
    async getBlob(id) { const b = blobs.get(id); return b ? Buffer.from(b) : null; },
    async delBlob(id) { blobs.delete(id); },
    async putMeta(id, obj) { meta.set(id, JSON.parse(JSON.stringify(obj))); },
    async getMeta(id) { const r = meta.get(id); return r ? JSON.parse(JSON.stringify(r)) : null; },
  };
}

const INHOUD = Buffer.from('a confidential report');

async function opgezet(klok) {
  const store = nepStore();
  const sends = createSendStore(klok ? { store, now: klok } : { store });
  const r = await sends.create({ plan: 'business', blob: INHOUD,
                                 addresses: ['anna@example.org', 'bob@example.org'],
                                 filename: 'rapport.pdf' });
  return { store, sends, r, token: r.tokens['anna@example.org'] };
}

test('the code is six digits and goes to the address, masked in the answer', async () => {
  const { sends, token } = await opgezet();
  const vraag = await sends.requestPickup(token);

  assert.equal(vraag.ok, true);
  assert.match(vraag.code, new RegExp('^\\d{' + CODE_DIGITS + '}$'));
  assert.equal(vraag.email, 'anna@example.org', 'the mailer needs the real address');
  assert.equal(vraag.masked, 'a***a@example.org',
    'and the reader gets enough to recognise their own mailbox, no more');
});

test('asking for a code does not burn the link', async () => {
  const { sends, token } = await opgezet();
  await sends.requestPickup(token);
  await sends.requestPickup(token);
  const derde = await sends.requestPickup(token);
  assert.equal(derde.ok, true, 'a stray click must not cost somebody their collection');

  const got = await sends.collect(token, derde.code);
  assert.equal(got.ok, true, 'and the newest code still works');
});

test('a fresh code replaces the previous one', async () => {
  const { sends, token } = await opgezet();
  const eerste = await sends.requestPickup(token);
  const tweede = await sends.requestPickup(token);

  const oud = await sends.collect(token, eerste.code);
  assert.equal(oud.ok, false);
  assert.equal(oud.reason, 'wrong_code', 'the code that was replaced is dead');
  assert.equal((await sends.collect(token, tweede.code)).ok, true);
});

test('three wrong codes close the door, and the right one no longer helps', async () => {
  const { sends, token } = await opgezet();
  const vraag = await sends.requestPickup(token);

  for (let i = 1; i <= CODE_TRIES; i++) {
    const mis = await sends.collect(token, '000000');
    assert.equal(mis.reason, 'wrong_code');
    assert.equal(mis.tries_left, CODE_TRIES - i, 'the answer says how much room is left');
  }
  const daarna = await sends.collect(token, vraag.code);
  assert.equal(daarna.ok, false);
  assert.equal(daarna.reason, 'too_many_tries',
    'guessing must not become cheaper by being patient');
});

test('a used code cannot be replayed', async () => {
  const { sends, token } = await opgezet();
  const vraag = await sends.requestPickup(token);
  assert.equal((await sends.collect(token, vraag.code)).ok, true);

  const opnieuw = await sends.collect(token, vraag.code);
  assert.equal(opnieuw.ok, false);
  assert.equal(opnieuw.reason, 'already_collected');
});

test('a code expires', async () => {
  let nu = 1_000_000;
  const { sends, token } = await opgezet(() => nu);
  const vraag = await sends.requestPickup(token);

  nu += 16 * 60 * 1000;                       // past the fifteen-minute window
  const laat = await sends.collect(token, vraag.code);
  assert.equal(laat.ok, false);
  assert.equal(laat.reason, 'code_expired');

  // And a new one works, because expiry is not a punishment.
  const nieuw = await sends.requestPickup(token);
  assert.equal((await sends.collect(token, nieuw.code)).ok, true);
});

test('collecting without ever asking for a code is refused', async () => {
  const { sends, token } = await opgezet();
  const r = await sends.collect(token, '123456');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no_code_requested');
});

test('the code is bound to its own token, not to the send', async () => {
  const { sends, r } = await opgezet();
  const annaToken = r.tokens['anna@example.org'];
  const bobToken = r.tokens['bob@example.org'];

  const anna = await sends.requestPickup(annaToken);
  await sends.requestPickup(bobToken);

  const kruis = await sends.collect(bobToken, anna.code);
  assert.equal(kruis.ok, false);
  assert.equal(kruis.reason, 'wrong_code',
    'one recipient\'s code must never open another recipient\'s link');
});

test('a withdrawn recipient gets no code at all', async () => {
  const { sends, r, token } = await opgezet();
  await sends.revoke(r.id, 'anna@example.org');

  const vraag = await sends.requestPickup(token);
  assert.equal(vraag.ok, false);
  assert.equal(vraag.reason, 'revoked');
  assert.equal(vraag.code, undefined, 'and no code is minted for somebody who is out');
});

test('the stored record never holds the code itself', async () => {
  const { store, sends, r, token } = await opgezet();
  const vraag = await sends.requestPickup(token);

  const opgeslagen = JSON.stringify(await store.getMeta(r.id));
  assert.ok(!opgeslagen.includes(vraag.code),
    'a dump of the store must not hand over a live code');
  assert.ok(opgeslagen.includes('code_hash'), 'only its hash is kept');
});

test('masking never leaks more than the first and last letter', () => {
  assert.equal(maskEmail('anna@example.org'), 'a***a@example.org');
  assert.equal(maskEmail('jo@example.org'), 'j***@example.org');
  assert.equal(maskEmail('x@example.org'), 'x***@example.org');
  assert.equal(maskEmail(''), '***');
  assert.equal(maskEmail('geen-apenstaartje'), '***');
});
